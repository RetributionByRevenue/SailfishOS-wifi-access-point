#!/bin/bash
# SailfishOS travel-router with anti-leak VPN gating.
# Sets up a Wi-Fi AP (test_ap) on wlan1, routes its clients through an
# OpenVPN tunnel on tun0, and refuses to allow AP traffic out until the
# tunnel is verified up. Press 2 at the end to tear everything back down.

# =========================================================================
echo -e "\033[36m==> step 1/15: writing AP wpa_supplicant config to /tmp\033[0m"
# =========================================================================
# Build the config that wpa_supplicant will use to drive wlan1 in AP mode.
# mode=2 means master/AP; ssid + psk are what clients will see and use.
# Living in /tmp so it disappears on reboot -- nothing persistent here.
rm -f /tmp/wpa_supplicant_ap.conf                                           # ensure no stale file
echo 'ctrl_interface=/var/run/wpa_supplicant' > /tmp/wpa_supplicant_ap.conf # wpa_cli socket path
echo 'ctrl_interface_group=0' >> /tmp/wpa_supplicant_ap.conf                # root may use the socket
echo 'update_config=1' >> /tmp/wpa_supplicant_ap.conf                       # allow runtime tweaks
echo '' >> /tmp/wpa_supplicant_ap.conf
echo 'network={' >> /tmp/wpa_supplicant_ap.conf
echo '    mode=2' >> /tmp/wpa_supplicant_ap.conf                            # 2 = access point
echo '    ssid="test_ap"' >> /tmp/wpa_supplicant_ap.conf                    # broadcast name
echo '    frequency=2412' >> /tmp/wpa_supplicant_ap.conf                    # 2412 MHz = channel 1
echo '    key_mgmt=WPA-PSK' >> /tmp/wpa_supplicant_ap.conf                  # WPA2-Personal
echo '    psk="12345678"' >> /tmp/wpa_supplicant_ap.conf                    # pre-shared key
echo '}' >> /tmp/wpa_supplicant_ap.conf

# =========================================================================
echo -e "\033[36m==> step 2/15: sanitizing FORWARD chain (clean baseline)\033[0m"
# =========================================================================
# Wipe any leftover rules and reset the default policy to ACCEPT so we
# start from a known state regardless of what previous runs may have left.
iptables -F FORWARD
iptables -P FORWARD ACCEPT

# =========================================================================
echo -e "\033[36m==> step 3/15: showing current wpa_supplicant processes\033[0m"
# =========================================================================
# Useful for debugging if something is stuck; harmless otherwise.
ps aux | grep "wpa_supp"

# =========================================================================
echo -e "\033[36m==> step 4/15: killing existing wpa_supplicant instances\033[0m"
# =========================================================================
# SailfishOS/ConnMan normally runs one for wlan0; we kill it so we can
# start our own with our preferred flags below.
pkill wpa_supplicant

# =========================================================================
echo -e "\033[36m==> step 5/15: creating virtual wlan1 (AP) on top of wlan0\033[0m"
# =========================================================================
# The Snapdragon Wi-Fi chip supports concurrent station+AP on a single
# radio. We create a virtual wlan1 interface in AP mode with a custom MAC
# so the AP has its own L2 identity, give it the gateway IP for the AP
# subnet (10.10.0.0/24), and bring it up.
iw dev wlan0 interface add wlan1 type __ap addr 12:34:56:78:ab:ce
ip addr add 10.10.0.1/24 dev wlan1
ip link set wlan1 up

# =========================================================================
echo -e "\033[36m==> step 6/15: enabling IPv4 forwarding\033[0m"
# =========================================================================
# Required so the kernel will route packets between wlan1 and tun0.
echo 1| tee /proc/sys/net/ipv4/ip_forward

# =========================================================================
echo -e "\033[36m==> step 7/15: starting AP wpa_supplicant on wlan1\033[0m"
# =========================================================================
# This is when test_ap actually goes on the air. -B = background, -c =
# config file (the AP one we built above), -i = interface, -O = control
# socket override directory.
/usr/sbin/wpa_supplicant -B -c /tmp/wpa_supplicant_ap.conf -O /var/run/wpa_supplicant -i wlan1

# =========================================================================
echo -e "\033[36m==> step 8/15: starting client wpa_supplicant on wlan0\033[0m"
# =========================================================================
# Re-launches the station-mode supplicant using ConnMan's saved networks
# config. -u = D-Bus interface enabled so ConnMan can still see/manage it.
# bgscan="simple:30:-45:300" (the default in that config) is what keeps
# wlan0 scanning for better APs in the background.
/usr/sbin/wpa_supplicant -B -u -c /etc/wpa_supplicant/wpa_supplicant.conf -O/var/run/wpa_supplicant -u -P /var/run/wpa_supplicant.pid -i wlan0

# =========================================================================
echo -e "\033[36m==> step 9/15: toggling ConnMan Wi-Fi to rebind wlan0\033[0m"
# =========================================================================
# After killing+restarting wpa_supplicant under ConnMan's feet, ConnMan
# needs this nudge to re-acquire wlan0 and connect to the saved network.
dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:false
dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:true

# =========================================================================
echo -e "\033[36m==> step 10/15: installing permanent wlan1 kill switch\033[0m"
# =========================================================================
# Drop every forwarded packet coming in from wlan1 whose outgoing interface
# is not a tun* device. This is stateless and always-on:
#   - VPN setup phase (tun0 doesn't exist yet) -> traffic drops, fail-closed
#   - VPN up -> wlan1 -> tun0 is allowed; everything else still dropped
#   - VPN dies later -> instantly back to drop, no leak window
# Net result: even if openvpn crashes, restarts, or reroutes, AP clients
# physically cannot leave the phone except through the tunnel.
# -D first removes any stale duplicate from a prior run, then -A appends.
echo -e "\033[33minstalling kill switch: wlan1 traffic blocked except via tun+\033[0m"
iptables -D FORWARD -i wlan1 ! -o tun+ -j DROP 2>/dev/null
iptables -A FORWARD -i wlan1 ! -o tun+ -j DROP

# =========================================================================
echo -e "\033[36m==> step 11/15: dialing OpenVPN + readiness probe\033[0m"
# =========================================================================
# Dial the home OpenVPN server in the background, then actively poll up to
# 600s for tun0 to be up AND reachable through itself before proceeding.
# (Previously this was a 3-option menu; simplified to always use the home
# server since the Nord profiles are no longer used.)
nohup openvpn --dev tun --config /home/defaultuser/Desktop/mark-home.ovpn >/dev/null 2>&1 &
echo "waiting for tun0 to come up (timeout 600s)..."
for i in $(seq 1 600); do
  # tun0 must be both UP and pingable through itself before we trust it
  if ip link show tun0 up >/dev/null 2>&1 && ping -I tun0 -c1 -W2 8.8.8.8 >/dev/null 2>&1; then
    echo "tun0 is up after ${i}s"
    break
  fi
  sleep 1
done

# Replace the default route so all phone-originated traffic uses tun0.
ip route del default && ip route add default dev tun0

# Heartbeat: every cycle, ping 8.8.8.8 (via current default route). If 100%
# packet loss, turn the blue LED off; otherwise turn it on. Gives a
# glanceable, physical "is the path to the internet alive?" indicator.
nohup sh -c 'while :; do if ping -c 3 -W 2 8.8.8.8 >/dev/null 2>&1; then echo 255 | tee /sys/class/leds/blue/brightness; else echo 0 | tee /sys/class/leds/blue/brightness; fi; sleep 4; done' >/dev/null 2>&1 &

# =========================================================================
echo -e "\033[36m==> step 12/15: VPN status check\033[0m"
# =========================================================================
# Purely informational -- the kill switch installed in step 10 is permanent
# and stateless, so this step does NOT touch the firewall. If the probe
# timed out, wlan1 just keeps dropping until you re-run the script.
if ip link show tun0 up >/dev/null 2>&1; then
  echo -e "\033[34mVPN is up -- AP clients will reach internet via tun0\033[0m"
else
  echo -e "\033[31mVPN not up -- AP clients remain blocked by kill switch\033[0m"
fi

# =========================================================================
echo -e "\033[36m==> step 13/15: installing NAT MASQUERADE for AP subnet\033[0m"
# =========================================================================
# For every non-loopback, non-cellular, non-USB-tether, non-AP interface,
# add a POSTROUTING MASQUERADE rule so packets sourced from 10.10.0.0/16
# get rewritten to the outgoing interface's IP (return traffic comes back).
for iface in $(ifconfig | grep "Link encap" | awk '{print $1}' | grep -vE "^(lo|rmnet_ipa0|rndis0|wlan1)$"); do
  echo -e "\033[32mmodifying $iface\033[0m"
  iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o "$iface" -j MASQUERADE
done

echo "now we see test_ap is online"

# =========================================================================
echo -e "\033[36m==> step 14/15: printing routing table\033[0m"
# =========================================================================
# Pretty-printed netstat with the noisy MSS/Window/irtt columns dropped.
netstat -nr | awk 'NF>=8 {printf "%-15s %-16s %-16s %-6s %s\n", $1, $2, $3, $4, $8; next} {print}'

# =========================================================================
echo -e "\033[36m==> step 15/15: starting DHCP server for AP clients\033[0m"
# =========================================================================
# Kill any stale instances first so we don't have two DHCP servers fighting
# on wlan1, then relaunch in the background under nohup so it survives this
# shell. stdout/stderr go to /dev/null to avoid filling disk.
pkill udhcpd
pkill -f wlan1_dhcp_server.py

nohup /home/defaultuser/python/venv/bin/python /home/defaultuser/python/wlan1_dhcp_server.py >/dev/null 2>&1 &
echo "dhcp server started in background (pid $!)"

# =========================================================================
# Setup complete -- sit here waiting for the user to press 2 to tear down.
# Anything other than 2 is silently ignored (stays in the loop).
# =========================================================================
while true; do
  echo ""
  echo "Press 2 to reset phone networking (undo all script changes), anything else to ignore:"
  read -r reset_choice
  reset_choice="${reset_choice//[^0-9]/}"                                   # strip ESC/junk so "2" matches
  if [ "$reset_choice" = "2" ]; then
    echo -e "\033[36m==> reset: tearing down everything\033[0m"

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 1/9: killing background processes\033[0m"
    # -----------------------------------------------------------------
    # Stop our long-running children first so they don't fight teardown
    # (DHCP server, LED heartbeat, both wpa_supplicant instances, openvpn).
    pkill -f wlan1_dhcp_server.py                                           # custom DHCP server
    pkill -f "blue/brightness"                                              # LED heartbeat loop
    pkill wpa_supplicant                                                    # AP + client supplicants
    pkill openvpn                                                           # VPN client

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 2/9: flushing iptables (NAT + FORWARD)\033[0m"
    # -----------------------------------------------------------------
    # Remove every rule we added and restore the default FORWARD policy
    # so the phone returns to normal-routing behavior afterward.
    iptables -t nat -F POSTROUTING                                          # remove MASQUERADE rules
    iptables -F FORWARD                                                     # remove our DROP rule + any leftovers
    iptables -P FORWARD ACCEPT                                              # restore default policy

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 3/9: cleaning up tun0 (routes + device)\033[0m"
    # -----------------------------------------------------------------
    # openvpn doesn't always clean these on SIGTERM; stale entries
    # accumulate across runs if we don't explicitly remove them.
    ip route flush dev tun0 2>/dev/null
    ip link delete tun0 2>/dev/null

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 4/9: bringing down wlan1 + wlan0\033[0m"
    # -----------------------------------------------------------------
    # Both adapters offline; delete the virtual AP interface entirely.
    ip link set wlan1 down 2>/dev/null
    ip link set wlan0 down 2>/dev/null
    iw dev wlan1 del 2>/dev/null

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 5/9: flushing wlan0 routes\033[0m"
    # -----------------------------------------------------------------
    # Clear stale routes BEFORE connman re-creates them when we bring
    # wlan0 back up; otherwise duplicates accumulate across runs.
    ip route flush dev wlan0 2>/dev/null

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 6/9: disabling IPv4 forwarding\033[0m"
    # -----------------------------------------------------------------
    # Back to normal phone behavior -- kernel will no longer route.
    echo 0 | tee /proc/sys/net/ipv4/ip_forward

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 7/9: bringing wlan0 back up as client\033[0m"
    # -----------------------------------------------------------------
    # Restart the station-mode wpa_supplicant with bgscan so the phone
    # behaves as a normal Wi-Fi client again.
    ip link set wlan0 up
    /usr/sbin/wpa_supplicant -B -u -c /etc/wpa_supplicant/wpa_supplicant.conf -O/var/run/wpa_supplicant -u -P /var/run/wpa_supplicant.pid -i wlan0

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 8/9: toggling ConnMan Wi-Fi\033[0m"
    # -----------------------------------------------------------------
    # Nudge ConnMan to re-recognize the now-clean state and rebind wlan0.
    dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:false
    dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:true

    # -----------------------------------------------------------------
    echo -e "\033[36m==> reset 9/9: turning off VPN-health LED\033[0m"
    # -----------------------------------------------------------------
    # Make sure the blue LED is off so it doesn't falsely indicate VPN.
    echo 0 | tee /sys/class/leds/blue/brightness 2>/dev/null

    echo -e "\033[32mnetworking reset complete\033[0m"
    break
  fi
done
