#!/bin/bash
rm -f /tmp/wpa_supplicant_ap.conf #ensure file does not exist
echo 'ctrl_interface=/var/run/wpa_supplicant' > /tmp/wpa_supplicant_ap.conf
echo 'ctrl_interface_group=0' >> /tmp/wpa_supplicant_ap.conf
echo 'update_config=1' >> /tmp/wpa_supplicant_ap.conf
echo '' >> /tmp/wpa_supplicant_ap.conf
echo 'network={' >> /tmp/wpa_supplicant_ap.conf
echo '    mode=2' >> /tmp/wpa_supplicant_ap.conf
echo '    ssid="test_ap"' >> /tmp/wpa_supplicant_ap.conf
echo '    frequency=2412' >> /tmp/wpa_supplicant_ap.conf
echo '    key_mgmt=WPA-PSK' >> /tmp/wpa_supplicant_ap.conf
echo '    psk="12345678"' >> /tmp/wpa_supplicant_ap.conf
echo '}' >> /tmp/wpa_supplicant_ap.conf

#ip -6 addr flush wlan0
echo "nameserver 137.220.33.124" > /etc/resolv.conf


#showcase instance of wpa_supplicant is running
ps aux | grep "wpa_supp"

#kill the instance of wpa_supplicant
pkill wpa_supplicant


iw dev wlan0 interface add wlan1 type __ap addr 12:34:56:78:ab:ce
ip addr add 10.10.0.1/24 dev wlan1 
ip link set wlan1 up
echo 1| tee /proc/sys/net/ipv4/ip_forward

#create wlan1
/usr/sbin/wpa_supplicant -B -c /tmp/wpa_supplicant_ap.conf -O /var/run/wpa_supplicant -i wlan1

#bring up adapter scanning mechansim on interval bgscan="simple:30:-45:300" (default)
/usr/sbin/wpa_supplicant -B -u -c /etc/wpa_supplicant/wpa_supplicant.conf -O/var/run/wpa_supplicant -u -P /var/run/wpa_supplicant.pid -i wlan0

#toggle wifi on and off (necessary)
dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:false
dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:true

read -t 100 -n 1 -p "Please ensure your VPN connection is active and applied to the default route (waiting for 100s, press any key to continue)..." key

# Store interfaces in a variable
INTERFACES=$(ifconfig | grep "Link encap" | awk '{print $1}' | grep -vE "^(lo|rmnet_ipa0|rndis0|wlan1)$")

# Print the interfaces
echo "Matching Interfaces:"
for iface in $INTERFACES; do
    echo "$iface"
done

# Loop through interfaces and apply MASQUERADE
echo "Applying MASQUERADE rules:"
for iface in $INTERFACES; do
    echo "Adding NAT rule for interface: $iface"
    iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o "$iface" -j MASQUERADE
done

echo "now we see test_ap is online"

netstat -tunlp

pkill udhcpd

/home/defaultuser/python/venv/bin/python    /home/defaultuser/python/wlan1_dhcp_server.py
