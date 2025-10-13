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

while true; do
  echo "Choose an option:"
  echo "1) Openvpn My VPS"
  echo "2) Openvpn Nordvpn Vancouver"
  echo "3) Openvpn Nordvpn Seattle"
  echo "4) Exit"
  read -r choice

  if [ "$choice" = "1" ]; then
    echo "Openvpn My VPS"
    nohup openvpn --dev tun --config /home/defaultuser/Desktop/mark-phone.ovpn >/dev/null 2>&1 &
    echo "created tun0 device and sleep for 30s"
    sleep 30
    ip route del default && ip route add default dev tun0
    nohup sh -c 'while :; do if ping -I tun0 -c 10 8.8.8.8 >/dev/null 2>&1; then echo 255 | tee /sys/class/leds/blue/brightness; else echo 0 | sudo tee /sys/class/leds/blue/brightness; fi; sleep 4; done' >/dev/null 2>&1 &
    break

  elif [ "$choice" = "2" ]; then
    echo "Openvpn Nordvpn"
    nohup openvpn --dev tun --config /home/defaultuser/Desktop/nord-vancouver-openvpn.ovpn >/dev/null 2>&1 &
    echo "created tun0 device and sleep for 30s"
    sleep 30
    ip route del default && ip route add default dev tun0
    nohup sh -c 'while :; do if ping -I tun0 -c 10 8.8.8.8 >/dev/null 2>&1; then echo 255 | tee /sys/class/leds/blue/brightness; else echo 0 | sudo tee /sys/class/leds/blue/brightness; fi; sleep 4; done' >/dev/null 2>&1 &
    break

  elif [ "$choice" = "3" ]; then
    echo "Openvpn Nordvpn"
    nohup openvpn --dev tun --config /home/defaultuser/Desktop/nord-seattle-openvpn.ovpn >/dev/null 2>&1 &
    echo "created tun0 device and sleep for 30s"
    sleep 30
    ip route del default && ip route add default dev tun0
    nohup sh -c 'while :; do if ping -I tun0 -c 10 8.8.8.8 >/dev/null 2>&1; then echo 255 | tee /sys/class/leds/blue/brightness; else echo 0 | sudo tee /sys/class/leds/blue/brightness; fi; sleep 4; done' >/dev/null 2>&1 &
    break

  elif [ "$choice" = "4" ]; then
    echo "Exiting..."
    break

  else
    echo "Invalid option. Try again."
  fi
done

for iface in $(ifconfig | grep "Link encap" | awk '{print $1}' | grep -vE "^(lo|rmnet_ipa0|rndis0|wlan1)$"); do
  echo "modifying $iface"
  iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o "$iface" -j MASQUERADE
done

echo "now we see test_ap is online"

netstat -nr  

pkill udhcpd

/home/defaultuser/python/venv/bin/python    /home/defaultuser/python/wlan1_dhcp_server.py
