Enable wifi sharing/ wifi repating on SailfishOS
this creats a wifi access point, deriverd from the wifi band in your sailfishos device.
<img src=https://raw.githubusercontent.com/RetributionByRevenue/SailfishOS-wifi-access-point/refs/heads/main/wifi.PNG>
a interface called wlan1 is created and occupies 10.10.0.0/16.
furthermore, a DHCP server can be launched that will handle the DHCP negotiation and allow you to connect to the access point effortlessly. 
<img src="https://github.com/RetributionByRevenue/SailfishOS-wifi-access-point/blob/main/wlan1_dhcp_server%20screenshot.PNG?raw=true">
you will need to create a python virtual enviroment and pip install scapy
