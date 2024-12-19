from scapy.all import *
from datetime import datetime
import sys
import os
import ipaddress

class DHCPServer:
    def __init__(self, interface="wlan1", server_ip="10.10.0.1", subnet="10.10.0.0/24"):
        self.interface = interface
        self.server_ip = server_ip
        self.subnet = ipaddress.ip_network(subnet)
        self.available_ips = list(self.subnet.hosts())[1:]  # Skip the first IP (server)
        self.leases = {}  # MAC -> (IP, lease_time)

    def log_packet(self, packet, step="", action="", success=False):
        """Log packet details with DHCP options."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        log_parts = [
            f"[{timestamp}] {step} {action}",
            f"Length: {len(packet)} bytes",
            f"Src MAC: {packet[Ether].src}",
            f"Dst MAC: {packet[Ether].dst}",
        ]
        
        # IP layer info
        if IP in packet:
            log_parts.extend([
                f"Src IP: {packet[IP].src}",
                f"Dst IP: {packet[IP].dst}",
                f"Protocol: {packet[IP].proto}"
            ])
        
        # UDP layer info
        if UDP in packet:
            log_parts.extend([
                f"Src Port: {packet[UDP].sport}",
                f"Dst Port: {packet[UDP].dport}"
            ])
        
        # Log basic packet details in one row
        print(" | ".join(log_parts))
        
        # DHCP options
        if DHCP in packet:
            dhcp_options = []
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple):
                    dhcp_options.append(f"{opt[0]}: {opt[1]}")
            if dhcp_options:
                print(f"DHCP Options: {', '.join(dhcp_options)}")
        
        # Success message for Acknowledgment
        if success:
            print(f"SUCCESS: Lease Acknowledged for MAC: {packet[Ether].src}")

    def get_ip_for_client(self, client_mac):
        if client_mac in self.leases:
            return self.leases[client_mac][0]
        
        if self.available_ips:
            ip = str(self.available_ips.pop(0))
            self.leases[client_mac] = (ip, 86400)
            return ip
        return None

    def handle_discover(self, packet):
        client_mac = packet[BOOTP].chaddr[:6].hex(':')
        xid = packet[BOOTP].xid

        self.log_packet(packet, step="Step 1:", action="Server Discovery Received")
        
        offered_ip = self.get_ip_for_client(client_mac)
        if not offered_ip:
            print(f"No IP addresses available for {client_mac}")
            return

        # Construct DHCP OFFER packet
        dhcp_offer = (
            Ether(dst=packet[Ether].src, src=get_if_hwaddr(self.interface)) /
            IP(src=self.server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,
                xid=xid,
                yiaddr=offered_ip,
                siaddr=self.server_ip,
                chaddr=packet[BOOTP].chaddr,
                giaddr=packet[BOOTP].giaddr
            ) /
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", self.server_ip),
                ("subnet_mask", "255.255.255.0"),
                ("router", self.server_ip),
                ("lease_time", 86400),
                ("renewal_time", 43200),
                ("rebinding_time", 75600),
                ("name_server", "8.8.8.8"),
                "end"
            ])
        )
        
        self.log_packet(dhcp_offer, step="Step 2:", action="Lease Offer Sent")
        sendp(dhcp_offer, iface=self.interface, verbose=False)

    def handle_request(self, packet):
        client_mac = packet[BOOTP].chaddr[:6].hex(':')
        xid = packet[BOOTP].xid

        self.log_packet(packet, step="Step 3:", action="Lease Request Received")
        
        requested_ip = None
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "requested_addr":
                requested_ip = opt[1]
                break
        
        if not requested_ip or requested_ip != self.leases.get(client_mac, (None,))[0]:
            print(f"Invalid IP request from {client_mac}")
            return

        dhcp_ack = (
            Ether(dst=packet[Ether].src, src=get_if_hwaddr(self.interface)) /
            IP(src=self.server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,
                xid=xid,
                yiaddr=requested_ip,
                siaddr=self.server_ip,
                chaddr=packet[BOOTP].chaddr,
                giaddr=packet[BOOTP].giaddr
            ) /
            DHCP(options=[
                ("message-type", "ack"),
                ("server_id", self.server_ip),
                ("subnet_mask", "255.255.255.0"),
                ("router", self.server_ip),
                ("lease_time", 86400),
                ("renewal_time", 43200),
                ("rebinding_time", 75600),
                ("name_server", "8.8.8.8"),
                "end"
            ])
        )
        
        self.log_packet(dhcp_ack, step="Step 4:", action="Lease Acknowledgment Sent", success=True)
        sendp(dhcp_ack, iface=self.interface, verbose=False)

    def process_packet(self, packet):
        if not packet.haslayer(DHCP):
            return

        dhcp_type = None
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                dhcp_type = opt[1]
                break

        if dhcp_type == 1:  # DISCOVER
            self.handle_discover(packet)
        elif dhcp_type == 3:  # REQUEST
            self.handle_request(packet)

    def start(self):
        print(f"Starting DHCP server on {self.interface}")
        print(f"Server IP: {self.server_ip}")
        print(f"Subnet: {self.subnet}")
        print(f"DNS Server: 8.8.8.8")
        print("Press Ctrl+C to stop the server")
        
        try:
            sniff(
                iface=self.interface,
                filter="udp and (port 67 or port 68)",
                prn=self.process_packet,
                store=0
            )
        except KeyboardInterrupt:
            print("\nDHCP server stopped.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

    server = DHCPServer()
    server.start()
