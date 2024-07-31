import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether

def packet_callback(packet):
    # Check if the packet has an Ethernet layer
    if Ether in packet:
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        eth_type = packet[Ether].type
        print(f"Ethernet Frame: {eth_src} -> {eth_dst} (Type: {eth_type})")
        
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ttl = packet[IP].ttl
        print(f"IP Packet: {ip_src} -> {ip_dst} (TTL: {ttl})")
        
        # Check for TCP packets
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            tcp_seq = packet[TCP].seq
            tcp_ack = packet[TCP].ack
            tcp_flags = packet[TCP].flags
            print(f"TCP Segment: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport} (Seq: {tcp_seq}, Ack: {tcp_ack}, Flags: {tcp_flags})")
        
        # Check for UDP packets
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            udp_len = packet[UDP].len
            print(f"UDP Datagram: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport} (Length: {udp_len})")
        
        # Check for ICMP packets
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"ICMP Packet: {ip_src} -> {ip_dst} (Type: {icmp_type}, Code: {icmp_code})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 packet_sniffer.py <interface>")
        sys.exit(1)

    # Get the interface from the command-line arguments
    interface = sys.argv[1]

    # Sniff packets on the specified interface and apply the callback function
    sniff(iface=interface, prn=packet_callback, store=0)