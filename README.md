# Packet-Sniffer
Packet Sniffer
A simple packet sniffer script written in Python using the Scapy library. This script captures and displays Ethernet frames, IP packets, TCP segments, UDP datagrams, and ICMP packets.

**Features**
This script offers the following features:
Captures and displays Ethernet frames, including source and destination MAC addresses and Ethernet frame types.
Captures and displays IP packets, including source and destination IP addresses and TTL values.
Captures and displays TCP segment details such as source/destination ports, sequence and acknowledgment numbers, and flags.
Captures and displays UDP datagram details such as source/destination ports and length.
Captures and displays ICMP type and code.

**Prerequisites**
To run this script, you need:
Python 3.x installed on your system. You can download it from the official Python website.
Scapy library installed. You can install it using pip by running pip install scapy.

**Running the Script**
To run the script, use the following command:
python3 packet_sniffer.py <interface>
Replace <interface> with the network interface you want to capture packets on. For example, use eth0 for Ethernet or wlan0 for Wi-Fi.

**Script Details**
The script imports necessary modules from the scapy library.
The packet_callback function processes each captured packet, extracting and printing relevant information based on the packet's layers.
The main part of the script checks for the correct usage and expects a network interface name as a command-line argument. It then uses scapy.sniff() to capture packets on the specified interface and applies the packet_callback function to each packet.
