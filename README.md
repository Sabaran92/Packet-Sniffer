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

## Legal Disclaimer
This packet sniffer script is provided for educational purposes only. It is intended to help users learn about network protocols and how packet sniffing works. 

### Usage Policy
- *Authorized Use*: This script should only be used on networks you own, have explicit permission to monitor, or are legally authorized to test. Unauthorized use of this script to capture packets on networks without permission is illegal and unethical.
- *Compliance*: Ensure you comply with all applicable local, state, and federal laws and regulations regarding network monitoring and data privacy.

### Responsibilities
- *Educational Tool*: The author of this script is not responsible for any misuse or illegal activities conducted with this script. The user assumes all responsibility for any consequences that arise from using this script.
- *Data Security*: Network traffic may contain sensitive and private information. Ensure you handle any captured data responsibly and in accordance with data protection regulations.

### Limitations
- *No Warranty*: This script is provided "as is" without any warranty of any kind. The author does not guarantee its accuracy, reliability, or functionality in all scenarios.
- *Liability*: The author shall not be liable for any direct, indirect, incidental, or consequential damages arising from the use or inability to use this script.

By using this packet sniffer script, you agree to the terms outlined in this disclaimer and accept full responsibility for your actions.
