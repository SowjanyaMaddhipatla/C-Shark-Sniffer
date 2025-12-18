C-Shark is a command-line network packet sniffer and analyzer developed in C Language using the libpcap library.
FEATURES : 
1. Detection of Available Network Interfaces. 
2. It enables real-time capturing and analysis of network traffic across multiple interfaces, can be done for full network packets and also Filters based on Protocols like HTTP, HTTPS, DNS, ARP, TCP, and UDP. 
3. It parses the Network packet from Ethernet Layer (L2) to Application Layer (L7).
4.  Persistent session storage with detailed packet inspection with ASCII conversion.
5. Reliable user interaction and signal handling.

TECHNOLOGIES USED :

1. Programming Language: C
2. Packet Capture Library: libpcap
3. Supported Protocols: Ethernet, IPv4/IPv6, TCP, UDP, ARP, ICMP
4. Data Storage: In-memory sessions, PCAP export

Applications:

1. Network traffic monitoring and analysis
2. Cybersecurity and threat detection

Code Structure & Descriptions : 

1. main.c : Does the User interaction and calls required action based on input given by the user.
2. Interfaces.c : It uses pcap library to Capture all interfaces and choose the interface to capture packets (according to user preference) .
3. Parser.c : It does the main Parsing of the capture packet layer by layer form L2 to L7
4. Sniffer.c : It helps in capturing packets from the choosen Interface (both filtered and unfiltered )
5. Storage.c : For the Storing and Detailed analysis of all captured packets from the previously (latest only) Sniffing Session.
