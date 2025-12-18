
#include "sniffer.h"
#include "parser.h"
#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

volatile sig_atomic_t stop_sniff = 0;
volatile sig_atomic_t return_to_menu = 0; 

/* Ctrl+C handler */
 void handle_sigint(int sig)
 {
     (void)sig;
     stop_sniff = 1;
 }



/* Prepare new session: free old session and init new */
static void prepare_new_session(void)
{
    session_free(&last_session);
    session_init(&last_session);
}

/* Print first 64 bytes of payload */

void print_payload_range(const u_char *payload, int len)
{
    int display_len = (len < 64) ? len : 64;
    printf("L7 (Payload): %d bytes | Bytes 0-%d\n", len, display_len - 1);
    printf("Data (first %d bytes):\n", display_len);
    for (int i = 0; i < display_len; i++)
    {
        printf("%02X ", payload[i]);
        if ((i + 1) % 16 == 0)
        {
            printf(" ");
            for (int j = i - 15; j <= i; ++j)
                printf("%c", (payload[j] >= 32 && payload[j] <= 126) ? payload[j] : '.');
            printf("\n");
        }
    }
    if (display_len % 16 != 0)
    {
        int rem = 16 - (display_len % 16);
        for (int i = 0; i < rem; i++)
            printf("   ");
        printf(" ");
        for (int j = display_len - (display_len % 16); j < display_len; j++)
            printf("%c", (payload[j] >= 32 && payload[j] <= 126) ? payload[j] : '.');
        printf("\n");
    }
}



void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;

    static int packet_count = 0;
    packet_count++;

    printf("\n-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %u bytes\n",
           packet_count,
           (long)header->ts.tv_sec,
           (long)header->ts.tv_usec,
           header->len);

    /* Store in session */
    if (session_store_packet(&last_session, header, packet) != 0)
    {
        static int warned = 0;
        if (!warned)
        {
            fprintf(stderr, "[C-Shark] Warning: session storage full; future packets won't be stored.\n");
            warned = 1;
        }
    }

    /* --- Parse L2 Ethernet --- */
    EthernetHeader eth;
    parse_ethernet(packet, &eth);
    print_ethernet(&eth);

    const u_char *l3_packet = packet + 14;
    int l3_len = header->len - 14;

     const u_char *payload  = l3_packet;
     int payload_len = l3_len;
    /* --- IPv4 --- */
    if (eth.ethertype == 0x0800 && l3_len >= 20)
    {
        IPv4Header ip;
        parse_ipv4(l3_packet, &ip);
        print_ipv4(&ip);

        const u_char *l4_packet = l3_packet + ip.ihl;
        int l4_len = ip.len - ip.ihl;
        if (l4_len < 0)
            l4_len = 0;

        if (ip.protocol == 6 && l4_len >= 20) // TCP
        {
            TCPHeader tcp;
            parse_tcp(l4_packet, &tcp);
            print_tcp(&tcp);

            payload = l4_packet + tcp.data_offset;
            payload_len = l4_len - tcp.data_offset;
            if (payload_len > 0)
            {
                const char *proto = identify_app_protocol(tcp.src_port, tcp.dst_port);
                printf("L7 (Payload): Identified as %s | %d bytes\n", proto, payload_len);
                //print_payload_range(payload, payload_len);
            }
        }
        else if (ip.protocol == 17 && l4_len >= 8) // UDP
        {
            UDPHeader udp;
            parse_udp(l4_packet, &udp);
            print_udp(&udp);

            payload = l4_packet + 8;
            payload_len = udp.len - 8;
            if (payload_len > 0)
            {
                const char *proto = identify_app_protocol(udp.src_port, udp.dst_port);
                printf("L7 (Payload): Identified as %s | %d bytes\n", proto, payload_len);
                //print_payload_range(payload, payload_len);
            }
        }
        else
    {
        // Assign payload for non-TCP/UDP (e.g., ICMPv6)
        payload = l4_packet;
        payload_len = l4_len;
    }
    }
    /* --- IPv6 --- */
    else if (eth.ethertype == 0x86DD && l3_len >= 40)
    {
        IPv6Header ip6;
        parse_ipv6(l3_packet, &ip6);
        print_ipv6(&ip6);

        const u_char *l4_packet = l3_packet + 40; // TCP/UDP starts after 40-byte IPv6 header
        int l4_len = ip6.payload_len_host;

        if (ip6.next_header == 6 && l4_len >= 20) // TCP
        {
            TCPHeader tcp;
            parse_tcp(l4_packet, &tcp);
            print_tcp(&tcp);

            payload = l4_packet + tcp.data_offset;
            payload_len = l4_len - tcp.data_offset;
            if (payload_len > 0)
            {
                const char *proto = identify_app_protocol(tcp.src_port, tcp.dst_port);
                printf("L7 (Payload): Identified as %s | %d bytes\n", proto, payload_len);
                //print_payload_range(payload, payload_len);
            }
        }
        else if (ip6.next_header == 17 && l4_len >= 8) // UDP
        {
            UDPHeader udp;
            parse_udp(l4_packet, &udp);
            print_udp(&udp);

            payload = l4_packet + 8;
            payload_len = udp.len - 8;
            if (payload_len > 0)
            {
                const char *proto = identify_app_protocol(udp.src_port, udp.dst_port);
                printf("L7 (Payload): Identified as %s | %d bytes\n", proto, payload_len);
                //print_payload_range(payload, payload_len);
            }
        }
        else
    {
        // Assign payload for non-TCP/UDP (e.g., ICMPv6)
        payload = l4_packet;
        payload_len = l4_len;
    }
    }
    /* --- ARP --- */
   
    else if (eth.ethertype == 0x0806 && l3_len >= 28)
    {
       
        ARPHeader arp;
    parse_arp(l3_packet, &arp);  // correctly parse the ARP header

    printf("\n--- L3 (ARP) ---\n");
    printf("Operation: %s\n", (arp.opcode == 1 ? "Request" : (arp.opcode == 2 ? "Reply" : "Unknown")));
    printf("Hardware Type: 0x%04X | Protocol Type: 0x%04X\n", arp.htype, arp.ptype);
    printf("Hardware Length: %u | Protocol Length: %u\n", arp.hlen, arp.plen);
    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp.sender_mac[0], arp.sender_mac[1], arp.sender_mac[2],
           arp.sender_mac[3], arp.sender_mac[4], arp.sender_mac[5]);
    printf("Sender IP: %u.%u.%u.%u\n",
           arp.sender_ip[0], arp.sender_ip[1], arp.sender_ip[2], arp.sender_ip[3]);
    printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp.target_mac[0], arp.target_mac[1], arp.target_mac[2],
           arp.target_mac[3], arp.target_mac[4], arp.target_mac[5]);
    printf("Target IP: %u.%u.%u.%u\n",
           arp.target_ip[0], arp.target_ip[1], arp.target_ip[2], arp.target_ip[3]);

    // Optionally, you can also print the ARP packet payload in hex
    const u_char *payload = l3_packet + sizeof(ARPHeader);
    int payload_len = l3_len - sizeof(ARPHeader);
    if (payload_len < 0)
        payload_len =0;
    }

    print_payload_range(payload, payload_len);

    fflush(stdout);
}


/* Start sniffing all packets */
void start_sniffing(const char *iface)
{
    prepare_new_session();
    
    
   
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
  
    if (!handle)
    {
        printf("Error opening interface %s: %s\n", iface, errbuf);
        
        return;
    }

    signal(SIGINT, handle_sigint);
    printf("[Sniffer] Capturing all packets on %s. Press Ctrl+C to stop...\n", iface);

    stop_sniff = 0;
    while (!stop_sniff)
    {
        
        pcap_dispatch(handle, 1, packet_handler, NULL);
        // handle give one packet and dispactch does this A pcap_pkthdr struct → containing metadata (timestamp, captured length, etc.)
        // A u_char* pointer → pointing to the actual raw bytes of the packet.

     
    }

    pcap_close(handle);
    printf("[Sniffer] Capture stopped. Total packets: %d\n", last_session.count);
    
}

/* Start sniffing with filter */
void start_sniffing_filtered(const char *iface, const char *filter_expr)
{
    prepare_new_session();
   
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        printf("Error opening interface %s: %s\n", iface, errbuf);
       
        return;
    }
  
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("Error compiling filter %s: %s\n", filter_expr, pcap_geterr(handle));
        pcap_close(handle);
       
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
       
        return;
    }

    
    pcap_freecode(&fp);

    signal(SIGINT, handle_sigint);
    printf("[Sniffer] Capturing filtered packets (%s) on %s. Press Ctrl+C to stop...\n", filter_expr, iface);

    stop_sniff = 0;
    while (!stop_sniff)
    {
        pcap_dispatch(handle, 1, packet_handler, NULL);
    }

   
    pcap_close(handle);
    printf("[Sniffer] Capture stopped. Total packets: %d\n", last_session.count);
}

/* Hex dump helper */
static void print_full_hex(const u_char *data, int len)
{
    for (int i = 0; i < len; i += 16)
    {
        // Print offset
        printf("%04X  ", i);

        // Print hex bytes
        int j;
        for (j = 0; j < 16 && (i + j) < len; j++)
            printf("%02X ", data[i + j]);

        // Pad remaining space if line < 16 bytes
        for (; j < 16; j++)
            printf("   ");

        // Print ASCII representation
        printf(" ");
        for (j = 0; j < 16 && (i + j) < len; j++)
        {
            u_char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
}


void inspect_last_session(void)
{
    if (last_session.count == 0)
    {
        printf("[C-Shark] No packets in last session.\n");
        return;
    }

    printf("[C-Shark] Last session packets summary:\n");
    for (int i = 0; i < last_session.count; i++)
    {
        StoredPacket *pkt = last_session.packets[i];
        if (!pkt)
            continue;
        printf("[%d] Timestamp: %ld.%06u | Length: %u bytes\n",
               i + 1, (long)pkt->hdr.ts.tv_sec, (unsigned)pkt->hdr.ts.tv_usec, (unsigned)pkt->hdr.len);

        // Minimal L3/L4 info
        EthernetHeader eth;
        parse_ethernet(pkt->data, &eth);
        if (eth.ethertype == 0x0800 && pkt->hdr.len >= 34)
        {
            IPv4Header ip;
            parse_ipv4(pkt->data + 14, &ip);
            printf("     IPv4: %u.%u.%u.%u -> %u.%u.%u.%u | Proto: %s (%u)\n",
                   (ip.src >> 0) & 0xFF, (ip.src >> 8) & 0xFF, (ip.src >> 16) & 0xFF, (ip.src >> 24) & 0xFF,
                   (ip.dst >> 0) & 0xFF, (ip.dst >> 8) & 0xFF, (ip.dst >> 16) & 0xFF, (ip.dst >> 24) & 0xFF,
                   ip_proto_to_str(ip.protocol), ip.protocol);
        }
    }

    int id;
    printf("Enter Packet ID to inspect: ");
    if (scanf("%d", &id) != 1 || id < 1 || id > last_session.count)
    {
        printf("Invalid Packet ID\n");
        return;
    }

    StoredPacket *pkt = last_session.packets[id - 1];
    if (!pkt)
    {
        printf("Corrupt packet at ID %d\n", id);
        return;
    }

    printf("\n[Inspecting Packet #%d | Length: %u bytes]\n", id, (unsigned)pkt->hdr.len);

    // --- Full packet hex dump ---
    printf("\n--- Full Packet Hex Dump ---\n");
    print_full_hex(pkt->data, pkt->hdr.len);

    const u_char *ptr = pkt->data;
    int remaining_len = pkt->hdr.len;

    // --- L2 Ethernet ---
    if (remaining_len >= 14)
    {
        printf("\n--- L2 (Ethernet) ---\n");
        print_full_hex(ptr, 14); // raw Ethernet header
        EthernetHeader eth;
        parse_ethernet(ptr, &eth);
        print_ethernet(&eth);
        ptr += 14;
        remaining_len -= 14;

        // --- L3 ---
        if (eth.ethertype == 0x0800 && remaining_len >= 20)
        { // IPv4
            printf("\n--- L3 (IPv4) ---\n");
            print_full_hex(ptr, 20); // first 20 bytes of IPv4 header
            IPv4Header ip;
            parse_ipv4(ptr, &ip);
            print_ipv4(&ip);
            int ip_header_len = ip.ihl;
            ptr += ip_header_len;
            remaining_len -= ip_header_len;

            // --- L4 ---
            if (ip.protocol == 6 && remaining_len >= 20)
            { // TCP
                printf("\n--- L4 (TCP) ---\n");
                print_full_hex(ptr, 20); // first 20 bytes TCP header
                TCPHeader tcp;
                parse_tcp(ptr, &tcp);
                print_tcp(&tcp);
                int tcp_header_len = tcp.data_offset;
                ptr += tcp_header_len;
                remaining_len -= tcp_header_len;

                // --- L7 ---
                if (remaining_len > 0)
                {
                    printf("\n--- L7 (Payload) ---\n");
                    print_payload_range(ptr, remaining_len);
                }
            }
            else if (ip.protocol == 17 && remaining_len >= 8)
            { // UDP
                printf("\n--- L4 (UDP) ---\n");
                print_full_hex(ptr, 8);
                UDPHeader udp;
                parse_udp(ptr, &udp);
                print_udp(&udp);
                ptr += 8;
                remaining_len -= 8;

                if (remaining_len > 0)
                {
                    printf("\n--- L7 (Payload) ---\n");
                    print_payload_range(ptr, remaining_len);
                }
            }
        }
        else if (eth.ethertype == 0x86DD && remaining_len >= 40)
        { // IPv6
            printf("\n--- L3 (IPv6) ---\n");
            print_full_hex(ptr, 40);
            IPv6Header ip6;
            parse_ipv6(ptr, &ip6);
            print_ipv6(&ip6);
            ptr += 40;
            remaining_len -= 40;

            // --- L4 ---
            if (ip6.next_header == 6 && remaining_len >= 20)
            { // TCP
                printf("\n--- L4 (TCP) ---\n");
                print_full_hex(ptr, 20);
                TCPHeader tcp;
                parse_tcp(ptr, &tcp);
                print_tcp(&tcp);
                int tcp_header_len = tcp.data_offset;
                ptr += tcp_header_len;
                remaining_len -= tcp_header_len;

                // --- L7 ---
                if (remaining_len > 0)
                {
                    printf("\n--- L7 (Payload) ---\n");
                    print_payload_range(ptr, remaining_len);
                }
            }
            else if (ip6.next_header == 17 && remaining_len >= 8)
            { // UDP
                printf("\n--- L4 (UDP) ---\n");
                print_full_hex(ptr, 8);
                UDPHeader udp;
                parse_udp(ptr, &udp);
                print_udp(&udp);
                ptr += 8;
                remaining_len -= 8;

                if (remaining_len > 0)
                {
                    printf("\n--- L7 (Payload) ---\n");
                    print_payload_range(ptr, remaining_len);
                }
            }
        }
        else if (eth.ethertype == 0x0806 && remaining_len >= 28)
        { // ARP
            printf("\n--- L3 (ARP) ---\n");
            print_full_hex(ptr, 28);
            ARPHeader arp;
            parse_arp(ptr, &arp);
            printf("Opcode: %s | Sender IP: %u.%u.%u.%u | Target IP: %u.%u.%u.%u\n",
                   (arp.opcode == 1 ? "Request" : (arp.opcode == 2 ? "Reply" : "Unknown")),
                   arp.sender_ip[0], arp.sender_ip[1], arp.sender_ip[2], arp.sender_ip[3],
                   arp.target_ip[0], arp.target_ip[1], arp.target_ip[2], arp.target_ip[3]);
        }
    }
}
