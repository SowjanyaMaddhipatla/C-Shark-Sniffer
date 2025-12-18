#include "parser.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>


/* Helper: friendly names for EtherType and protocol */
static const char *ether_type_to_str(uint16_t ethertype) {
    switch (ethertype) {
        case 0x0800: return "IPv4";
        case 0x86DD: return "IPv6";
        case 0x0806: return "ARP";
        default:     return "Unknown";
    }
}

const char *ip_proto_to_str(uint8_t p) {
    switch (p) {
        case 6:  return "TCP";
        case 17: return "UDP";
        case 1:  return "ICMP";
        case 58: return "ICMPv6";
        default: return "Other";
    }
}

/* Identify common app protocols from ports (uses both src & dst) */
const char *identify_app_protocol(uint16_t src_port, uint16_t dst_port) {
    if (src_port == 80 || dst_port == 80) return "HTTP";
    if (src_port == 443 || dst_port == 443) return "HTTPS/TLS";
    if (src_port == 53 || dst_port == 53) return "DNS";
    if (src_port == 25 || dst_port == 25) return "SMTP";
    if (src_port == 53 || dst_port == 53) return "DNS";
    return "Unknown";
}

/* ---- Parse implementations ---- */

void parse_ethernet(const u_char *packet, EthernetHeader *eth) {
    memcpy(eth->dst, packet, 6);
    memcpy(eth->src, packet + 6, 6);
    eth->ethertype = ntohs(*(uint16_t *)(packet + 12));
}

void parse_ipv4(const u_char *packet, IPv4Header *ip) {
    // packet points to the IPv4 header start
    uint8_t ver_ihl = packet[0];
    uint8_t ihl_words = ver_ihl & 0x0F;
    ip->ihl = (uint16_t)(ihl_words * 4); // bytes
    ip->tos = packet[1];
    ip->len = ntohs(*(uint16_t *)(packet + 2));
    ip->id = ntohs(*(uint16_t *)(packet + 4));
    ip->frag_off = ntohs(*(uint16_t *)(packet + 6));
    ip->ttl = packet[8];
    ip->protocol = packet[9];
    ip->checksum = ntohs(*(uint16_t *)(packet + 10));
    memcpy(&ip->src, packet + 12, 4);
    memcpy(&ip->dst, packet + 16, 4);
}



void parse_ipv6(const u_char *packet, IPv6Header *ip6) {
    if (!packet || !ip6) return;

    // First 4 bytes: Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint32_t vtf = ntohl(*(uint32_t *)packet);
    ip6->ver_tc_fl = vtf; // store network-order 32-bit raw value

    // Payload length: bytes 4-5
    ip6->payload_len = ntohs(*(uint16_t *)(packet + 4));
    ip6->payload_len_host = ip6->payload_len; // convenience field

    // Next Header: byte 6
    ip6->next_header = packet[6];

    // Hop Limit: byte 7
    ip6->hop_limit = packet[7];

    // Source address: bytes 8-23
    memcpy(ip6->src, packet + 8, 16);

    // Destination address: bytes 24-39
    memcpy(ip6->dst, packet + 24, 16);

    // Safety: zero out unused fields if struct is extended in future
    // (optional depending on your parser)
}



void parse_arp(const u_char *packet, ARPHeader *arp) {
    // packet points to start of ARP header
    arp->htype = ntohs(*(uint16_t *)(packet + 0));
    arp->ptype = ntohs(*(uint16_t *)(packet + 2));
    arp->hlen = packet[4];
    arp->plen = packet[5];
    arp->opcode = ntohs(*(uint16_t *)(packet + 6));
    memcpy(arp->sender_mac, packet + 8, 6);
    memcpy(arp->sender_ip, packet + 14, 4);
    memcpy(arp->target_mac, packet + 18, 6);
    memcpy(arp->target_ip, packet + 24, 4);
}

void parse_tcp(const u_char *packet, TCPHeader *tcp) {
    // packet is start of TCP header (no IP offset)
    tcp->src_port = ntohs(*(uint16_t *)(packet + 0));
    tcp->dst_port = ntohs(*(uint16_t *)(packet + 2));
    tcp->seq = ntohl(*(uint32_t *)(packet + 4));
    tcp->ack = ntohl(*(uint32_t *)(packet + 8));
    // data offset is top 4 bits of byte 12 (in 32-bit words)
    tcp->data_offset = ((packet[12] >> 4) & 0x0F) * 4;
    tcp->flags = packet[13];
    tcp->window = ntohs(*(uint16_t *)(packet + 14));
    tcp->checksum = ntohs(*(uint16_t *)(packet + 16));
    tcp->urgent = ntohs(*(uint16_t *)(packet + 18));
}

void parse_udp(const u_char *packet, UDPHeader *udp) {
    udp->src_port = ntohs(*(uint16_t *)(packet + 0));
    udp->dst_port = ntohs(*(uint16_t *)(packet + 2));
    udp->len = ntohs(*(uint16_t *)(packet + 4));
    udp->checksum = ntohs(*(uint16_t *)(packet + 6));
}

/* ---- Print implementations ---- */

static void format_mac(const uint8_t *mac, char *buf, size_t buflen) {
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}



void print_ethernet(const EthernetHeader *eth) {
    char dst[18], src[18];
    format_mac(eth->dst, dst, sizeof(dst));
    format_mac(eth->src, src, sizeof(src));
    printf("L2 (Ethernet): Dst MAC: %s | Src MAC: %s | EtherType: %s (0x%04X)\n",
           dst, src, ether_type_to_str(eth->ethertype), eth->ethertype);
}

void print_ipv4(const IPv4Header *ip) {
    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    struct in_addr s, d;
    memcpy(&s.s_addr, &ip->src, 4);
    memcpy(&d.s_addr, &ip->dst, 4);
    inet_ntop(AF_INET, &s, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &d, dst_buf, sizeof(dst_buf));

    // Format protocol name with number
    const char *pname = ip_proto_to_str(ip->protocol);
    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%u) | TTL: %u | ID: 0x%X\n| Header Len: %u bytes | Total Len: %u  ",
           src_buf, dst_buf, pname, ip->protocol,
           ip->ttl, ip->id, ip->ihl, ip->len);

    // Flags decode (DF/MF)
    unsigned short frag = ip->frag_off;
    int df = (frag & 0x4000) ? 1 : 0;
    int mf = (frag & 0x2000) ? 1 : 0;
    if (df || mf) {
        printf("IP Flags:");
        if (df) printf(" [DF]");
        if (mf) printf(" [MF]");
        printf("\n");
    }
}

void print_ipv6(const IPv6Header *ip6) {
    char src_buf[INET6_ADDRSTRLEN], dst_buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip6->src, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET6, ip6->dst, dst_buf, sizeof(dst_buf));

    uint32_t vtf = ntohl(ip6->ver_tc_fl);
    uint8_t version = (vtf >> 28) & 0x0F;
    uint8_t traffic_class = (vtf >> 20) & 0xFF;
    uint32_t flow_label = vtf & 0xFFFFF;

    const char *next_name = ip_proto_to_str(ip6->next_header);

    printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%u) | Hop Limit: %u\n",
           src_buf, dst_buf, next_name, ip6->next_header, ip6->hop_limit);

    printf("Traffic Class: %u | Flow Label: 0x%05X | Payload Length: %u\n",
           traffic_class, flow_label, ip6->payload_len);
}

void print_tcp(const TCPHeader *tcp) {
    // Identify common well-known service by destination port (as required)
    const char *svc = identify_app_protocol(tcp->src_port, tcp->dst_port);
    // Format flags into a list
    char flags_buf[128] = {0};
    int pos = 0;
    if (tcp->flags & 0x01) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",FIN":"FIN");
    if (tcp->flags & 0x02) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",SYN":"SYN");
    if (tcp->flags & 0x04) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",RST":"RST");
    if (tcp->flags & 0x08) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",PSH":"PSH");
    if (tcp->flags & 0x10) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",ACK":"ACK");
    if (tcp->flags & 0x20) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",URG":"URG");
    if (tcp->flags & 0x40) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",ECE":"ECE");
    if (tcp->flags & 0x80) pos += snprintf(flags_buf + pos, sizeof(flags_buf)-pos, "%s", pos ? ",CWR":"CWR");

    // If svc is not "Unknown" print service name after dst port
    if (svc && strcmp(svc, "Unknown") != 0) {
        printf("L4 (TCP): Src Port: %u | Dst Port: %u (%s) | Seq: %u | Ack: %u | Flags: [%s] | Window: %u | Checksum: 0x%04X | Header Length: %u bytes\n",
               tcp->src_port, tcp->dst_port, svc, tcp->seq, tcp->ack,
               (pos ? flags_buf : "None"), tcp->window, tcp->checksum, tcp->data_offset);
    } else {
        printf("L4 (TCP): Src Port: %u | Dst Port: %u (Unknown) | Seq: %u | Ack: %u | Flags: [%s] | Window: %u | Checksum: 0x%04X | Header Length: %u bytes\n",
               tcp->src_port, tcp->dst_port, tcp->seq, tcp->ack,
               (pos ? flags_buf : "None"), tcp->window, tcp->checksum, tcp->data_offset);
    }
}

void print_udp(const UDPHeader *udp) {
    const char *svc = identify_app_protocol(udp->src_port, udp->dst_port);
    if (svc && strcmp(svc, "Unknown") != 0) {
        printf("L4 (UDP): Src Port: %u | Dst Port: %u (%s) | Length: %u | Checksum: 0x%04X\n",
               udp->src_port, udp->dst_port, svc, udp->len, udp->checksum);
    } else {
        printf("L4 (UDP): Src Port: %u | Dst Port: %u (Unknown) | Length: %u | Checksum: 0x%04X\n",
               udp->src_port, udp->dst_port, udp->len, udp->checksum);
    }
}
