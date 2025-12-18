#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <pcap.h>



#define IF_NAME_LEN 128

// Ethernet header (L2)
typedef struct {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype; // host order
} EthernetHeader;

// IPv4 header (L3)
typedef struct {
    uint16_t ihl;      // in bytes (header length)
    uint8_t tos;
    uint16_t len;      // total length (host order)
    uint16_t id;       // host order
    uint16_t frag_off; // host order
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;      // network-order raw 32-bit (use inet_ntop to print)
    uint32_t dst;
} IPv4Header;

// IPv6 header (L3)
typedef struct {
    uint32_t ver_tc_fl; // raw 32-bit (network order)
    uint16_t payload_len; // host order
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
    // convenience:
    uint16_t payload_len_host;
} IPv6Header;

// ARP header (L3)
typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} ARPHeader;

// TCP header (L4)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t data_offset; // bytes
    uint8_t flags;        // raw flags byte
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} TCPHeader;

// UDP header (L4)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} UDPHeader;

/* Parse functions - fill structs from raw packet pointers */
void parse_ethernet(const u_char *packet, EthernetHeader *eth);
void parse_ipv4(const u_char *packet, IPv4Header *ip);
void parse_ipv6(const u_char *packet, IPv6Header *ip6);
void parse_arp(const u_char *packet, ARPHeader *arp);
void parse_tcp(const u_char *packet, TCPHeader *tcp);
void parse_udp(const u_char *packet, UDPHeader *udp);

/* Print functions - nicely formatted outputs matching your requirements */
void print_ethernet(const EthernetHeader *eth);
void print_ipv4(const IPv4Header *ip);
void print_ipv6(const IPv6Header *ip6);
void print_tcp(const TCPHeader *tcp);
void print_udp(const UDPHeader *udp);
const char *ip_proto_to_str(uint8_t proto);
/* Utility: identify common application protocols using both ports */
const char *identify_app_protocol(uint16_t src_port, uint16_t dst_port);

#endif // PARSER_H
