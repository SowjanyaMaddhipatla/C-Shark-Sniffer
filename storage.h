#ifndef PACKET_STORAGE_H
#define PACKET_STORAGE_H

#include <pcap.h>
#include <stdint.h>


#define MAX_PACKETS 10000  /* capacity for last session */



typedef struct {
    struct pcap_pkthdr hdr; /* copy of header */
    u_char *data;           /* malloc'd packet bytes */
} StoredPacket;

typedef struct {
    StoredPacket **packets; /* dynamic array of StoredPacket* (size MAX_PACKETS) */
    int count;              /* number currently stored */
    int capacity;           /* should be MAX_PACKETS */
} PacketSession;

/* Initialize session (must be called before storing) */
void session_init(PacketSession *s);

/* Free all memory owned by the session */
void session_free(PacketSession *s);

/* Store a packet (makes a deep copy). Returns 0 on success, -1 on failure (e.g. full). */
int session_store_packet(PacketSession *s, const struct pcap_pkthdr *hdr, const u_char *packet);

/* Save session to a libpcap file. Returns 0 on success, -1 on failure. */
/* The function uses pcap_open_dead(DLT_EN10MB, snaplen) internally so it doesn't need the live handle. */
int session_save_to_pcap(const PacketSession *s, const char *filename, int linktype, int snaplen);

/* Print brief summary of session (count + timestamps) */
void session_print_summary(const PacketSession *s);

/* Print a stored packet summary (index 0..count-1) */
void session_print_packet(const PacketSession *s, int index);


extern PacketSession last_session;


#endif /* PACKET_STORAGE_H */
