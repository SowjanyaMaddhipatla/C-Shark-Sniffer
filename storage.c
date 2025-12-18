
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <ctype.h>

#include "storage.h"



PacketSession last_session; 

void session_init(PacketSession *s) {
    if (!s) return;
    s->capacity = MAX_PACKETS;
    s->count = 0;
    s->packets = (StoredPacket **)calloc(s->capacity, sizeof(StoredPacket *));
    if (!s->packets) {
        fprintf(stderr, "[C-Shark] session_init: allocation failed\n");
        s->capacity = 0;
    }
}

void session_free(PacketSession *s) {
    if (!s || !s->packets) return;
    for (int i = 0; i < s->count; ++i) {
        if (s->packets[i]) {
            free(s->packets[i]->data);
            free(s->packets[i]);
            s->packets[i] = NULL;
        }
    }
    free(s->packets);
    s->packets = NULL;
    s->count = 0;
    s->capacity = 0;
}

/* Deep-copy store */
int session_store_packet(PacketSession *s, const struct pcap_pkthdr *hdr, const u_char *packet) {
    if (!s || !s->packets || !hdr || !packet) return -1;
    if (s->count >= s->capacity) return -1; /* full */

    StoredPacket *sp = (StoredPacket *)malloc(sizeof(StoredPacket));
    if (!sp) return -1;
    sp->hdr = *hdr; /* copy header struct */
    sp->data = (u_char *)malloc(hdr->len);
    if (!sp->data) {
        free(sp);
        return -1;
    }
    memcpy(sp->data, packet, hdr->len);
    s->packets[s->count++] = sp;
    return 0;
}


/* Save to pcap file using pcap_dump */
int session_save_to_pcap(const PacketSession *s, const char *filename, int linktype, int snaplen) {
    if (!s || !filename) return -1;
    if (s->count == 0) {
        fprintf(stderr, "[C-Shark] session_save_to_pcap: no packets to save\n");
        return -1;
    }

    /* Create a fake pcap_t to write file headers */
    pcap_t *dead = pcap_open_dead(linktype, snaplen);
    if (!dead) {
        fprintf(stderr, "[C-Shark] session_save_to_pcap: pcap_open_dead failed\n");
        return -1;
    }

    pcap_dumper_t *dumper = pcap_dump_open(dead, filename);
    if (!dumper) {
        fprintf(stderr, "[C-Shark] session_save_to_pcap: pcap_dump_open failed: %s\n", pcap_geterr(dead));
        pcap_close(dead);
        return -1;
    }

    for (int i = 0; i < s->count; ++i) {
        StoredPacket *sp = s->packets[i];
        if (!sp) continue;
        /* pcap_dump expects (u_char*)dumper as first arg */
        pcap_dump((u_char *)dumper, &sp->hdr, sp->data);
    }

    pcap_dump_close(dumper);
    pcap_close(dead);
    return 0;
}


void session_print_summary(const PacketSession *s) {
    if (!s || !s->packets) {
        printf("[C-Shark] No session available.\n");
        return;
    }
    printf("[C-Shark] Stored packets: %d\n", s->count);
    for (int i = 0; i < s->count; ++i) {
        StoredPacket *sp = s->packets[i];
        if (!sp) continue;
        printf("[%d] Timestamp: %ld.%06u | Length: %u bytes\n", i+1,
               (long)sp->hdr.ts.tv_sec, (unsigned)sp->hdr.ts.tv_usec, (unsigned)sp->hdr.len);
    }
}

void session_print_packet(const PacketSession *s, int index) {
    if (!s || !s->packets) {
        printf("[C-Shark] No session available.\n");
        return;
    }
    if (index < 0 || index >= s->count) {
        printf("[C-Shark] Invalid packet index (valid 0..%d)\n", s->count - 1);
        return;
    }
    StoredPacket *sp = s->packets[index];
    if (!sp) {
        printf("[C-Shark] Corrupt stored packet at index %d\n", index);
        return;
    }
    printf("Stored Packet #%d | Timestamp: %ld.%06u | Length: %u bytes\n",
           index+1, (long)sp->hdr.ts.tv_sec, (unsigned)sp->hdr.ts.tv_usec, (unsigned)sp->hdr.len);

    /* print first 64 bytes hex/ASCII similar to sniffer's dump */
    int display_len = (sp->hdr.len < 64) ? sp->hdr.len : 64;
    for (int i = 0; i < display_len; i++) {
        printf("%02X ", sp->data[i]);
        if ((i+1) % 16 == 0) {
            printf(" ");
            for (int j = i-15; j <= i; ++j)
                printf("%c", (sp->data[j] >= 32 && sp->data[j] <= 126) ? sp->data[j] : '.');
            printf("\n");
        }
    }
    if (display_len % 16) {
        int rem = 16 - (display_len % 16);
        for (int i = 0; i < rem; ++i) printf("   ");
        printf(" ");
        int start = display_len - (display_len % 16);
        for (int j = start; j < display_len; ++j)
            printf("%c", (sp->data[j] >= 32 && sp->data[j] <= 126) ? sp->data[j] : '.');
        printf("\n");
    }
}

