#ifndef SNIFFER_H
#define SNIFFER_H

#include "interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
void start_sniffing(const char *iface);
void start_sniffing_filtered(const char *iface, const char *filter_exp);

void inspect_last_session(void);   // <--- new

extern volatile sig_atomic_t stop_sniff;
extern volatile sig_atomic_t return_to_menu;
void handle_sigint(int sig);

#endif

