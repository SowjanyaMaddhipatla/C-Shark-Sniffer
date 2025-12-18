#ifndef INTERFACE_H
#define INTERFACE_H

#include <pcap.h>
#include <string.h>

#define MAX_INTERFACES 100
typedef struct {
    char name[64];
    char description[256];
} NetInterface;

int list_interfaces(NetInterface interfaces[], int max);
int choose_interface(NetInterface interfaces[], int count);

#endif
