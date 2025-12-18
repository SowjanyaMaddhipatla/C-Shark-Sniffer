#include "interface.h"
#include <pcap.h> //packet capturing
#include <stdio.h>
#include <string.h>
#include <signal.h>

int list_interfaces(NetInterface interfaces[], int max)
{
   
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "[C-Shark] Error finding devices: %s\n", errbuf);
        return 0;
    }
    
    for (pcap_if_t *d = alldevs; d != NULL && i < max; d = d->next, i++)
    {
        strncpy(interfaces[i].name, d->name, sizeof(interfaces[i].name) - 1);
        interfaces[i].name[sizeof(interfaces[i].name) - 1] = '\0';

        if (d->description)
        {
            strncpy(interfaces[i].description, d->description, sizeof(interfaces[i].description) - 1);
            interfaces[i].description[sizeof(interfaces[i].description) - 1] = '\0';
        }
        else
        {
            strncpy(interfaces[i].description, " ", sizeof(interfaces[i].description) - 1);
            interfaces[i].description[sizeof(interfaces[i].description) - 1] = '\0';
        }

        printf("%d. %s %s\n", i + 1, interfaces[i].name, interfaces[i].description);
    }

    pcap_freealldevs(alldevs);
    
    return i; // number of interfaces found
}

int choose_interface(NetInterface interfaces[], int count)
{
    int choice = 0;
    printf("Select an interface to sniff (1-%d): ", count);
    
     struct sigaction sa_old, sa_new;
    sa_new.sa_handler = SIG_IGN;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0;
    sigaction(SIGINT, &sa_new, &sa_old);
   

    while (1)
    {
        int feedback = scanf("%d", &choice);

        if (feedback == EOF)  // Ctrl+D
        {
            printf("\n[Info] EOF detected. Exiting...\n");
            return -1; // indicate user wants to quit
        }
        else if (feedback != 1)
        {
            // Clear invalid input
            while (getchar() != '\n')
                ;
            printf("Invalid input. Enter a number between 1 and %d: ", count);
        }
        else if (choice < 1 || choice > count)
        {
            printf("Out of range. Enter a number between 1 and %d: ", count);
        }
        else
        {
            

            break;
        }
    }
    sigaction(SIGINT, &sa_old, NULL);

    return choice - 1; // return index
}
