// main.c
#include <stdio.h>
#include <stdlib.h>
#include "interface.h" // Contains NetInterface struct and list_interfaces/choose_interface
#include "sniffer.h"
#include "storage.h"
// #include "session.h"

int main()
{
    signal(SIGINT, handle_sigint);
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");

    // Phase 1: Discover interfaces
    printf("[C-Shark] Searching for available interfaces... ");
    NetInterface interfaces[MAX_INTERFACES];
    int count = list_interfaces(interfaces, MAX_INTERFACES);
    if (count == 0)
    {
        printf("No interfaces found! Exiting...\n");
        return 1;
    }

    // User selects interface
    int choice = choose_interface(interfaces, count);
    if (choice < 0 || choice >= count)
    {
        printf("[C-Shark] Invalid interface selection. Exiting...\n");
        return 1;
    }

    printf("You selected interface: %s\n", interfaces[choice].name);

    // Phase 1 Main Menu loop
    int running = 1;
    while (running)

    {

        printf("\n[C-Shark] Interface '%s' selected. What's next?\n", interfaces[choice].name);
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Inspect Last Session\n");
        printf("4. Exit C-Shark\n");
        printf("Enter choice: ");

        int menu_choice;
        int feedback_menu_choice = scanf("%d", &menu_choice) ;


        if (feedback_menu_choice == -1)
        {
            printf("\n[C-Shark]  Ctrl+D detected. Exiting...\n");
            break;
        }
        else if (feedback_menu_choice != 1)
        {
            printf("\n[C-Shark] Invalid input . Exiting...\n");
            break;
        }

        switch (menu_choice)
        {
        case 1:
            printf("[C-Shark] Starting packet capture on %s...\n", interfaces[choice].name);
            start_sniffing(interfaces[choice].name);
            break;

        case 2:
        {

            printf("[C-Shark] Choose a filter:\n");
            printf("1. HTTP\n");
            printf("2. HTTPS\n");
            printf("3. DNS\n");
            printf("4. ARP\n");
            printf("5. TCP\n");
            printf("6. UDP\n");
            printf("Enter choice: ");
            int fchoice;
            int feedback_fchoice = scanf("%d", &fchoice);
            if (feedback_fchoice == -1)
            {
                printf("\n[C-Shark]  Ctrl+D detected. Exiting...\n");
                exit(0);
            }
            else if ( feedback_fchoice != 1)
            {
                printf("\n[C-Shark] Invalid input. Exiting...\n");
                exit(0);
            }

            const char *filter = NULL;
            switch (fchoice)
            {
            case 1:
                filter = "tcp port 80";
                break;
            case 2:
                filter = "tcp port 443";
                break;
            case 3:
                filter = "udp port 53";
                break;
            case 4:
                filter = "arp";
                break;
            case 5:
                filter = "tcp";
                break;
            case 6:
                filter = "udp";
                break;
            default:
                printf("[C-Shark] Invalid filter choice.\n");
                continue;
            }

            printf("[C-Shark] Starting filtered sniff on %s...\n", interfaces[choice].name);
            start_sniffing_filtered(interfaces[choice].name, filter);
            break;
        }

        case 3:
            inspect_last_session();
            break;

        case 4:
            printf("[C-Shark] Exiting...\n");
            running = 0;
            break;
        default:
            printf("[C-Shark] Invalid choice , try again.\n");
        }
    }

    return 0;
}
