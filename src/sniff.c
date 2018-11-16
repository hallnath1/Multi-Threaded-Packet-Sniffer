#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <signal.h>

#include "dispatch.h"

pcap_t *pcap_handle;
int verbose;
unsigned long arp_poisioning_counter = 0;
unsigned long xmas_tree_counter = 0;
unsigned long blacklisted_requests_counter = 0;


// Application main sniffing loop
void sniff(char *interface, int v) {

	verbose = v;	
	
	if (signal(SIGINT, sig_handler) == SIG_ERR)
        	printf("\nCan't catch SIGINT\n");

	// Open network interface for packet capture
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  	if (pcap_handle == NULL) {
    		fprintf(stderr, "Unable to open interface %s\n", errbuf);
    		exit(EXIT_FAILURE);
  	} 
	else {
    		printf("SUCCESS! Opened %s for capture\n", interface);
  	}
	pcap_loop(pcap_handle, 0, packet_handler, NULL);
}

void packet_handler(
    unsigned char *args,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
)
{
	if (packet == NULL) {
        	// pcap_next can return null if no packet is seen within a timeout
                if (verbose) {
                	printf("No packet received. %s\n", pcap_geterr(pcap_handle));
                }
       	}
       	else {
       		unsigned char *pack = malloc(sizeof(char)*header->len + 1);
                memcpy(pack, packet, header->len);
		pack[sizeof(char)*header->len] = '\0';
                
		// Dispatch packet for processing
                dispatch(header, pack, verbose);
		
		free((void*)pack);
	}

    	return;
}

void sig_handler(int signo){
        if (signo == SIGINT){
                printf("\n\n===Packet Sniffing Report===\n");
                printf("ARP Poision Atacks = %ld\n", arp_poisioning_counter);
                printf("Xmas Tree Atacks = %ld\n", xmas_tree_counter);
                printf("Blacklisted Requests = %ld\n", blacklisted_requests_counter);
                printf("\n\n");

                pcap_close(pcap_handle);
                exit(0);
        }
}

