#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <string.h>

#include "dispatch.h"

pcap_t *pcap_handle;
int verbose;

// Application main sniffing loop
void sniff(char *interface, int v) {

	verbose = v;	

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
	}
	
    	return;
}
