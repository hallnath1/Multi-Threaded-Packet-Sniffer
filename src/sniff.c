#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>

#include "dispatch.h"


pcap_t *pcap_handle;
int verbose;

// Application main sniffing loop
void sniff(char *interface, int v) {

	verbose = v;
	
	
	
	// Open network interface for packet capture
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
	if (signal(SIGINT, sig_handler) == SIG_ERR)
        	printf("\nCan't catch SIGINT\n");
  	if (pcap_handle == NULL) {
    		fprintf(stderr, "Unable to open interface %s\n", errbuf);
    		exit(EXIT_FAILURE);
  	} 
	else {
    		printf("SUCCESS! Opened %s for capture\n", interface);
  	}
  	
  	//CREATE QUEUE
	initQueue();
	//CREATE THREADS
	createThreads();

	pcap_loop(pcap_handle, 0, packet_handler, NULL);
}

void packet_handler(
    unsigned char *args,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
)
{
	static unsigned long pcount = 0;
	if (packet == NULL) {
        	// pcap_next can return null if no packet is seen within a timeout
                if (verbose) {
                	printf("No packet received. %s\n", pcap_geterr(pcap_handle));
                }
       	}
       	else {
       		
                
		// Dispatch packet for processing
		dispatch(header, packet, pcount);
		
		pcount++;
	}

    	return;
}

void sig_handler(int signo){
        if (signo == SIGINT){
		cleanThreads();
		
		if (pcap_handle)
			pcap_close(pcap_handle);
		
		destroyQueue();
		
                exit(0);
        }
}






