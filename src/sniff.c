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

	//Initialise the global verbose variable
	verbose = v;
	
	// Open network interface for packet capture
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
	
	//Call signal function to setup sig_handler(), whenever ^C is pressed after this line sig_handler() is executed
	if (signal(SIGINT, sig_handler) == SIG_ERR){
        	printf("\nCan't catch SIGINT\n");
		exit(0);
	}
	
	//Check network interface has been opened
  	if (pcap_handle == NULL) {
    		fprintf(stderr, "Unable to open interface %s\n", errbuf);
    		exit(EXIT_FAILURE);
  	} 
	else {
    		printf("SUCCESS! Opened %s for capture\n", interface);
  	}
  	
  	//Initialise Queue
	initQueue();
	
	//Setup threads
	createThreads();

	//Begin packet capture loop
	pcap_loop(pcap_handle, 0, packet_handler, NULL);
}

//Handles every new packet recieved
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
	//Every packet assigned a number
	static unsigned long pcount = 0;
	
	 // Dispatch packet for processing
	dispatch(header, packet, pcount);
	
	pcount++;
}

//Once ^C is detected, clean up heap and output the result
void sig_handler(int signo){
        if (signo == SIGINT){
		//Cleans the thread and outputs the packet sniffing result
		cleanThreads();
		
		//If in verbose output a closing report
		if(verbose)
			printf(" === Closing Report ===");
		
		//If pcap_handle has been declared (pcap is running), close pcap
		if (pcap_handle)
			pcap_close(pcap_handle);
		
		//Finaly destroy queue and all packets in it
		destroyQueue();
		
		//Close proccess
                exit(0);
        }
}






