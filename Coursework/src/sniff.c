/**
*	@file 	sniff.c
*	@brief 	This file contains all the functions that deal with incoming packets and
* 	the ^C manager
*	
*	@author	Nathan Hall
*	
*	@date	21/11/2018
*/

#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>

#include "dispatch.h"


pcap_t *pcap_handle;
int verbose;		//Gloabal Variable to track verbose mode

/**
*	This method will set-up packet sniffing and initilaise a pcap_loop 
*	
*	@param		interface	Contains the interface which the user wishes to sniff on
*			verbose		Contains the verbose mode flag
*/
void sniff(char *interface, int v) {

	//Initialise the global verbose variable
	verbose = v;

	//Call signal function to setup sig_handler(), whenever ^C is pressed after this line sig_handler() is executed
	if (signal(SIGINT, sig_handler) == SIG_ERR){
        	printf("\nCan't catch SIGINT\n");
		exit(0);
	}
	
	// Open network interface for packet capture
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);

	

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

/**
*	This method will run for every incoming packet, it passes it to dispatch and assigns it a
*	packet number 
*	
*	@param		interface	Contains the interface which the user wishes to sniff on
*			verbose		Contains the verbose mode flag
*/
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
	//Every packet assigned a number
	static unsigned long pcount = 0;

	 // Dispatch packet for processing
	dispatch(header, packet, pcount);

	pcount++;
}

/**
*	This method will run when ^C signal is detected and will close the program and clean up memeory
*	
*	@param		signo		Contains the value of the signal detected
*/
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
