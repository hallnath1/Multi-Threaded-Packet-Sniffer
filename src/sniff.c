#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "dispatch.h"
#include "analysis.h"

pcap_t *pcap_handle;
int verbose;

//FOR THREADS
pthread_t threads[4];
counters *threadOut[4];
linkedlist* packet_queue;
pthread_mutex_t queuelock = PTHREAD_MUTEX_INITIALIZER;
int FLAG_RUN = 1;
unsigned long pcount = 0;

// Application main sniffing loop
void sniff(char *interface, int v) {

	verbose = v;	

	//CREATE QUEUE
	initQueue();
	//CREATE THREADS
	createThreads();

	
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
                dispatch(packet, pcount);
		pcount++;
		free((void*)pack);
	}

    	return;
}

void *thread_code(void* arg) {
	struct thread_args * args = (struct thread_args *) arg;
	threadOut[args->threadnum]->xmas_tree_counter = 0;
	threadOut[args->threadnum]->arp_poisioning_counter = 0;
	threadOut[args->threadnum]->blacklisted_requests_counter = 0;
	while(FLAG_RUN){
		
		if (packet_queue->head != NULL){
			pthread_mutex_lock(&queuelock);
			
			struct element * elem = packet_queue->head;
			packet_queue->head = elem->next;
			
			pthread_mutex_unlock(&queuelock);
			
			counters *return_counters = analyse(elem->packet, elem->pcount);
			
			threadOut[args->threadnum]->xmas_tree_counter += return_counters->xmas_tree_counter;
			threadOut[args->threadnum]->arp_poisioning_counter += return_counters->arp_poisioning_counter;
			threadOut[args->threadnum]->blacklisted_requests_counter += return_counters->blacklisted_requests_counter;
			
			free(elem);
			free(return_counters);
		}
	}
	free(args);
	return NULL;
}

void sig_handler(int signo){
        if (signo == SIGINT){
                pcap_close(pcap_handle);
		FLAG_RUN = 0;
		cleanThreads();
		destroyQueue();
		
		int i;
		for (i = 1; i < 4; i++) {
			threadOut[0]->arp_poisioning_counter += threadOut[i]->arp_poisioning_counter;
			threadOut[0]->xmas_tree_counter += threadOut[i]->xmas_tree_counter; 
			threadOut[0]->blacklisted_requests_counter += threadOut[i]->blacklisted_requests_counter;
			free(threadOut[i]);
		}
		
		printf("\n\n===Packet Sniffing Report===\n");
                printf("ARP Poision Atacks = %ld\n", threadOut[0]->arp_poisioning_counter);
                printf("Xmas Tree Atacks = %ld\n", threadOut[0]->xmas_tree_counter);
                printf("Blacklisted Requests = %ld\n\n", threadOut[0]->blacklisted_requests_counter);
                printf("\n\n");
		free(threadOut[0]);
                exit(0);
        }
}

void createThreads(){
	int i;
	for (i = 0; i < 4; i++) {
		threadOut[i] = malloc(sizeof(counters));
		struct thread_args *args = malloc(sizeof(struct thread_args));
		args->threadnum = i;
		pthread_create(&threads[i], NULL, &thread_code,(void *) args);
	}
}

void cleanThreads(){
	pthread_mutex_destroy(&queuelock);
	
	//JOIN THREADS
	int i;
	for (i = 0; i < 4; ++i) {
		pthread_join(threads[i], NULL);
	}
}

void initQueue(){
	packet_queue = malloc(sizeof(linkedlist));
	packet_queue->head = NULL;
}

void destroyQueue(){
	while(packet_queue->head){
		struct element * elem = packet_queue->head;
		if (elem) {
			packet_queue->head = elem->next;
			free(elem);
		}
		else{
			break;
		}
	}
	free(packet_queue);
}