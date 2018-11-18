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
pthread_t threads[2];
counters *threadOut[2];
linkedlist* packet_queue;
pthread_mutex_t queuelock = PTHREAD_MUTEX_INITIALIZER;
int FLAG_RUN = 1;
int THREADS_FLAG = 0;
unsigned long pcount = 0;

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
	if (packet == NULL) {
        	// pcap_next can return null if no packet is seen within a timeout
                if (verbose) {
                	printf("No packet received. %s\n", pcap_geterr(pcap_handle));
                }
       	}
       	else {
       		
                
		// Dispatch packet for processing
                pthread_mutex_lock(&queuelock);
		dispatch(header, packet, pcount);
		pthread_mutex_unlock(&queuelock);
		
		pcount++;
	}

    	return;
}

void *thread_code(void* arg) {
	struct thread_args * args = (struct thread_args *) arg;
	threadOut[args->threadnum]->xmas_tree_counter = 0;
	threadOut[args->threadnum]->arp_poisioning_counter = 0;
	threadOut[args->threadnum]->blacklisted_requests_counter = 0;
	while(FLAG_RUN){
		pthread_mutex_lock(&queuelock);
		if (packet_queue->head){
			
			
			struct element * elem = packet_queue->head;
			packet_queue->head = elem->next;
			pthread_mutex_unlock(&queuelock);
			
			counters *return_counters = analyse(elem->packet, elem->pcount);
			
			
			
			threadOut[args->threadnum]->xmas_tree_counter += return_counters->xmas_tree_counter;
			threadOut[args->threadnum]->arp_poisioning_counter += return_counters->arp_poisioning_counter;
			threadOut[args->threadnum]->blacklisted_requests_counter += return_counters->blacklisted_requests_counter;
			
			free((void *)elem->packet);
			free(elem);
			
			free(return_counters);
		}
		else{
			pthread_mutex_unlock(&queuelock);
		}
	}
	free(args);
	return NULL;
}

void sig_handler(int signo){
        if (signo == SIGINT){
		FLAG_RUN = 0;
		if(THREADS_FLAG)
			cleanThreads();
		if (pcap_handle)
			pcap_close(pcap_handle);
		destroyQueue();
		pthread_mutex_destroy(&queuelock);
		
		int i;
		for (i = 1; i < 2; i++) {
			threadOut[0]->arp_poisioning_counter += threadOut[i]->arp_poisioning_counter;
			threadOut[0]->xmas_tree_counter += threadOut[i]->xmas_tree_counter; 
			threadOut[0]->blacklisted_requests_counter += threadOut[i]->blacklisted_requests_counter;
			free(threadOut[i]);
		}
		
		printf("\n\n===Packet Sniffing Report===\n");
                printf("ARP Poision Atacks = %ld\n", threadOut[0]->arp_poisioning_counter);
                printf("Xmas Tree Atacks = %ld\n", threadOut[0]->xmas_tree_counter);
                printf("Blacklisted Requests = %ld\n", threadOut[0]->blacklisted_requests_counter);
                printf("\n\n");
		free(threadOut[0]);
                exit(0);
        }
}

void createThreads(){
	int i;
	THREADS_FLAG = 1;
	for (i = 0; i < 2; i++) {
		threadOut[i] = malloc(sizeof(counters));
		struct thread_args *args = malloc(sizeof(struct thread_args));
		args->threadnum = i;
		pthread_create(&threads[i], NULL, &thread_code,(void *) args);
	}
}

void cleanThreads(){
	
	//JOIN THREADS
	int i;
	for (i = 0; i < 2; ++i) {
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
			free((void *)elem->packet);
			free(elem);
		}
		else{
			break;
		}
	}
	free(packet_queue);
}