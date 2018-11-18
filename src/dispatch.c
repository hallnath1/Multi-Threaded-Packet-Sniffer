#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "analysis.h"

pthread_t threads[2];
//counters *threadOut[2];
int THREADS_FLAG = 0;
pthread_mutex_t queuelock = PTHREAD_MUTEX_INITIALIZER;
linkedlist* packet_queue;
int FLAG_RUN = 1;


void dispatch(const struct pcap_pkthdr *header, const unsigned char *pack, unsigned long pcount) {
	
	//Copy the packet into heap memory to avoid it being overwritten when space is required in the buffer
	unsigned char *packet = malloc((sizeof(char)*header->len) + 1);
        memcpy(packet, pack, header->len);
	packet[sizeof(char)*header->len] = '\0';
	
	element* new_packet = malloc(sizeof(element));
	
	if (new_packet==NULL) 
		exit (1);

	
	new_packet->pcount = pcount;
	new_packet->packet = packet;
	new_packet->next = NULL;
               
	pthread_mutex_lock(&queuelock);
	
	if (packet_queue->head == NULL){
		packet_queue->head = new_packet;
	}
	else{	
		struct element *tail = packet_queue->head;
		while(tail->next != NULL)
			tail = tail->next;
		tail->next = new_packet;
	}
	
	
        pthread_mutex_unlock(&queuelock);
}


void *thread_code() {
	counters *thread_count = malloc(sizeof(counters));
	thread_count->arp_poisioning_counter = 0;
	thread_count->xmas_tree_counter = 0;
	thread_count->blacklisted_requests_counter = 0;
	
	while(FLAG_RUN){
		pthread_mutex_lock(&queuelock);
		if (packet_queue->head){
			
			
			struct element * elem = packet_queue->head;
			packet_queue->head = elem->next;
			pthread_mutex_unlock(&queuelock);
			
			counters *return_counters = analyse(elem->packet, elem->pcount);
			
			
			
			thread_count->xmas_tree_counter += return_counters->xmas_tree_counter;
			thread_count->arp_poisioning_counter += return_counters->arp_poisioning_counter;
			thread_count->blacklisted_requests_counter += return_counters->blacklisted_requests_counter;
			
			free((void *)elem->packet);
			free(elem);
			
			free(return_counters);
		}
		else{
			pthread_mutex_unlock(&queuelock);
		}
	}
	
	return (void *)thread_count;
}

void createThreads(){
	int i;
	THREADS_FLAG = 1;
	for (i = 0; i < 2; i++) {
		pthread_create(&threads[i], NULL, &thread_code, NULL);
	}
}

void cleanThreads(){
	FLAG_RUN = 0;
	if(THREADS_FLAG){
		//JOIN THREADS
		counters* total_count = malloc(sizeof(counters));
		total_count->xmas_tree_counter = 0;
		total_count->arp_poisioning_counter = 0;
		total_count->blacklisted_requests_counter = 0;
		
		int i;
		for (i = 0; i < 2; ++i) {
			void* ptr;	
			pthread_join(threads[i], &ptr);
			
			counters* thread_count = (counters *)ptr;
			
			total_count->arp_poisioning_counter += thread_count->arp_poisioning_counter;
			total_count->xmas_tree_counter += thread_count->xmas_tree_counter;
			total_count->blacklisted_requests_counter += thread_count->blacklisted_requests_counter;
			
			free(ptr);
		}
		
		
		printf("\n\n===Packet Sniffing Report===\n");
		printf("ARP Poision Atacks = %ld\n", total_count->arp_poisioning_counter);
		printf("Xmas Tree Atacks = %ld\n", total_count->xmas_tree_counter);
		printf("Blacklisted Requests = %ld\n\n\n", total_count->blacklisted_requests_counter);
		
		free(total_count);
	}
}

void initQueue(){
	packet_queue = malloc(sizeof(linkedlist));
	packet_queue->head = NULL;
}

void destroyQueue(){
	if(packet_queue){
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
	//if(THREADS_FLAG)
		pthread_mutex_destroy(&queuelock);
}


//move queue and thread creation to sniff (own file?)
//seperate counters for threads
//variable thread size
//mutex locks
//make verbose global
//