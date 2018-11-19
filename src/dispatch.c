#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "analysis.h"

pthread_t threads[2];
int THREADS_FLAG = 0;
pthread_mutex_t queuelock = PTHREAD_MUTEX_INITIALIZER;
linkedlist* packet_queue;
int FLAG_RUN = 1;


void dispatch(const struct pcap_pkthdr *header, const unsigned char *pack, unsigned long pcount) {
	
	//Copy the packet into heap memory to avoid it being overwritten when space is required in the buffer
	unsigned char *packet = malloc((sizeof(char)*header->len) + 1);
	if (packet==NULL) 
		exit (1);
        memcpy(packet, pack, header->len);
	packet[sizeof(char)*header->len] = '\0';
	
	
	//Initialise packet with element struct containign packet data, packet header data and pcount
	element* new_packet = malloc(sizeof(element));
	if (new_packet==NULL) 
		exit (1);

	new_packet->pcount = pcount;
	new_packet->header = header;
	new_packet->packet = packet;
	new_packet->next = NULL;
        
	//While adding new packet element, lock the queue
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
	
	//Unlock once finished
        pthread_mutex_unlock(&queuelock);
}

//Code ran by each thread
void *thread_code() {
	//Inititalise thread local counters struct in heap memory
	counters *thread_count = malloc(sizeof(counters));
	if (thread_count==NULL) 
		exit (1);
	
	thread_count->arp_poisioning_counter = 0;
	thread_count->xmas_tree_counter = 0;
	thread_count->blacklisted_requests_counter = 0;
	
	//While run flag is set
	while(FLAG_RUN){
		//Lock the queue when dealling with queue
		pthread_mutex_lock(&queuelock);
		if (packet_queue->head){
			
			//Get packet from head and set head to the next packet
			struct element * elem = packet_queue->head;
			packet_queue->head = elem->next;
			
			//Unlock once finished with the queue
			pthread_mutex_unlock(&queuelock);
			
			//Call analyse to sniff the packet, returning a counters struct
			counters *return_counters = analyse(elem->header, elem->packet, elem->pcount);
			
			//Add the returned counters to the threads counter
			thread_count->xmas_tree_counter += return_counters->xmas_tree_counter;
			thread_count->arp_poisioning_counter += return_counters->arp_poisioning_counter;
			thread_count->blacklisted_requests_counter += return_counters->blacklisted_requests_counter;
			
			//Free the element, the packet data within and the returned counters struct
			free((void *)elem->packet);
			free(elem);
			free(return_counters);
		}
		else{
			//Unlock if packet_queue->head is NULL
			pthread_mutex_unlock(&queuelock);
		}
	}
	
	//When the thread is closed return its counters struct
	return (void *)thread_count;
}

//Set-up the threads and assign the function thread_code() to each one
void createThreads(){
	//Indicates the threads have been set-up 
	THREADS_FLAG = 1;
	
	int i;
	for (i = 0; i < 2; i++) {
		pthread_create(&threads[i], NULL, &thread_code, NULL);
	}
}

//Clean up the threads and output the number of attacks or blacklisted requests detected
void cleanThreads(){
	//Set run flag to 0, stopping the thread_code() loop (threads close)
	FLAG_RUN = 0;
	
	//If threads exist
	if(THREADS_FLAG){
		
		//Create counters struct for total atttack and request count
		counters* total_count = malloc(sizeof(counters));
		if (total_count==NULL) 
			exit (1);
		total_count->xmas_tree_counter = 0;
		total_count->arp_poisioning_counter = 0;
		total_count->blacklisted_requests_counter = 0;
		
		//For every thread retrieve the thread_count and add it to the total_count
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
		
		//Output the final count for ARP Poision Attacks, Xmas Tree Attacks and Blacklisted Requests
		printf("\n\n === Packet Sniffing Report === \n");
		printf("ARP Poision Attacks = %ld\n", total_count->arp_poisioning_counter);
		printf("Xmas Tree Attacks = %ld\n", total_count->xmas_tree_counter);
		printf("Blacklisted Requests = %ld\n\n\n", total_count->blacklisted_requests_counter);
		
		//Free the total_count counters struct
		free(total_count);
	}
}

//Initialise the queue
void initQueue(){
	packet_queue = malloc(sizeof(linkedlist));
	if (packet_queue==NULL) 
		exit (1);
	packet_queue->head = NULL;
}

//Free the heap memory of the queue and its constituting packet elements
void destroyQueue(){
	//Track the number of unproccessed packets still in the queue
	int unproccessed_count = 0;
	
	//While the packet_queue has a head that is not null
	while(packet_queue->head){
		//Get the next element
		struct element * elem = packet_queue->head;
		//If the element is not null
		if (elem) {
			unproccessed_count++;
			//Set the next head
			packet_queue->head = elem->next;	
			//Free the packet and the element data structure
			free((void *)elem->packet);
			free(elem);
		}
		else{
			break;
		}
	}
	//Free the queue
	free(packet_queue);

	//If verbose set, print out the no. of unproccessed packets
	if(verbose)
		printf("\n%d Packets Unprocessed\n\n", unproccessed_count);

	//Destroy the queuelock mutex
	pthread_mutex_destroy(&queuelock);
}