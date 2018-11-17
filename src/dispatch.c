#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "analysis.h"


void dispatch(const struct pcap_pkthdr *header, const unsigned char *pack, unsigned long pcount) {
	
	unsigned char *packet = malloc((sizeof(char)*header->len) + 1);
        memcpy(packet, pack, header->len);
	packet[sizeof(char)*header->len] = '\0';
	
	element* new_packet = malloc(sizeof(element));
	
	if (new_packet==NULL) 
		exit (1);

	
	new_packet->pcount = pcount;
	new_packet->packet = packet;
	new_packet->next = NULL;
	if (packet_queue->head == NULL){
		packet_queue->head = new_packet;
	}
	else{	
		struct element *tail = packet_queue->head;
		while(tail->next != NULL)
			tail = tail->next;
		tail->next = new_packet;
	}
}





//move queue and thread creation to sniff (own file?)
//seperate counters for threads
//variable thread size
//mutex locks
//make verbose global
//
