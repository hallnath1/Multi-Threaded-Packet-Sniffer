#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>

#include "analysis.h"


void dispatch(const unsigned char *packet, unsigned long pcount) {
	
	element* new_packet = malloc(sizeof(element));
	
	//CHECK MALLOC WORKED
	
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
