/**
*	@file 	dispatch.h
*	@brief 	This header file defines all the functions that deal with the dispatch and 
* 	distribution of packets, and the creation/termination of threads and the packet queue
*	
*	@author	Nathan Hall
*	
*	@date	21/11/2018
*/

#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

#include "sniff.h"

extern int verbose;

typedef struct counters{
	unsigned long arp_poisioning_counter;
	unsigned long xmas_tree_counter;
	unsigned long blacklisted_requests_counter;
} counters;


typedef struct element{
	const unsigned char *packet;
	unsigned long pcount;
	const struct pcap_pkthdr *header;
        struct element* next;
} element;

typedef struct linkedlist{
	element *head;
} linkedlist;

/**
*	This method will add a new packet to the packet queue, within its own packet element
*	
*	@param		header		Contains header data about the packet
*			packet		Contains packet data about the packet
*			pcount		Contains the packet number (order revieved)
*/
void dispatch(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned long pcount);

/**
*	This method is run by all threads, it analyses the packets in the queue and tracks the 
* 	different attacks in local counters 
*/
void *thread_code();

/**
*	This method checks the FLAG_RUN variable, ensuring mutex locks
*	
*	@return	 	int 	Returns 1 if the FLAG_RUN is set to 1 and 0 in opposite situation
*/
int threadRunCheck();

/**
*	This method initialises threads, assigning the function thread_code() to each one. It also
* 	initialises the mutexes
*/
void createThreads();

/**
*	This method sets FLAG_RUN to 0 and then cleans up the threads. It sums together the local
* 	counters then calls outReport()
*/
void cleanThreads();

/**
*	This method initialises the queue
*/
void initQueue();

/**
*	This method destroys the queue and frees the heap memory allocated to it. It will track the
* 	number of packets still in the queue and output the number in verbose mode. Finally, the mutexes
* 	are destroyed
*/
void destroyQueue();

/**
*	Output the final report on the packet sniffing
* 
* 	@param		total_count	Contains the final counter for each attack/request
*/
void outReport(counters* total_count);

#endif
