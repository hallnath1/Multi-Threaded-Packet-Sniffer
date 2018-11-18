#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

#include "sniff.h"

extern int verbose;
extern int FLAG_RUN;

void dispatch(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned long pcount);
void *thread_code();

void createThreads();
void cleanThreads();

void initQueue();
void destroyQueue();

void reportOut();

typedef struct counters{
	unsigned long arp_poisioning_counter;
	unsigned long xmas_tree_counter;
	unsigned long blacklisted_requests_counter;
} counters;


typedef struct element{
	const unsigned char *packet;
	unsigned long pcount;
        struct element* next;
} element;

typedef struct linkedlist{
	element *head;
} linkedlist;

#endif