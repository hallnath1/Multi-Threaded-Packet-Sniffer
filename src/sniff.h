#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <pcap.h>

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void sig_handler(int signo);

typedef struct element{
	const unsigned char *packet;
	unsigned long pcount;
        struct element* next;
} element;

typedef struct linkedlist{
	element *head;
} linkedlist;

typedef struct counters{
	unsigned long arp_poisioning_counter;
	unsigned long xmas_tree_counter;
	unsigned long blacklisted_requests_counter;
} counters;

struct thread_args {
  unsigned int threadnum;
};

void initQueue();
void destroyQueue();

void createThreads();
void cleanThreads();
void *thread_code(void* args);



#endif
