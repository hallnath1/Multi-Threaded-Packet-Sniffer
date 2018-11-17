#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

#include "sniff.h"

extern linkedlist* packet_queue;
extern int verbose;

void dispatch(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned long pcount);

#endif