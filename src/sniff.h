#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <pcap.h>

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif
