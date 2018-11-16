#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sniff.h"

extern pcap_t * pcap_handle;

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose);

void etherOut(struct ether_header *eth_header);

void ipOut(struct iphdr *ip_header);

void tcpOut(struct tcphdr *tcp_header);

void arpOut(struct ether_arp *arp_packet, struct arphdr *arp_header);

#endif
