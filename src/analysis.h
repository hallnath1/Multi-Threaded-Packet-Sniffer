#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
<<<<<<< HEAD
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose);

void etherOut(struct ether_header *eth_header);

void ipOut(struct iphdr *ip_header);

void tcpOut(struct tcphdr *tcp_header);

void arpOut(struct ether_arp *arp_packet, struct arphdr *arp_header);
=======

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);
>>>>>>> d7f4ad92172e6c3ad8064dce7fdb532bf474e5f3

#endif
