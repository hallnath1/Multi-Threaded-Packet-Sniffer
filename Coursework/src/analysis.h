/**
*	@file 	analysis.h
*	@brief 	This header file defines all the functions required when analysing the 
*	packets and dumping the headers, it also defines the external variables required
*	
*	@author	Nathan Hall
*	
*	@date	21/11/2018
*/

#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "dispatch.h"

extern int verbose;

/**
*	This method will analyse a given packet, returning a struct that warns of any 
*	suspected attacks, when the global variable verbose is set the function will 
*	dump all packet header data
*	
*	@param		header		Contains header data about the packet
*			packet		Contains packet data about the packet
*			pcount		Contains the packet number (order revieved)
*
*	@return	 	counters* 	A pointer to a struct of values that contain the type of attack
*/
counters *analyse(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned long pcount);


/**
*	This method dumps the ethernet header data
*
*	@param		eth_header	Contains ethernet header data
*/
void etherOut(struct ether_header *eth_header);

/**
*	This method dumps the ip header data
*
*	@param		ip_header	Contains ip header data
*/
void ipOut(struct iphdr *ip_header);

/**
*	This method dumps the tcp header data
*
*	@param		tcp_header	Contains tcp header data
*/
void tcpOut(struct tcphdr *tcp_header);

/**
*	This method dumps the arp header data
*
*	@param		arp_header	Contains arp header data
*/
void arpOut(struct ether_arp *arp_packet, struct arphdr *arp_header);

#endif
