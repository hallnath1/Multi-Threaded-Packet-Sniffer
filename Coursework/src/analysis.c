/**
*	@file 	analysis.c
*	@brief 	This file contains all the functions required for analysing the 
*	packets and dumping the headers, it also defines the external variables required
*	
*	@author	Nathan Hall
*	
*	@date	21/11/2018
*/

#include "analysis.h"

#include <stdlib.h>
#include <string.h>

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
counters* analyse(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned long pcount) {
	
	//Tracks the type of attack in the counters struct
	counters *packet_counter = malloc(sizeof(counters));
	packet_counter->arp_poisioning_counter = 0;
	packet_counter->xmas_tree_counter = 0;
	packet_counter->blacklisted_requests_counter = 0;
	
	if (verbose == 1)
		printf("\n\n === PACKET %ld HEADER ===\n", pcount);
	
	struct ether_header *eth_header = (struct ether_header *) packet;

	if (verbose == 1)
		etherOut(eth_header);
	
	//If the packet has an IP header
	if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){
		
		const unsigned char *eth_strip_packet = packet + ETH_HLEN;
                struct iphdr *ip_header = (struct iphdr *) eth_strip_packet;
		
		if (verbose == 1)
			ipOut(ip_header);
		
		//If the packet uses the TCP protocol
		if (ip_header->protocol == 6){
			const unsigned char *ip_strip_packet = eth_strip_packet + 4*ip_header->ihl;
                        struct tcphdr *tcp_header = (struct tcphdr *) ip_strip_packet;
			
			if (verbose == 1)
				tcpOut(tcp_header);
			
			//Test for Xmas Tree Packets (FIN, URG and PUSH set)
			if (tcp_header->fin && tcp_header->urg && tcp_header->psh)
				packet_counter->xmas_tree_counter++;
			
			//Test for request to blacklisted site
			const char *http_packet = (char *) (ip_strip_packet + 4*tcp_header->doff);
			if (strstr(http_packet, "Host: www.bbc.co.uk") && (ntohs(tcp_header->dest) == 80) ) 
				packet_counter->blacklisted_requests_counter++;
		}
	}
	//Else if the packet has an ARP header
	else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
		const unsigned char *eth_strip_packet = packet + ETH_HLEN;
        	struct ether_arp *arp_packet = (struct ether_arp *) eth_strip_packet;
 		struct arphdr *arp_header = (struct arphdr *) &arp_packet->ea_hdr;

		if (verbose == 1)
			arpOut(arp_packet, arp_header);
		
		//Test for Cache Poisioning (ARP Attack)
		if (ntohs(arp_header->ar_op) == ARPOP_REPLY)
			packet_counter->arp_poisioning_counter++;			
	}
	
	//Return the packet attack type counter
	return packet_counter;
}

/**
*	This method dumps the ethernet header data
*
*	@param		eth_header	Contains ethernet header data
*/
void etherOut(struct ether_header *eth_header) {
	unsigned int i;

        printf("---Ethernet Header---");

	printf("\nSource MAC: ");
  	for (i = 0; i < 6; ++i) {
  	  	printf("%02x", eth_header->ether_shost[i]);
    		if (i < 5) {
      			printf(":");
    		}
  	}

  	printf("\nDestination MAC: ");
  	for (i = 0; i < 6; ++i) {
    		printf("%02x", eth_header->ether_dhost[i]);
    		if (i < 5) {
      			printf(":");
    		}
  	}

	printf("\nType: %d\n", ntohs(eth_header->ether_type));
}

/**
*	This method dumps the ip header data
*
*	@param		ip_header	Contains ip header data
*/
void ipOut(struct iphdr *ip_header){
	unsigned int i;

	printf("---IP Header---");

	printf("\nVersion: %d ", ip_header->version);

	switch(ip_header->version){
		case 4:
			printf("(IP, Internet Protocol)");
			break;
		case 5:
			printf("(ST, ST Datagram Mode)");
			break;
		case 6:
			printf("(IPv6, Internet Protocol)");
			break;
		case 7:
			printf("(TP/IX, The Next Internet)");
			break;
		case 9:
			printf("(TUBA)");
			break;
		case 0:
		case 15:
			printf("(Reserved)");
			break;
		default:
			printf("Unknown");
	}

	printf("\nInternet Header Length: %d", ip_header->ihl);

	printf("\nTOS: %d", ip_header->tos);			//EXPAND ME

	printf("\nTotal length: %d", ip_header->tot_len);

	printf("\nIdentification: %d", ip_header->id);

	printf("\nFlags:");					//EXPAND ME

	printf("%d", (ip_header->frag_off >> 2) & 1);

	printf("\nTime To Live: %hu", ip_header->ttl);

	printf("\nProtocol: %hu", ip_header->protocol);		//EXPAND ME

	printf("\nChecksum: %d", ip_header->check); 		//EXPAND ME

	printf("\nSource IP: ");

	for (i = 0; i < 32; i = i + 8) {
          	printf("%d", (ip_header->saddr >> i) & 0xFF);
     		if (i < 24) {
                       	printf(".");
                }
        }

	printf("\nDestination IP: ");
	for (i  = 0; i < 32; i = i + 8) {
       	 	printf("%d", (ip_header->daddr >> i) & 0xFF);
       		if (i < 24) {
                	printf(".");
        	}
        }
}

/**
*	This method dumps the tcp header data
*
*	@param		tcp_header	Contains tcp header data
*/
void tcpOut(struct tcphdr *tcp_header){

	printf("\n---TCP Header---");

	printf("\nSource Port: %d", tcp_header->source);

	printf("\nDestination Port: %d", tcp_header->dest);

	printf("\nSequence Number: %u", tcp_header->seq);

	printf("\nAcknowledgement Sequence Number: %u", tcp_header->ack_seq);

	printf("\nData Offset: %hu", tcp_header->doff);

	printf("\nReserved: %d", tcp_header->res1 + tcp_header->res2);

	printf("\nFlags: ");

	if (tcp_header->urg)					//NO FLAGS?
		printf("URG ");
	if (tcp_header->ack)
		printf("ACK ");
	if (tcp_header->psh)
		printf("PSH ");
	if (tcp_header->rst)
		printf("RST ");
	if (tcp_header->syn)
		printf("SYN ");
	if (tcp_header->fin)
		printf("FIN ");

	printf("\nWindow: %d", tcp_header->window);

	printf("\nChecksum: %d", tcp_header->check);		//EXPAND ME

	printf("\nUrgent Pointer: %d", tcp_header->urg_ptr);	//EXPAND ME?
}

/**
*	This method dumps the arp header data
*
*	@param		arp_header	Contains arp header data
*/
void arpOut(struct ether_arp *arp_packet, struct arphdr *arp_header){
	unsigned int i;

        printf("\n---ARP Header---");

	printf("\nARP Opcode: %d", ntohs(arp_header->ar_op));

	printf("\nSender MAC Address ");
	for (i = 0; i < 6; ++i) {
               	printf("%02x", arp_packet->arp_sha[i]);
             	  	if (i < 5) {
                       	printf(":");
               	}
	}

	printf("\nTarget MAC Address ");
        for (i = 0; i < 6; ++i) {
        	printf("%02x", arp_packet->arp_tha[i]);
        	if (i < 5) {
                       	printf(":");
                }
	}

	printf("\nSender IP Address: ");
        for (i = 0; i < 4; i++) {
        	printf("%d", arp_packet->arp_spa[i]);
                if (i < 3) {
                	printf(".");
                }
        }

	printf("\nTarget IP Address: ");
        for (i = 0; i < 4; i++) {
        	printf("%d", arp_packet->arp_tpa[i]);
                if (i < 3) {
                        printf(".");
                }
        }
}
