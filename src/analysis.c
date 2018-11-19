#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

//Expand packet data into headers and detect specific attacks or requests
counters* analyse(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned long pcount) {
	
	//Initialise the counters struct
	counters *packet_counter = malloc(sizeof(counters));
	packet_counter->arp_poisioning_counter = 0;
	packet_counter->xmas_tree_counter = 0;
	packet_counter->blacklisted_requests_counter = 0;
	
	int packet_len = header->len;
	
	//If verbose set, output packet number
	if (verbose == 1)
		printf("\n\n === PACKET %ld ===\n", pcount);	
	
	//Populate ethernet header 
	struct ether_header *eth_header = (struct ether_header *) packet;
	
	//If verbose set, out put ethernet header
	if (verbose == 1)
		etherOut(eth_header);

	//If the ethernet header declares the packet type to be IP
	if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){
		
		//Populate the IP header
		const unsigned char *eth_strip_packet = packet + ETH_HLEN;
                struct iphdr *ip_header = (struct iphdr *) eth_strip_packet;
		packet_len = packet_len - ETH_HLEN;
		
		//If verbose set, output IP header
		if (verbose == 1)
			ipOut(ip_header);
		
		//If the protocol in IP header is TCP
		if (ip_header->protocol == 6){
			
			//Populate TCP header
			const unsigned char *ip_strip_packet = eth_strip_packet + 4*ip_header->ihl;
                        struct tcphdr *tcp_header = (struct tcphdr *) ip_strip_packet;
			packet_len = packet_len - 4*ip_header->ihl;
			
			//If verbose set, output TCP header and dump the remainigng packet data 
			if (verbose == 1){
				tcpOut(tcp_header);
				//dataDump(ip_strip_packet, packet_len);
			}
			
			//Test for Xmas Tree Packets (FIN, URG and PUSH set)
			if (tcp_header->fin && tcp_header->urg && tcp_header->psh)
				packet_counter->xmas_tree_counter++;
			
			//Test for request to blacklisted site (www.bbc.co.uk)
			const char *http_packet = (char *) (ip_strip_packet + 4*tcp_header->doff);
			if (strstr(http_packet, "Host: www.bbc.co.uk") && (ntohs(tcp_header->dest) == 80) ) 
				packet_counter->blacklisted_requests_counter++;
			
		}
		else if (verbose == 1){
			//dataDump(eth_strip_packet, packet_len);
		}
	}
	//Else if the ethernet header declares the packet type to be ARP
	else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
		
		//Populate ARP header and packet
		const unsigned char *eth_strip_packet = packet + ETH_HLEN;
        	struct ether_arp *arp_packet = (struct ether_arp *) eth_strip_packet;
 		struct arphdr *arp_header = (struct arphdr *) &arp_packet->ea_hdr;

		//If verbose set, output ARP packet and header
		if (verbose == 1)
			arpOut(arp_packet, arp_header);

		//Test for ARP poisioning attack
		if (ntohs(arp_header->ar_op) == ARPOP_REPLY)
			packet_counter->arp_poisioning_counter++;			
	}
	
	//Return counters struct
	return packet_counter;
}

//Breakdown and output Ethernet Header
void etherOut(struct ether_header *eth_header) {
	unsigned int i;
  	
	// Breakdown of Ethernet Header
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

//Breakdown and output IP Header
void ipOut(struct iphdr *ip_header){
	unsigned int i;
	
	// Breakdown of IP Header
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

//Breakdown and output TCP Header
void tcpOut(struct tcphdr *tcp_header){
		
	//Breakdown of TCP Header
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

//Breakdown and output ARP Header and ARP Packet Data
void arpOut(struct ether_arp *arp_packet, struct arphdr *arp_header){
	unsigned int i;
	
	//Decode ARP Header
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

//Dump packet data
void dataDump(const unsigned char *payload, int data_bytes){
	printf("\n---Raw Data---\n");
	int i;
	const static int output_sz = 20; // Output this many bytes at a time
	while (data_bytes > 0) {
		int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
		// Print data in raw hexadecimal form
		for (i = 0; i < output_sz; ++i) {
			if (i < output_bytes) {
				printf("%02x ", payload[i]);
			} else {
				printf ("   "); // Maintain padding for partial lines
			}
		}
		printf ("| ");
		// Print data in ascii form
		for (i = 0; i < output_bytes; ++i) {
			char byte = payload[i];
			if (byte > 31 && byte < 127) {
				// Byte is in printable ascii range
				printf("%c", byte);
			} else {
				printf(".");
			}
		}
		printf("\n");
		payload += output_bytes;
		data_bytes -= output_bytes;
	}
}
