/**
*	@file 	sniff.h
*	@brief 	This file defines all the functions that deal with incoming packets and
* 	the ^C manager
*	
*	@author	Nathan Hall
*	
*	@date	21/11/2018
*/

#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <pcap.h>

/**
*	This method will set-up packet sniffing and initilaise a pcap_loop 
*	
*	@param		interface	Contains the interface which the user wishes to sniff on
*			verbose		Contains the verbose mode flag
*/
void sniff(char *interface, int verbose);

/**
*	This method will run for every incoming packet, it passes it to dispatch and assigns it a
*	packet number 
*	
*	@param		interface	Contains the interface which the user wishes to sniff on
*			verbose		Contains the verbose mode flag
*/
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/**
*	This method will run when ^C signal is detected and will close the program and clean up memeory
*	
*	@param		signo		Contains the value of the signal detected
*/
void sig_handler(int signo);

#endif
