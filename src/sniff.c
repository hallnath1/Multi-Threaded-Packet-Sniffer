#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <string.h>

#include "dispatch.h"

pcap_t *pcap_handle;

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  // Capture packets (very ugly code)
  struct pcap_pkthdr header;
  const unsigned char *packet;
  while (1) {
    // Capture a  packet
    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
    } else {
      // Optional: dump raw data to terminal
      
/*	if (verbose) {
        dump(packet, header.len);
      }
  */    
      unsigned char *pack = malloc(sizeof(char)*header.len);
      memcpy(pack, packet, header.len);
      // Dispatch packet for processing
      dispatch(&header, pack, verbose);
    }
  }
}
