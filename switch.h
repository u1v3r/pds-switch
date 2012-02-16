#ifndef SWITCH_H_INCLUDED
#define SWITCH_H_INCLUDED

#include <stdlib.h>

#define MAXBYTES2CAPTURE 2048
#define SIZE_ETHERNET 14


void init_switch();

void process_packet(u_char *, const struct pcap_pkthdr *,
	    const u_char *);

void start_listening();
void *open_device(void *);


#endif // SWITCH_H_INCLUDED
