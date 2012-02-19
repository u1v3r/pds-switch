#ifndef SWITCH_H_INCLUDED
#define SWITCH_H_INCLUDED

#include <stdlib.h>

#include "cam_table.h"

#define MAXBYTES2CAPTURE 2048
#define SIZE_ETHERNET 14
#define DEBUG 1

//struktura obsahuje statistiky pre rozhrania
struct stat_table{
    u_char *port;
    unsigned sent_bytes;
    unsigned sent_frames;
    unsigned recv_bytes;
    unsigned recv_frames;
    pcap_t *handler;        //taky mensi hack, uchavava deskriptor pre rozhranie
};
//sluzi pri predavani hodnot pri pcap_loop
struct send_values{
    u_char *port;
    pcap_t *handler;
};
pcap_if_t *devices;
struct stat_table *stat_table_t[HASH_LENGTH];
static char errbuf[PCAP_ERRBUF_SIZE];       //error buffer
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned make_stat_hash(u_char *);
void init_switch();
void process_packet(u_char *, const struct pcap_pkthdr *,
	    const u_char *);
void *open_device(void *);
struct stat_table *find_stat_value(u_char *);
struct stat_table *add_stat_value(u_char *);
void send_unicast(const u_char *,const struct pcap_pkthdr *,u_char *,pcap_t *);
u_char *get_mac_adress(char*);
void send_broadcast(const u_char *,const struct pcap_pkthdr *,u_char *);
void get_all_devices(pcap_if_t *);

#endif // SWITCH_H_INCLUDED
