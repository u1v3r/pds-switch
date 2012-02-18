#ifndef SWITCH_H_INCLUDED
#define SWITCH_H_INCLUDED

#include <stdlib.h>

#include "cam_table.h"

#define MAXBYTES2CAPTURE 2048
#define SIZE_ETHERNET 14
#define DEBUG 1

struct stat_table{
    u_char *port;
    unsigned sent_bytes;
    unsigned sent_frames;
    unsigned recv_bytes;
    unsigned recv_frames;
};
struct stat_table *stat_table_t[HASH_LENGTH];
static char errbuf[PCAP_ERRBUF_SIZE];       //error buffer
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned make_stat_hash(u_char *);
void init_switch();
void process_packet(u_char *, const struct pcap_pkthdr *,
	    const u_char *);
void start_listening();
void *open_device(void *);
struct stat_table *find_stat_value(u_char *);
struct stat_table *add_stat_value(u_char *);
void send_unicast(const u_char *,const struct pcap_pkthdr *,u_char *);
u_char *get_mac_adress(char*);
void send_broadcast(const u_char *,const struct pcap_pkthdr *,u_char *);

#endif // SWITCH_H_INCLUDED
