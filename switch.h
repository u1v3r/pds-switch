#ifndef SWITCH_H_INCLUDED
#define SWITCH_H_INCLUDED

#include <pcap.h>
#include <pthread.h>
#include <stdio.h>

#include "cam_table.h"

#define PROMISCUOUS_MODE 1
#define DEFAULT_PORTS_COUNT 10  //pouziva sa pri dynamickom alokovani pamati pre thready
#define MAXBYTES2CAPTURE 2048
#define DEBUG 1

//struktura obsahuje statistiky pre rozhrania
struct stat_table{
    char *port;
    unsigned sent_bytes;
    unsigned sent_frames;
    unsigned recv_bytes;
    unsigned recv_frames;
    pcap_t *handler;        //taky mensi hack, uchavava deskriptor pre rozhranie
};
struct stat_table *stat_table_t[HASH_LENGTH];
static char errbuf[PCAP_ERRBUF_SIZE];       //error buffer
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t *threads;//hready pre rozhrania
pthread_t thread_checker,thread_user_input;
int counter = 0;

unsigned make_stat_hash(char *);
void init_switch();
void process_packet(char *, const struct pcap_pkthdr *,
	    const u_char *);
void *open_device(void *);
struct stat_table *find_stat_value(char *);
struct stat_table *add_stat_value(char *);
void send_unicast(const u_char *,const struct pcap_pkthdr *,char *,pcap_t *);
u_int8_t *get_mac_adress(char *);
void send_broadcast(const u_char *,const struct pcap_pkthdr *,char *);
void get_all_devices(pcap_if_t *);
void user_input();
void quit_switch();

#endif // SWITCH_H_INCLUDED
