#ifndef SWITCH_H_INCLUDED
#define SWITCH_H_INCLUDED

#include "cam_table.h"

#define PROMISCUOUS_MODE 1
#define DEFAULT_PORTS_COUNT 15  //pouziva sa pri dynamickom alokovani pamati pre thready
#define MAXBYTES2CAPTURE 2048


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
pthread_mutex_t mutex;
pthread_mutex_t mutex_igmp;
pthread_t *threads;//hready pre rozhrania
pthread_t thread_checker,thread_user_input;
int counter = 0;
char *igmp_querier_port = NULL;    //port na ktorom sa nachadza igmp querier

unsigned make_stat_hash(char *);
void init_switch();
void process_packet(char *, const struct pcap_pkthdr *,
	    const u_char *);
void *open_device(void *);
struct stat_table *find_stat_value(char *);
struct stat_table *add_stat_value(char *);
void send_unicast(const u_char *,const struct pcap_pkthdr *,char *);
u_int8_t *get_mac_adress(char *);
void send_broadcast(const u_char *,const struct pcap_pkthdr *,char *);
void send_multicast(const u_char *,const struct pcap_pkthdr *,uint32_t, char *);
void get_all_devices(pcap_if_t *);
void user_input();
void quit_switch();
void process_igmp_packet(const u_char *,struct ether_header *,
                         struct ip_header_def *, char *,
                         const struct pcap_pkthdr *);
void print_ip_address(uint32_t);
void print_igmp_table();
inline void print_hosts(struct igmp_group_table *);
int multicast_type(uint32_t);
void igmp_table_check();
#endif // SWITCH_H_INCLUDED
