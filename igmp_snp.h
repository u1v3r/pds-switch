#ifndef IGMP_SNP_H_INCLUDED
#define IGMP_SNP_H_INCLUDED

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>

#include "packet_headers.h"

#define HASH_LENGTH 257         /* velkost cam a igmp tabulky - malo by byt prvocislo */
#define IP_ADDRESS_LENGTH 4
//#define CHECKER_SLEEP_TIME 120  /* igmp tabulka sa kontroluje vzdy po 2 minutach */
#define VALID_AGE 300           /* platnost zaznamu 5 minut */

#define IGMP_PROTO 0x02
#define IGMP_MEMBERSHIP_QUERY 0x11
#define IGMP_MEMBERSHIP_REPORT_V1 0x12
#define IGMP_MEMBERSHIP_REPORT_V2 0x16
#define IGMP_MEMBERSHIP_REPORT_V3 0x22
#define IGMP_LEAVE_GROUP_V2 0x17
#define IGMP_GENERAL_QUERY 0/* group adress je nastavena na 0 ak je general query */

struct igmp_host{
    char *port;             /* port na ktorom sa zariadenie nachadza */
    unsigned long age;      /* udava dobu poslednej komunikacie pre zariadenie */
    struct igmp_host *next; /* ukazuje na dalsi prvok zoznamu */
    int deleted;            /* 1 host bol zmazany, 0 - host existuje */
};

struct igmp_group_table{
    struct igmp_host *igmp_hosts;   /* clenovia skupiny */
    uint32_t group_addr;            /* ip adresa skupiny */
    struct igmp_group_table *next;  /* ukazatel na nasedujucu skupinu */
    int length;                     /* udava pocet clenov multicast skupiny */
    int deleted;                    /* ak je 1 skupina bola zmazana 0 existuje */
};

struct igmp_group_table *igmp_groups[HASH_LENGTH];

struct igmp_group_table *add_group(uint32_t, char *);
struct igmp_group_table *create_group(uint32_t, char *);
struct igmp_group_table *find_group(uint32_t);
unsigned make_address_hash(uint32_t);
unsigned char *convert_ip(uint32_t);
struct igmp_host *find_host(struct igmp_group_table *, char *);
int remove_host(uint32_t, char *);

#endif // IGMP_SNP_H_INCLUDED
