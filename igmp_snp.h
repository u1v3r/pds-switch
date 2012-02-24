#ifndef IGMP_SNP_H_INCLUDED
#define IGMP_SNP_H_INCLUDED

#include "packet_headers.h"

#define IGMP_PROTO 0x02
#define IGMP_MEMBERSHIP_QUERY 0x11
#define IGMP_MEMBERSHIP_REPORT_V1 0x12
#define IGMP_MEMBERSHIP_REPORT_V2 0x16
#define IGMP_MEMBERSHIP_REPORT_V3 0x17
#define IGMP_LEAVE_GROUP_V2 0x17
#define HASH_LENGTH 101     //velkost cam a igmp tabulky

struct igmp_table{
    char *port;
    u_int8_t *mac;
    u_long group_addr;
};

void process_igmp_packet(struct ether_header *, struct ip_header *);

#endif // IGMP_SNP_H_INCLUDED
