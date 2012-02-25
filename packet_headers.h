#ifndef PACKET_HEADERS_H_INCLUDED
#define PACKET_HEADERS_H_INCLUDED

#include <sys/types.h>
#include <stdint.h>
#include <libnet.h>

#define ETHERNET_SIZE 14
#define DEBUG 1

struct ether_header
{
  u_int8_t  ether_dhost[ETHER_ADDR_LEN];//dst adresa
  u_int8_t  ether_shost[ETHER_ADDR_LEN];//src adresa
  u_int16_t ether_type;
};

struct ip_header {
    u_char  ip_ver_ihl;        /* Version (4 bits) + Internet header length (4 bits) */
    u_char  ip_tos;            /* Type of service */
    u_short ip_tlen;           /* Total length */
    u_short ip_identification; /* Identification */
    u_short ip_flags_fo;       /* Flags (3 bits) + Fragment offset (13 bits) */
    u_char  ip_ttl;            /* Time to live */
    u_char  ip_proto;          /* Protocol */
    u_short ip_sum;            /* Header checksum */
    uint32_t  ip_saddr;          /* Source address */
    uint32_t  ip_daddr;          /* Destination address */
    u_int   ip_op_pad;         /* Option + Padding */
};

struct igmp_header {
    u_char  igmp_type;           /* Type */
    u_char  igmp_mrt;            /* Max response time */
    u_short igmp_sum;            /* Checksum */
    uint32_t igmp_gaddr;          /* Group address */
};

#endif // PACKET_HEADERS_H_INCLUDED
