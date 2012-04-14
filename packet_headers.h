#ifndef PACKET_HEADERS_H_INCLUDED
#define PACKET_HEADERS_H_INCLUDED

/*#include <sys/types.h>*/
#include <stdint.h>
#include <libnet.h>

#define MULTICAST_ALL_ON_SUBNET 0x10000e0 /* IP 224.0.0.1 */
#define MULTICAST_START 224
#define MULTICAST_END 239
#define MULTICAST_TYPE_GROUP 1
#define MULTICAST_TYPE_ALL 2
#define ETHERNET_SIZE 14
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      0x6
#endif
//#define DEBUG 1

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint8_t u_char;
typedef unsigned short u_short;


/** zdroj: http://www.tcpdump.org/pcap.html */

struct ether_header{
  u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* dst adresa */
  u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* src adresa */
  u_int16_t ether_type;
};


struct ip_header_def {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		uint32_t  ip_saddr;        /* Source address */
        uint32_t  ip_daddr;        /* Destination address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


struct igmp_header{
    u_char  igmp_type;           /* Type */
    u_char  igmp_mrt;            /* Max response time */
    u_short igmp_sum;            /* Checksum */
    uint32_t igmp_gaddr;         /* Group address */
};


struct igmp_group_record {
	u_int8_t	record_type;	/* record types for membership report */
	u_int8_t	auxlen;		/* aux data length (must be zero)  */
	u_int16_t	numsrc;		/* number of sources		   */
	uint32_t	group;		/* group address		   */
	//uint32_t	src[25];		/* source address list		   */
};

struct igmpv3_report {
	u_int8_t	igmp_type;	/* version & type of IGMP message  */
	u_int8_t	igmp_reserved1;	/* reserved (set to zero)	   */
	u_int16_t	igmp_cksum;	/* IP-style checksum		   */
	u_int16_t	igmp_reserved2;	/* reserved (set to zero)	   */
	u_int16_t	igmp_grpnum;	/* number of group record	   */
	struct igmp_group_record group_rec;
};

#endif // PACKET_HEADERS_H_INCLUDED
