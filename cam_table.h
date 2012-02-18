#ifndef CAM_TABLE_H_INCLUDED
#define CAM_TABLE_H_INCLUDED

#define AGE_CHECK_TIME 20
#define DELETE_WAIT_TIME 20
#define HASH_LENGTH 101
#define BROADCAST 5

#include <stdint.h>

struct cam_table{
    struct cam_table *next;
    u_char *port;             //meno rozhranie
    u_char *source_mac;     //adresa prichadzajuceho paketu
    unsigned long age;      //urcuje platnost zaznamu
};
static struct cam_table *cam_table_t[HASH_LENGTH];
unsigned make_ether_hash(u_char *);
struct cam_table *find_value(u_char *);
struct cam_table *add_value(u_char source_mac[ETHER_ADDR_LEN], u_char *);
int comapre_u_char(u_char *,u_char *, int);
char *copy_dupl(u_char *);
void print_mac_adress(u_char mac[ETHER_ADDR_LEN]);
void print_cam_table();
void cam_table_age_checker();
void print_cam_table_stats();

#endif // CAM_TABLE_H_INCLUDED
