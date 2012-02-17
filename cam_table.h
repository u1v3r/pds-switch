#ifndef CAM_TABLE_H_INCLUDED
#define CAM_TABLE_H_INCLUDED

#define AGE_CHECK_TIME 20
#define DELETE_WAIT_TIME 20
#define HASH_LENGTH 101
#define DEBUG 1

#include <stdint.h>

struct cam_table{
    struct cam_table *next;
    char *port;
    u_char *source_mac;
    unsigned long age;
};
static struct cam_table *cam_table_t[HASH_LENGTH];
unsigned make_hash(char *);
struct cam_table *find_value(u_char *);
struct cam_table *add_value(u_char source_mac[ETHER_ADDR_LEN], char *);
int comapre_u_char(u_char *,u_char *, int);
char *copy_dupl(char *);
void print_mac_adress(u_char mac[ETHER_ADDR_LEN]);
void print_cam_table();
void cam_table_age_checker();

#endif // CAM_TABLE_H_INCLUDED
