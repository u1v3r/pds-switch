#ifndef CAM_TABLE_H_INCLUDED
#define CAM_TABLE_H_INCLUDED

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#define AGE_CHECK_TIME 180  //udava dobu platnosti zaznamu v tabulke v sekundach
#define DELETE_WAIT_TIME 30 //doba po ktorej sa vzdy skontroluje cam tabulka
#define HASH_LENGTH 101     //velkost cam tabulky
#define BROADCAST 5         //hash pre broadcast adresu

struct cam_table{
    struct cam_table *next;
    char *port;             //meno rozhrania
    u_int8_t *source_mac;   //adresa prichadzajuceho paketu
    unsigned long age;      //urcuje platnost zaznamu
};
static struct cam_table *cam_table_t[HASH_LENGTH];
unsigned make_ether_hash(u_int8_t *);
struct cam_table *find_packet_value(u_int8_t *);
struct cam_table *add_value(u_int8_t source_mac[ETHER_ADDR_LEN], char *);
int comapre_mac(u_int8_t *,u_int8_t *);
u_int8_t *copy_dupl_mac(u_int8_t *);
void print_mac_adress(u_int8_t mac[ETHER_ADDR_LEN]);
void print_cam_table();
void cam_table_age_checker();
void print_cam_table_stats();

#endif // CAM_TABLE_H_INCLUDED
