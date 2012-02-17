#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <time.h>

#include "cam_table.h"
#include "switch.h"

/** Jenoducha hashovacia funkcia :D */
unsigned make_hash(char *value){

    unsigned hash_value = 0;
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++){
        hash_value = *(value + i) + 11 * hash_value;
    }

    return (hash_value % HASH_LENGTH);
}

/** Vyhlada zaznam v tabulke a vrati ho, inak NULL*/
struct cam_table *find_value(u_char *value){

    struct cam_table *founded;

    #ifdef DEBUG
    printf("\nSearching hash value %d in cam_table...",make_hash(value));
    #endif

    founded = cam_table_t[make_hash(value)];

    if(founded != NULL) {
       #ifdef DEBUG
       printf("Found\n");
       printf("Adress: %x:%x:%x:%x:%x:%x\n",founded->source_mac[0],founded->source_mac[1],
              founded->source_mac[2],founded->source_mac[3],founded->source_mac[4],founded->source_mac[5]);
       printf("Port: %s\n",founded->port);
       #endif
       return founded;
    }

    /*
    for(founded = cam_table_t[make_hash(value)]; founded != NULL; founded = founded->next){
        printf("cylus: %d\n",i++);
        printf("%d\n",founded->source_mac);
        //if(comapre_u_char(value,founded->source_mac,ETHER_ADDR_LEN)){
          //  return founded;
        //}
    }
    */

    #ifdef DEBUG
    printf("Not found\n");
    #endif

    return NULL;
};

struct cam_table *add_value(u_char source_mac[ETHER_ADDR_LEN], char *port){
    struct cam_table *founded;
    unsigned hash_value;

    //mac adresa sa este v zozname nenachadza
    if((founded = find_value(port)) == NULL){
        #ifdef DEBUG
        printf("Adding to cam_table...");
        #endif

        //vytvor novy zaznam
        founded = (struct cam_table *) malloc(sizeof(*founded));
        if((founded->port = copy_dupl(port)) == NULL || founded == NULL) return NULL;
        founded->source_mac = source_mac;
        //vytovri hash a vlozi do cam_tabulky
        hash_value = make_hash(port);
        founded->next = cam_table_t[hash_value];
        founded->age = (unsigned long)time(NULL);
        cam_table_t[hash_value] = founded;

        #ifdef DEBUG
        printf("Hash %d added to cam_table\n",hash_value);
        #endif
    } else {
        //zaznam existuje, je treba upravit jeho platnost
        founded->age = (unsigned long)time(NULL);

        //ked uz sme u teho, tak v ramci uspory casu odstranime neplatne zaznamy


    }




    /*else {//odstran stary a vloz nove hodnoty
        #ifdef DEBUG
        printf("Replacing row in cam_table\n");
        #endif

        printf("port %s\n",founded->port);
        free((void *) founded->port);

        #ifdef DEBUG
        printf("Row with hash %d replaced in cam_table\n",make_hash(founded->source_mac));
        #endif
    }
    */

    print_cam_table();

    return founded;
};


int comapre_u_char(u_char *a,u_char *b, int char_size){
    int i;

    printf("a %x\n",*(a + 1));
    printf("b %x\n",*(b + 1));
    for(i = 0; i < char_size ; i++){
        //printf("char a: %d\n char b: %d\n",*(a + i),*(b + i));
        //if(*(a + 1) != *(b + 1)) return 0;
    }

    return 1;
}

char *copy_dupl(char *value){

    char *returned;

    if((returned = (char *) malloc(strlen(value) + 1)) != NULL){
        strcpy(returned,value);
    }

    return returned;

}

void print_mac_adress(u_char mac[ETHER_ADDR_LEN]){

    int i = ETHER_ADDR_LEN;
    int j = 0;
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",mac[j++]);
    }while(--i > 0);

    printf("\t");

}

void print_cam_table(){

    struct cam_table *row;
    int i = 0;
    time_t cur_time = time(NULL);

    printf("---------------------------------------\n");
    printf("---------------CAM TABLE---------------\n");
    printf("---------------------------------------\n");
    printf("MAC address\tPort\tAge\t\n");
    for(i = 0; i < HASH_LENGTH;i++){
        if(cam_table_t[i] == NULL) continue;

        print_mac_adress(cam_table_t[i]->source_mac);
        printf("%s\t",cam_table_t[i]->port);
        printf("%i s\n",(cur_time - cam_table_t[i]->age));
    }
    printf("---------------------------------------\n");

}

/** Konstroluje tabulku a odstranuje stare zaznamy */
void cam_table_age_checker(){

    time_t cur_time;
    int i;

    while(0 == 0){
        //kazdych n sekund skontroluj ci tabulka neobsahuje stare zaznamy
        sleep(DELETE_WAIT_TIME);
        #ifdef DEBUG
        printf("\n\nCam table age checking...\n\n");
        #endif
        for(i = 0; i < HASH_LENGTH; i++){
            //preskoc  indexy bez zaznamu
            if(cam_table_t[i] == NULL) continue;

            cur_time = time(NULL);
            if((cur_time - cam_table_t[i]->age) >= AGE_CHECK_TIME){
                pthread_mutex_lock(&mutex);
                cam_table_t[i] = NULL;//odstran zaznam
                pthread_mutex_unlock(&mutex);
            }

        }
    }
}