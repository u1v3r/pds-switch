#include "cam_table.h"



/** Jenoducha hashovacia funkcia :D */
unsigned make_ether_hash(u_int8_t *value){


    unsigned hash_value = 0;
    int i;

    for(i = 0; i < ETHER_ADDR_LEN; i++){
        hash_value = *(value + i) ^ 11 * hash_value;
    }

    return (hash_value % HASH_LENGTH);
}

/** Vyhlada zaznam v tabulke a vrati ho, inak NULL*/
struct cam_table *find_packet_value(u_int8_t *value){

    struct cam_table *founded;


    #ifdef DEBUG
    printf("\nSearching hash value %d in cam_table...",make_ether_hash(value));
    #endif

    for(founded = cam_table_t[make_ether_hash(value)]; founded != NULL ; founded = founded->next){
        if(comapre_mac(value,founded->source_mac) == 1){//nasiel sa
            #ifdef DEBUG
            printf("Found\n");
            printf("Adress: %x:%x:%x:%x:%x:%x\n",founded->source_mac[0],founded->source_mac[1],
                   founded->source_mac[2],founded->source_mac[3],founded->source_mac[4],founded->source_mac[5]);
            printf("Port: %s\n",founded->port);
            #endif
            return founded;
        }
    }

    /*
    founded = cam_table_t[make_ether_hash(value)];


    if(founded != NULL) {
       #ifdef DEBUG
       printf("Found\n");
       printf("Adress: %x:%x:%x:%x:%x:%x\n",founded->source_mac[0],founded->source_mac[1],
              founded->source_mac[2],founded->source_mac[3],founded->source_mac[4],founded->source_mac[5]);
       printf("Port: %s\n",founded->port);
       #endif
       return founded;
    }
    */

    #ifdef DEBUG
    printf("Not found\n");
    #endif

    return NULL;
};

/** Prida mac adresu do cam tabulku */
struct cam_table *add_value(u_int8_t source_mac[ETHER_ADDR_LEN], char *port){

    struct cam_table *founded;
    unsigned hash_value = 0;

    //mac adresa sa este v zozname nenachadza
    if((founded = find_packet_value(source_mac)) == NULL){
        #ifdef DEBUG
        printf("Adding to cam_table...");
        #endif

        //vytvor novy zaznam
        founded = (struct cam_table *) malloc(sizeof(*founded));

        //if(founded == NULL) return NULL;
        if((founded->source_mac = copy_dupl_mac(source_mac)) == NULL || founded == NULL){
            return NULL;
        }
        founded->port = port;
        founded->age = (unsigned long)time(NULL);

        hash_value = make_ether_hash(source_mac);
        founded->next = cam_table_t[hash_value];
        cam_table_t[hash_value] = founded;

        #ifdef DEBUG
        printf("\nport: %s\n",founded->port);
        printf("mac:");print_mac_adress(founded->source_mac);
        printf("\nage: %li\n",founded->age);
        printf("Hash %d added to cam_table\n",hash_value);
        #endif
    }else {
        founded->age = (unsigned long)time(NULL);
    }

    return founded;
};

/** Porovnava dve mac adresy a vrati 1 ak sa rovnaju, inak 0 */
int comapre_mac(u_int8_t *a,u_int8_t *b){

    int i;
    for(i = 0; i < ETHER_ADDR_LEN ; i++){
        if(*(a + i) != *(b + i)) return 0;
    }

    return 1;
}

/** Vytvori kopiu mac adresy */
u_int8_t *copy_dupl_mac(u_int8_t *mac){

    #ifdef DEBUG
    printf("Kopirujem mac:");
    print_mac_adress(mac);
    printf("\n");
    #endif
    u_int8_t *returned;
    int i;

    if((returned = (u_int8_t *) malloc(sizeof(u_int8_t) * ETHER_ADDR_LEN)) != NULL){
        for(i = 0; i < ETHER_ADDR_LEN; i++){
            *(returned + i) = *(mac + i);
        }
    }

    return returned;
}

/** Na vystup vypise mac adresu */
void print_mac_adress(u_int8_t mac[ETHER_ADDR_LEN]){

    int i = ETHER_ADDR_LEN;
    int j = 0;
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? "" : ":",mac[j++]);
    }while(--i > 0);

    printf("\t");

}

/** Na vystup vypise cam tabulku */
void print_cam_table(){

    int i,pocet = 0;
    time_t cur_time = time(NULL);
    struct cam_table *founded;

    printf("\n---------------CAM TABLE---------------\n");
    printf("MAC address\tPort\tAge\t\n");
    pthread_mutex_lock(&mutex);
    for(i = 0; i < HASH_LENGTH;i++){
        //prechadzaj len tie kde su nejake hodnoty
        if(cam_table_t[i] == NULL) continue;

        //ak sa v jednom indexe nachadza viac hodnot, tak vypis
        if(cam_table_t[i]->next != NULL){
            #ifdef DEBUG
            printf("\nkolizne pre hash %i\n",i);
            #endif
            //postupne vypisuj
            for(founded = cam_table_t[i]; founded != NULL; founded = founded->next){
                print_mac_adress(founded->source_mac);
                printf("%s\t",founded->port);
                printf("%li s\n",(cur_time - founded->age));
                pocet++;
            }
            #ifdef DEBUG
            printf("koniec kolizne\n\n");
            #endif
        } else {//inak vypisuj len hodnoty na indexoch
            print_mac_adress(cam_table_t[i]->source_mac);
            printf("%s\t",cam_table_t[i]->port);
            printf("%li s\n",(cur_time - cam_table_t[i]->age));
            pocet++;
        }


    }
    pthread_mutex_unlock(&mutex);
    printf("------------------%i---------------------\n",pocet);

}

/** Kontroluje tabulku a odstranuje stare zaznamy */
void cam_table_age_checker(){


    int i;

    while(0 == 0){
        //kazdych n sekund skontroluj ci tabulka neobsahuje stare zaznamy
        sleep(DELETE_WAIT_TIME);
        #ifdef DEBUG
        printf("\n\nCam table age checking...\n\n");
        #endif
        pthread_mutex_lock(&mutex);
        for(i = 0; i < HASH_LENGTH; i++){
            //preskoc  indexy bez zaznamu
            if(cam_table_t[i] == NULL) continue;

            //ak existuje viac zaznomov v skupine
            if(cam_table_t[i]->next != NULL){

                struct cam_table *founded;

                //zoznam je usporiadany od najmensieho
                for(founded = cam_table_t[i]; founded != NULL; founded = founded->next){
                    //dalsi zaznam v poradi
                    if((time(NULL) - founded->age) >= AGE_CHECK_TIME){
                        if(founded->next == NULL){//posledny v rade
                            printf("MAZEM posledny zaznam - %i\n",i);
                            free((void *) founded);
                            break;
                        } else{//este tam je nejaky
                            struct cam_table *next = founded->next;

                            printf("\n\n\nMAZEM pre index %i\n\n\n",i);
                            print_mac_adress(founded->source_mac);

                            free((void *)founded);//odstran zaznam
                            //founded = next;

                            printf("\nsmazal som\n");
                        }

                    }
                }

            } else {
                if((time(NULL) - cam_table_t[i]->age) >= AGE_CHECK_TIME){

                    cam_table_t[i] = NULL;//odstran zaznam

                }
            }




        }
        pthread_mutex_unlock(&mutex);
    }
}

/** Zobrazi stat tabulku */
void print_cam_table_stats(){

    int i;

    printf("\n------------------STAT-----------------\n");
    printf("Iface\tSent-B\tSent-frm\tRecv-B\tRecv-frm\n");
    for(i = 0; i < HASH_LENGTH;i++){
        if(stat_table_t[i] == NULL) continue;

        printf("%s\t",stat_table_t[i]->port);
        printf("%i\t",stat_table_t[i]->sent_bytes);
        printf("%i\t",stat_table_t[i]->sent_frames);
        printf("%i\t",stat_table_t[i]->recv_bytes);
        printf("%i\t\n",stat_table_t[i]->recv_frames);

    }
    printf("---------------------------------------\n");
}
