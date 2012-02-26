#include "igmp_snp.h"


/* Vlozi zaznam do skupiny */
struct igmp_group_table *add_group(uint32_t address, char *port){

    struct igmp_group_table *founded = find_group(address);
    unsigned hash_value = 0;
    struct igmp_host *tmp_host;

    //multicast skupina existuje, treba len pridat clena skupiny
    if(founded != NULL){

        /* uvolnime pamat pre novy zaznam */
        if(founded->deleted == 1) {
            #ifdef DEBUG
            printf("Clen skupiny bol zmazany, pouzijem jeho miesto\n");
            #endif

            free((void *)founded->igmp_hosts);

            //upravenie stareho clena
            tmp_host = (struct igmp_host *) malloc(sizeof(*tmp_host));
            if(tmp_host == NULL) return NULL;
            tmp_host->age = (unsigned long)time(NULL);//aktualny cas
            tmp_host->port = port;
            tmp_host->next = NULL;//je prvy v zozname, takze NULL
            founded->igmp_hosts = tmp_host;//vlozime do zoznamu
            founded->length = 1;
            founded->deleted = 0;
            tmp_host->last_element = tmp_host;

            return;
        }


        /* kontrola ci uz nahodou nie je rovnaky port v skupine */
        if((tmp_host = find_host(founded,port)) != NULL){
            #ifdef DEBUG
            printf("Rovnakeho clena uz skupina obsahuje, upravujem cas\n");
            #endif
            tmp_host->age = (unsigned long)time(NULL);
            return;
        }

        #ifdef DEBUG
        printf("Pridavam noveho clena na porte %s do skupiny:",port);
        print_ip_address(address);
        printf("\n");
        #endif

        #ifdef DEBUG
        printf("Posledny port v zozname je port: %s\n",founded->igmp_hosts->last_element->port);
        #endif

        //vytvorime noveho hosta
        struct igmp_host *new_host = (struct igmp_host *) malloc(sizeof(*new_host));
        new_host->port = port;
        new_host->age = (unsigned long)time(NULL);
        new_host->next = NULL;


        //a pridame ho nakoniec
        founded->igmp_hosts->last_element->next = new_host;
        founded->igmp_hosts->last_element = new_host;

        /* inkrementujeme pocitadlo */
        founded->length = founded->length + 1;

        #ifdef DEBUG
        printf("Novy posledny port je taraz: %s\n",founded->igmp_hosts->last_element->port);
        #endif

    }else {//multicast skupina este nie je v tabulke, alebo je "vymazana"

        #ifdef DEBUG
        printf("IGMP - Adding to group_table...");
        #endif

        founded = create_group(address,port);
    }

    return founded;
};

inline struct igmp_group_table *create_group(uint32_t address, char *port){

    struct igmp_group_table *founded;
    unsigned hash_value = 0;
    struct igmp_host *tmp_host;

    //vytvor novy zaznam
    founded = (struct igmp_group_table *) malloc(sizeof(*founded));

    if(founded == NULL) return NULL;

    //adresa skupiny
    founded->group_addr = address;

    //vlozenie noveho clena skupiny
    tmp_host = (struct igmp_host *) malloc(sizeof(*tmp_host));
    if(tmp_host == NULL) return NULL;
    tmp_host->age = (unsigned long)time(NULL);//aktualny cas
    tmp_host->port = port;
    tmp_host->next = NULL;//je prvy v zozname, takze NULL
    founded->igmp_hosts = tmp_host;//vlozime do zoznamu
    founded->length = 1;
    founded->deleted = 0;
    tmp_host->last_element = tmp_host;

    hash_value = make_address_hash(address);
    founded->next = igmp_groups[hash_value];
    igmp_groups[hash_value] = founded;

    #ifdef DEBUG
    printf("\nVytovrena nova multicast skupina\n");
    printf("address:");print_ip_address(address);
    printf("\nhash %d added to group_table\n",hash_value);
    #endif

    return founded;
}

struct igmp_group_table *find_group(uint32_t address){

    struct igmp_group_table *founded;

    #ifdef DEBUG
    printf("\nSearching hash value %d in group_table...",make_address_hash(address));
    #endif

    for(founded = igmp_groups[make_address_hash(address)]; founded != NULL ; founded = founded->next){
        if(address == founded->group_addr){//nasiel sa
            #ifdef DEBUG
            printf("Found\n");
            print_ip_address(address);
            printf("\n");
            #endif
            return founded;
        }
    }

    return NULL;
};

int remove_host(uint32_t address, char *port){

    struct igmp_group_table *group = find_group(address);


    if(group == NULL){
        #ifdef DEBUG
        printf("IGMP remove host: mazany zanam neexistuje\n");
        #endif
        return 0;
    }

    /* skupina ma len jedneho clena, takze ju mozeme v pohode celu odstranit*/
    if(group->length == 1){
        if(strcmp(group->igmp_hosts->port,port) == 0){
            group->deleted = 1;
            return 1;
        }
    }/*else if(group->length == 2){

        struct igmp_host *next_host = group->igmp_hosts->next;

        if(strcmp(next_host->port,port) == 0){
            free((void *)next_host);
            return 1;
        }
    }*/else {
        //neotestovane
        struct igmp_host *prev_host = group->igmp_hosts;

        while(prev_host != NULL){

            if(strcmp(prev_host->port,port) == 0){
                #ifdef DEBUG
                printf("Odstranujem port %s\n",port);
                #endif
                prev_host->deleted = 1;
                group->length = group->length -1;

                return 1;
            }

            prev_host = prev_host->next;
        }
    }

    return 0;
}

unsigned make_address_hash(uint32_t address){

    return (address % HASH_LENGTH);
}

/* Prevedie ip adresu do citatelnej podoby */
unsigned char *convert_ip(uint32_t ip_address){

    unsigned char tmp[4] = {0,0,0,0};

    int i;

    for (i = 0; i < 4; i++){
        tmp[i] = ( ip_address >> (i*8) ) & 0xFF;
    }

    return tmp;
}


/* vyhlada clena v zadanej skupiny */
struct igmp_host *find_host(struct igmp_group_table *group, char *port){

    if(group == NULL) return NULL;

    struct igmp_host *hosts;
    for(hosts = group->igmp_hosts; hosts != NULL; hosts = hosts->next){
        if(strcmp(hosts->port,port) == 0 && hosts->deleted == 0){
            return hosts;
        }
    }

    return NULL;
};
