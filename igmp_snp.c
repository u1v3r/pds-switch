#include "igmp_snp.h"


/* Vlozi zaznam do skupiny */
struct igmp_group_table *add_group(uint32_t address, char *port){

    struct igmp_group_table *founded;
    unsigned hash_value = 0;
    struct igmp_host *tmp_host;

    //multicast skupina este nie je v tabulke
    if((founded = find_group(address)) == NULL){
        #ifdef DEBUG
        printf("IGMP - Adding to group_table...");
        #endif

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

        hash_value = make_address_hash(address);
        founded->next = igmp_groups[hash_value];
        igmp_groups[hash_value] = founded;

        #ifdef DEBUG
        printf("\nVytovrena nova multicast skupina\n");
        printf("address:");print_ip_address(address);
        printf("\nhash %d added to group_table\n",hash_value);
        #endif
    }else {//multicast skupina existuje, treba len pridat clena skupiny

        //prechadzaj zoznamom a najdi posledny zaznam
        do{
            tmp_host = founded->igmp_hosts->next;
        } while(tmp_host != NULL);

        //vytvorime noveho hosta
        struct igmp_host *new_host = (struct igmp_host *) malloc(sizeof(*new_host));
        new_host->port = port;
        new_host->port = (unsigned long)time(NULL);
        new_host->next = NULL;
        //a pridameho nakoniec
        tmp_host->next = new_host;
    }

    return founded;
};

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

unsigned make_address_hash(uint32_t address){

    //prevedieme adresu na nieco hashovatelne
    unsigned char *value = convert_ip(address);
    unsigned hash_value = 0;
    int i;

    for(i = 0; i < ETHER_ADDR_LEN; i++){
        hash_value = *(value + i) ^ 31 * hash_value;
    }

    #ifdef DEBUG
    printf("IP ADDRESS HASH - ");
    printf("Sum %i ,Hash %i\n",hash_value,(hash_value % HASH_LENGTH));
    #endif

    return (hash_value % HASH_LENGTH);
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


