#include "switch.h"
#include "cam_table.c"

/**
 * Inicializuje switch
 */
void init_switch(){

    pcap_if_t *devices;

    int threads_count = DEFAULT_PORTS_COUNT;
    pcap_if_t *d;
    int j,i = 0;

    //najdi vsetky rozhrania
    if( (pcap_findalldevs(&devices,errbuf)) == -1){
        fprintf(stderr,"ERROR: Can't find ethernet devices");
        exit(EXIT_FAILURE);
    }

    //inicializacia pamate pre vlakna
    threads = (pthread_t *) calloc(DEFAULT_PORTS_COUNT,sizeof(pthread_t));
    if(threads == NULL){
        exit(EXIT_FAILURE);
    }

    //vyfiltruje len relevantne zariadenia
    #ifdef DEBUG
    printf("Adding ethernet interface:\n");
    #endif

    for(d=devices; d; d=d->next){

        //filturuje len relevantne zariadenia
        if(d->addresses == NULL || d->flags == 1) continue;

        //ak je treba alokuj novu pamat
        if(i % threads_count == 0 && i != 0) {
            threads_count = threads_count + DEFAULT_PORTS_COUNT;
            threads = (pthread_t *) realloc(threads,threads_count * sizeof(pthread_t));
            #ifdef DEBUG
            printf("Memory re-allocation: %lu\n",(unsigned long)threads_count * sizeof(pthread_t));
            #endif
        }

        #ifdef DEBUG
        printf("device: %s,",d->name);
        //printf("address: %d,",d->addresses->addr);
        printf("desc: %s,",d->description);
        printf("flag: %d\n",d->flags);
        #endif

        pthread_mutex_init(&mutex,NULL);
        pthread_mutex_init(&mutex_igmp,NULL);

        /* vytvorenie samostatného vlákna pre každé rozhranie */
        pthread_create(&threads[i++],NULL,open_device,(void *) d->name);

        /* vlozenie rozhrani do stat tabulky */
        add_stat_value(d->name);

        /* pocet vytvorenych vlakien */
        counter++;
    }

    #ifdef DEBUG
    printf("Threads count: %d\n", counter);
    #endif

    /* vlakno prechadza tabulku a ak obsahuje stary zaznam tak ho odstrani */
    pthread_create(&thread_checker,NULL,(void *)cam_table_age_checker,NULL);

    /* zachytava prikazy uzivatela */
    pthread_create(&thread_user_input,NULL,(void *)user_input,NULL);

    pthread_join(thread_checker,NULL);
    pthread_join(thread_user_input,NULL);

    for(j = 0; j < counter;j++){
        pthread_join(threads[j],NULL);
    }

}

/** Otvori zadane rozhrania a zacne na nom odchytavat pakety */
void *open_device(void *name){

    struct stat_table *found;  //treba do struktury ulozit deskriptor rozhrania

    /*
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    char filer_exp[] = "";
    */

    /* vyber z tabulky rozhranie */
    found = find_stat_value((char *)name);
    if((found->handler = pcap_open_live((const char *)name,MAXBYTES2CAPTURE,
                                        PROMISCUOUS_MODE,512,errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    #ifdef DEBUG
    printf("Handler adress for device %s: %li\n",(char *)name,(long)&found->handler);
    printf("Openning device %s\n",(char *)name);
    #endif

/*
    if( pcap_lookupnet(device_name,&net,&mask,errbuf) == -1){
        fprintf(stderr,"ERROR: Cant get netmask for device %s\n",device_name);
        net = 0;
        mask = 0;
        return 2;
    }

    if(pcap_compile(handler,&fp,filer_exp,0,net) == -1){
        fprintf(stderr,"ERROR: Cant compile %s\n",filer_exp);
        return 2;
    }

    if(pcap_setfilter(handler,&fp) == -1){
        fprintf(stderr,"ERROR: Cant install filter %s\n",filer_exp);
        return 2;
    }
*/

    /* odchytavaj len prichadzajuce pakety */
    if(pcap_setdirection(found->handler,PCAP_D_IN) == -1){
        fprintf(stderr,"ERROR: Can't set packet capture direction");
        exit(EXIT_FAILURE);
    };

    //spracuj prichodzie pakety pomocou process_packet
    pcap_loop(found->handler,-1,(void *)process_packet,(u_char *) name);
}

/**
 * Spracuje prichadzajuci paket
 */
void process_packet(char *incoming_port,const struct pcap_pkthdr *header, const u_char *packet){

    struct stat_table *founded;
    struct ether_header *ether = (struct ether_header*)(packet);
    struct ip_header_def *ip = (struct ip_header_def*)(packet + ETHERNET_SIZE);

    u_int8_t source_mac[ETHER_ADDR_LEN],dest_mac[ETHER_ADDR_LEN];
    memcpy(source_mac,ether->ether_shost,ETHER_ADDR_LEN);
    memcpy(dest_mac,ether->ether_dhost,ETHER_ADDR_LEN);

    #ifdef DEBUG
        int i = ETHER_ADDR_LEN;
        int j = 0;

        printf("-------------------------------------\n");
        printf("Source port: %s\n",incoming_port);
        printf("Source address:  ");
        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",source_mac[j++]);
        }while(--i > 0);
        printf("\n");

        i = ETHER_ADDR_LEN;
        j = 0;
        printf("Dest Address:  ");
        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",dest_mac[j++]);
        }while(--i > 0);

        printf("\n");
    #endif


    pthread_mutex_lock(&mutex);

    /* vlozi mac adresu rozhrania do cam tabulky */
    add_value(source_mac,(char *)incoming_port);

    /* zapise statistiky */
    founded = find_stat_value((char *)incoming_port);
    founded->recv_frames = founded->recv_frames + 1;
    founded->recv_bytes = founded->recv_bytes + header->len;

    pthread_mutex_unlock(&mutex);

    /* ak je prijaty igmp packet */
    if(ip->ip_p == IGMP_PROTO){
        #ifdef DEBUG
            printf("\n\n IGMP packet \n\n");
        #endif
        process_igmp_packet(packet,ether,ip,incoming_port,header);
        return;
    }


    /* ak je broadcast alebo je nastavena dst ip 224.0.0.1, tak posli broadcast */
    if (make_ether_hash(dest_mac) == BROADCAST ||
        ip->ip_daddr == MULTICAST_ALL_ON_SUBNET){
        #ifdef DEBUG
            printf("\n\n BROADCAST \n\n");
        #endif
        send_broadcast(packet,header,(char *)incoming_port);
        return;
    }

    /* zachytava vsetky multicast pakety, ktore nie su IGMP */
    if(multicast_type(ip->ip_daddr) > 0){

        /*
        if(multicast_t == MULTICAST_TYPE_ALL){

            #ifdef DEBUG
            printf("Adresa ");
            print_ip_address(ip->ip_daddr);
            printf(" je z rozsahu 224.0.0.0/24 - broadcast");
            #endif
            send_broadcast(packet,header,incoming_port);

        }else {
        */
            #ifdef DEBUG
                printf("\n\n\n MULTICAST pre skupinu ");
                print_ip_address(ip->ip_daddr);
                printf(" \n\n\n");
            #endif
            send_multicast(packet,header,ip->ip_daddr,incoming_port);
        //}

        return;
    }

    /* ak je cielovym portom port na switch, tak neposielaj dalej */
    if(comapre_mac(get_mac_adress(incoming_port),dest_mac)){
        #ifdef DEBUG
            printf("Cielova mac adresa paketu sa zhoduje s adresou portu %s, neposielam paket dalej:\n ",incoming_port);
            print_mac_adress(get_mac_adress(incoming_port));
            printf("==");
            print_mac_adress(dest_mac);
            printf("\n");
        #endif
        return;
    }

    /* ak sa cielova mac nachadza v cam table, tak posli na dany port */
    pthread_mutex_lock(&mutex);
    struct cam_table *cam_table_found = find_packet_value(dest_mac);
    pthread_mutex_unlock(&mutex);

    /* mac adresa sa nachadza v cam tabulke */
    if(cam_table_found != NULL){

        /* treba posielat len pakety, ktore danej adrese patria */
        if( comapre_mac(cam_table_found->source_mac,dest_mac) == 0) {
            #ifdef DEBUG
                print_mac_adress(cam_table_found->source_mac);
                printf(" != ");
                print_mac_adress(dest_mac);
                printf("\n");
            #endif
            return;
        }

        #ifdef DEBUG
            printf("Posielam packet z rozhrania %s cez rozhranie %s z adresy ",
                   incoming_port,cam_table_found->port);
            print_mac_adress(source_mac);
            printf("na adresu ");
            print_mac_adress(dest_mac);
            printf("\n");
        #endif

        send_unicast(packet,header,cam_table_found->port);

    }
    else{
        /*rozhranie sa v cam tabulke nenechadza */

        #ifdef DEBUG
            printf("Rozhranie som pre adresu ");
            print_mac_adress(dest_mac);
            printf("nenasiel\n");
        #endif

        send_broadcast(packet,header,incoming_port);
    }

}

/** Podla nazvu rozhrania vyhlada zaznam v stat tabulke */
struct stat_table *find_stat_value(char *port){

    struct stat_table *founded;

    founded = stat_table_t[make_stat_hash(port)];

    if(founded == NULL) return NULL;

    return founded;
}

/** Prida zaznam do stat tabulky */
struct stat_table *add_stat_value(char *port){

    struct stat_table *add;

    unsigned hash_value = make_stat_hash(port);
    add = (struct stat_table *) malloc(sizeof(*add));
    add->port = port;
    add->recv_bytes = 0;
    add->recv_frames = 0;
    add->sent_bytes = 0;
    add->sent_frames = 0;
    stat_table_t[hash_value] = add;

    return add;
}

/** Vytvori hash pre stat tabulku */
unsigned make_stat_hash(char *value){

    unsigned hash_value = 0;

    int i;

    for(i = 0; i < strlen(value); i++){
        hash_value = *(value + i) + 11 * hash_value;
    }
    return (hash_value % HASH_LENGTH);

}

/** Posle unicast */
void send_unicast(const u_char *packet,const struct pcap_pkthdr *header,char *port){

    /* zisti handler pre dany port */
    pcap_t *handler = find_stat_value(port)->handler;
    struct stat_table *founded;

    /* posle na otvorene rozhranie paket */
    int sent_bytes = pcap_inject(handler,packet,header->len);

    /* ak prijalo zapis statistiky */
    if(sent_bytes == -1){
        fprintf(stderr,"Note: Packet not send  - %s\n",pcap_geterr(handler));

    }else{
        /* zapise statistiky*/
        founded = find_stat_value(port);

        if(founded == NULL){
            fprintf(stderr,"ERROR: Interface %s not found in stats table\n",port);
            exit(-1);
        }

        pthread_mutex_lock(&mutex);
        founded->sent_bytes = founded->sent_bytes + sent_bytes;
        founded->sent_frames = founded->sent_frames + 1;
        pthread_mutex_unlock(&mutex);

    }
}

/** Posle boradcast */
void send_broadcast(const u_char *packet,const struct pcap_pkthdr *header,char *incoming_port){

    int i;

    #ifdef DEBUG
    printf("Posielam broadcast, ktory prisiel z rozhrania %s...\n",incoming_port);
    #endif

    for(i = 0; i < HASH_LENGTH; i++){

        /* ak neobsahuje ziadny zaznam */
        if(stat_table_t[i] == NULL) continue;

        /* port na ktory sa posiela je zhodny s odosialajucim portom, netreba posielat */
        if(stat_table_t[i]->port == incoming_port) {
            #ifdef DEBUG
                printf("Port %s sa zhoduje s portom %s, neposielam unicast\n",
                       stat_table_t[i]->port,incoming_port);
            #endif
            continue;
        }

        #ifdef DEBUG
            printf("Posielam cez port: %s\n",stat_table_t[i]->port);
        #endif

        send_unicast(packet,header,stat_table_t[i]->port);
    }

    #ifdef DEBUG
    printf("\n");
    #endif
}

/** Posle multicast packet na vsetky rozhrania skupiny */
void send_multicast(const u_char *packet,const struct pcap_pkthdr *header,uint32_t address, char *incoming_port){

    struct igmp_group_table *group;

    pthread_mutex_lock(&mutex_igmp);
    /* najdi skupinu */
    group = find_group(address);
    pthread_mutex_unlock(&mutex_igmp);

    /* ak skupina neexistuje, tak preposli na port queriera */
    if(group == NULL){
        #ifdef DEBUG
            printf("Packet pre multicast skupinu ");
            print_ip_address(address);
            printf(" nebol odoslany, skupina neexistuje\n");
        #endif

        if(igmp_querier_port != NULL){
            #ifdef DEBUG
                printf("Preposielam na rozhranie queriera %s\n",igmp_querier_port);
            #endif
            send_unicast(packet,header,igmp_querier_port);
        }

        return;
    }

    /* ak bola skupina vymazana, tak preposli na port queriera*/
    if(group->deleted == 1){
        if(igmp_querier_port != NULL){
            #ifdef DEBUG
                printf("Preposielam na rozhranie queriera %s\n",igmp_querier_port);
            #endif
            send_unicast(packet,header,igmp_querier_port);
        }
        return;
    }


    struct igmp_host *hosts;

    for(hosts = group->igmp_hosts; hosts != NULL; hosts = hosts->next){
        /* neposielaj na rozhranie z ktoreho sprava prisla, alebo ak bol clen zmazany */
        if(strcmp(hosts->port,incoming_port) || hosts->deleted == 1) continue;

        #ifdef DEBUG
            printf("Posielam multicast paket na rozhranie %s\n",hosts->port);
        #endif
        send_unicast(packet,header,hosts->port);
    }

    return;
}

/** Zisti mac adresu daneho rozhrania */
u_int8_t *get_mac_adress(char* port){

    libnet_t *l = libnet_init(LIBNET_LINK, port, errbuf);
    if ( l == NULL ) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        exit(-1);
    }

    struct libnet_ether_addr *mac_addr = libnet_get_hwaddr(l);
    libnet_destroy(l);

    return mac_addr->ether_addr_octet;
}

/** Obsluhuje prikazy zadane uzivatelom */
void user_input(){

    char user_choice[10];

    for(;;){
        printf("switch> ");
        scanf("%s",user_choice);
        if(strlen(user_choice) > 10) continue;

        if(strcmp(user_choice,"cam") == 0){
            print_cam_table();
            printf("\n");
        }else if(strcmp(user_choice,"stat") == 0){
            print_cam_table_stats();
            printf("\n");
        }else if(strcmp(user_choice,"igmp") == 0){
            print_igmp_table();
            printf("\n");
        }else if(strcmp(user_choice,"quit") == 0){
            quit_switch();
        }else{
            printf("switch: %s: command not found\n",user_choice);
        }
    }
}

/** Zatvori vsetky ether rohrania a ukonci switch */
void quit_switch(){

    int i,j;

    //ukonci thready pre jednotlive rozhrania
    for(j = 0; j < counter; j++){
        if(pthread_cancel(threads[j]) != 0){
            fprintf(stderr,"Chyba pri ukoncovani\n");
            exit(EXIT_FAILURE);
        }
    }

    //ukonci thread pre kontrolu mac tabulky
    if(pthread_cancel(thread_checker) != 0 ){
        fprintf(stderr,"Chyba pri ukoncovani\n");
        exit(EXIT_FAILURE);
    }

    //ukonci thread pre zadavanie vstupu
    if(pthread_cancel(thread_user_input) != 0){
        fprintf(stderr,"Chyba pri ukoncovani\n");
        exit(EXIT_FAILURE);
    }

    //uzatvori rozhrania
    for(i = 0; i < HASH_LENGTH; i++){

        //ak neobsahuje ziadny zaznam, tak preskoc index
        if(stat_table_t[i] == NULL) continue;

        pcap_close(stat_table_t[i]->handler);

    }

    exit(EXIT_SUCCESS);
}

/** Postara sa o spracovanie igmp packetu */
void process_igmp_packet(const u_char *packet,struct ether_header *ether,
                         struct ip_header_def *ip, char *incoming_port,
                         const struct pcap_pkthdr *header){

    u_int ip_len = IP_HL(ip)*4;/* velost ip paketu */


    struct igmp_header *igmp_t = (struct igmp_header *)(packet + ETHERNET_SIZE + ip_len);

    /* paket posiela querier zisti port na ktorom sa nachadza */
    if(igmp_t->igmp_type == IGMP_MEMBERSHIP_QUERY){
        #ifdef DEBUG
            printf("IGMP querier port: %s\n", incoming_port);
            printf("IGMP group address: ");
            print_ip_address(igmp_t->igmp_gaddr);
            printf("\n");
            printf("IGMP dest address: %x - ",ip->ip_daddr);
            print_ip_address(ip->ip_daddr);
            printf("\n");
            printf("Hash: %d\n",make_address_hash(igmp_t->igmp_gaddr));
        #endif

        /* ulozi do global premmenej port na ktorom je querier */
        igmp_querier_port = incoming_port;

        /* GENERAL QUERY = posli na vsetky rozhrania */
        if(igmp_t->igmp_gaddr == IGMP_GENERAL_QUERY){
            #ifdef DEBUG
            printf("IGMP general query\n");
            #endif

            /* posli broadcast na vsetky rozhrania a cakaj na odpoved */
            send_broadcast(packet,header,incoming_port);
            return;
        }else { /* group specific query */
            /* posle paket vsetkym v danej skupine*/

            /* najdi skupinu v zozname */
            pthread_mutex_lock(&mutex_igmp);
            struct igmp_group_table *founded = find_group(igmp_t->igmp_gaddr);
            pthread_mutex_unlock(&mutex_igmp);

            /* skupina v zozname neexistuje */
            if(founded == NULL || founded->deleted == 1){
                #ifdef DEBUG
                printf("IGMP skupina s adresou ");
                print_ip_address(igmp_t->igmp_gaddr);
                printf(" neexistuje\n");
                #endif
                return;
            }

            struct igmp_host *hosts = founded->igmp_hosts;

            while(hosts != NULL){

                /* clen skupiny nie je "zmazany" */
                if(hosts->deleted == 0){
                    #ifdef DEBUG
                    printf("Posielam IGMP query na port %s\n",hosts->port);
                    #endif

                    /* posle na vsetky porty v skupine */
                    send_unicast(packet,header,hosts->port);

                    hosts = hosts->next;
                }
            }
        }

        return;
    }

    /* MEMBERSHIP REPORT */
    if(igmp_t->igmp_type == IGMP_MEMBERSHIP_REPORT_V1 ||
       igmp_t->igmp_type == IGMP_MEMBERSHIP_REPORT_V2 ||
       igmp_t->igmp_type == IGMP_MEMBERSHIP_REPORT_V3){

        if(igmp_querier_port == NULL){
            #ifdef DEBUG
            printf("IGMP querier neexistuje, nemozem poslat membership report\n");
            #endif
            return;
        }

        /* pri kazdom reporte skontroluje ci neobsahuje neaktivnych hostov */
        igmp_table_check();

        uint32_t gaddr;

        if(igmp_t->igmp_type == IGMP_MEMBERSHIP_REPORT_V3){
            struct igmpv3_report *igmp_report = (struct igmpv3_report *)(packet + ETHERNET_SIZE + ip_len);
            gaddr = igmp_report->group_rec.group;
        }else{
            gaddr = igmp_t->igmp_gaddr;
        }


        /* preposli paket na rozhranie querieru */
        send_unicast(packet,header,igmp_querier_port);


        /* pri genral query treba preposlat paket aj na rozhrania ostatnych hostov */
        pthread_mutex_lock(&mutex_igmp);
        struct igmp_group_table *group = find_group(gaddr);
        pthread_mutex_unlock(&mutex_igmp);


        /* Zisti port a group adresu a uloz do group_table */
        pthread_mutex_lock(&mutex_igmp);

        /* vloz novu alebo uprav skupinu resp. clena skupiny */
        add_group(gaddr,incoming_port);

        pthread_mutex_unlock(&mutex_igmp);

        int i;
        /* skupina este neexistuje, takze bol general query */
        if(group == NULL || group->deleted == 1){
            /* preposli na vsetky rozhrania okrem querieru */
            for(i = 0; i < HASH_LENGTH; i++){

                /* ak neobsahuje ziadny zaznam */
                if(stat_table_t[i] == NULL) continue;

                /* na querier uz bolo poslane a na port z ktoreho sa posiela uz neposialaj */
                if(stat_table_t[i]->port == incoming_port || stat_table_t[i]->port == igmp_querier_port) {
                    continue;
                }

                #ifdef DEBUG
                    printf("Posielam membership report na hosta: %s\n",stat_table_t[i]->port);
                #endif

                send_unicast(packet,header,stat_table_t[i]->port);
            }
        }




        /* pri rovnako preposli aj na rozhrania clenov skupiny */
        /* TREBA ZISTIT CI TREBA PREPOSIELAT AJ OSTATNYM CLENOM SKUPINY *
        struct igmp_host *tmp_hosts;
        for(tmp_hosts = find_group(gaddr); tmp_hosts != NULL; tmp_hosts = tmp_hosts->next){

            // neposielaj na port z ktoreho report prisiel a ak je host zmazany
            if(strcmp(tmp_hosts->port,incoming_port) == 0 || tmp_hosts->deleted == 1){
                continue;
            }

            #ifdef DEBUG
            printf("Preposielam memebership report na rozhranie clena %s\n",tmp_hosts->port);
            #endif


            send_unicast(packet,header,tmp_hosts->port);
        }
        */
        return;
    }


    /* IGMP REPORT V3 *
    if(igmp_t->igmp_type == IGMP_MEMBERSHIP_REPORT_V3){

        struct igmpv3_report *igmp_report = (struct igmpv3_report *)(packet + ETHERNET_SIZE + ip_len);

        if(igmp_querier_port == NULL){
            #ifdef DEBUG
            printf("IGMP querier neexistuje, nemozem poslat membership report\n");
            #endif
            return;
        }

        /* Zisti port a group adresu a uloz do group_table *
        pthread_mutex_lock(&mutex_igmp);

        /* vloz novu alebo uprav skupinu resp. clena skupiny*
        add_group(igmp_report->group_rec.group,incoming_port);

        pthread_mutex_unlock(&mutex_igmp);

        /* preposli paket na rozhranie querieru *
        send_unicast(packet,header,igmp_querier_port);

        return;
    }
    */

    /* IGMP LEAVE */
    if(igmp_t->igmp_type == IGMP_LEAVE_GROUP_V2){

        /* Odstrani clena zo skupiny */
        pthread_mutex_lock(&mutex_igmp);
        if(remove_host(igmp_t->igmp_gaddr,incoming_port) == 0){
            #ifdef DEBUG
                printf("Clena skupiny ");
                print_ip_address(igmp_t->igmp_gaddr);
                printf(" sa nepodarilo odstranit\n");
            #endif

        }
        pthread_mutex_unlock(&mutex_igmp);

        /* preposli leave paket na rozhranie querieru */
        send_unicast(packet,header,igmp_querier_port);

        return;
    }

}

/** Na vystup vypise ip adresu */
void print_ip_address(uint32_t ip_address){

    unsigned char *octet = convert_ip(ip_address);

    printf("%d.%d.%d.%d",octet[0],octet[1],octet[2],octet[3]);
}


/** Zobrazi igmp tabulku */
void print_igmp_table(){
    int i;
    struct igmp_group_table *founded;

    printf("\n---------------IGMP TABLE---------------\n");
    printf("GroupAddr\tIfaces\t\n");
    pthread_mutex_lock(&mutex_igmp);
    for(i = 0; i < HASH_LENGTH;i++){
        /* prechadzaj len tie kde su nejake hodnoty */
        if(igmp_groups[i] == NULL) continue;
        if(igmp_groups[i]->deleted == 1) continue;

        /* ak sa v jednom indexe nachadza viac hodnot, tak vypis*/
        if(igmp_groups[i]->next != NULL){
            #ifdef DEBUG
            printf("\nkolizne pre hash %i\n",i);
            #endif
            //postupne vypisuj
            for(founded = igmp_groups[i]; founded != NULL; founded = founded->next){
                print_ip_address(founded->group_addr);
                printf("\t");
                printf("*%s,",igmp_querier_port);
                print_hosts(igmp_groups[i]);

            }
            #ifdef DEBUG
            printf("koniec kolizne\n\n");
            #endif
        } else {/* inak vypisuj len hodnoty na indexoch */

            print_ip_address(igmp_groups[i]->group_addr);
            printf("\t");
            printf("*%s,",igmp_querier_port);
            print_hosts(igmp_groups[i]);
        }
    }
    pthread_mutex_unlock(&mutex_igmp);
    printf("-----------------------------------------\n");
}

/** Vypise vsetkych clenov igmp multicast skupiny */
inline void print_hosts(struct igmp_group_table *group){

    struct igmp_host *hosts;
    for(hosts = group->igmp_hosts; hosts != NULL; hosts = hosts->next){
        /* preskoc odstranene zaznamy */
        if(hosts->deleted == 1) continue;

        /* je to posledny zaznam */
        if(hosts->next == NULL){
            printf("%s",hosts->port);
        }else{
            printf("%s,",hosts->port);
        }
    }
    printf("\n");
}

/** Zisti ci sa jedna o multicast adresu */
int multicast_type(uint32_t address){

    unsigned char *ip = convert_ip(address);

    /* adresy z rozsahu 224.0.0.0/24 */
    if(ip[0] == MULTICAST_START && ip[1] == 0 && ip[2] == 0){
        return MULTICAST_TYPE_ALL;
    }

    /* vsetky adresy v rozsahu 224 - 239*/
    if(ip[0] >= MULTICAST_START && ip[0] <= MULTICAST_END){
        return MULTICAST_TYPE_GROUP;
    }


    /* nie je multicast*/
    return 0;
}

/** Skontroluje aktivitu clenov jednotlivych skupin a neaktivnych odstrani */
void igmp_table_check(){

    int i;
    struct igmp_group_table *founded;

    pthread_mutex_lock(&mutex_igmp);

        #ifdef DEBUG
            printf("\nIGMP table age checking...\n");
        #endif
        for(i = 0; i < HASH_LENGTH;i++){
            /* prechadzaj len tie kde su nejake hodnoty */
            if(igmp_groups[i] == NULL) continue;
            if(igmp_groups[i]->deleted == 1) continue;

            /* skupina musi obsahovat nejaky zaznam */
            if(igmp_groups[i]->next != NULL){

                for(founded = igmp_groups[i]; founded != NULL; founded = founded->next){
                    struct igmp_host *hosts;
                    for(hosts = founded->igmp_hosts; hosts != NULL; hosts = hosts->next){
                        /* preskoc odstranene zaznamy */
                        if(hosts->deleted == 1) continue;

                        /* "odstrani" hosta zo skupiny */
                        if(time(NULL) - hosts->age >= VALID_AGE){
                            remove_host(founded->group_addr,hosts->port);
                        }
                    }
                }
            } else {
                struct igmp_host *hosts;
                for(hosts = igmp_groups[i]->igmp_hosts; hosts != NULL; hosts = hosts->next){
                        /* preskoc odstranene zaznamy */
                        if(hosts->deleted == 1) continue;

                        /* "odstrani" hosta zo skupiny */
                        if(time(NULL) - hosts->age >= VALID_AGE){
                            remove_host(igmp_groups[i]->group_addr,hosts->port);
                        }
                    }
            }
        }

    pthread_mutex_unlock(&mutex_igmp);
}
