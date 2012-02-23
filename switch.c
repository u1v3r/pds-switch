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
            printf("Memory re-allocation: %li\n",threads_count * sizeof(pthread_t));
            #endif
        }

        #ifdef DEBUG
        printf("device: %s,",d->name);
        //printf("address: %d,",d->addresses->addr);
        printf("desc: %s,",d->description);
        printf("flag: %d\n",d->flags);
        #endif


        //vytvorenie samostatného vlákna pre každé rozhranie
        pthread_create(&threads[i++],NULL,open_device,(void *) d->name);

        //vlozenie rozhrani do stat tabulky
        add_stat_value(d->name);

        //pocet vytvorenych vlakien
        counter++;
    }

    #ifdef DEBUG
    printf("Threads count: %d\n", counter);
    #endif

    //vlakno prechadza tabulku a ak obsahuje stary zaznam tak ho odstrani
    pthread_create(&thread_checker,NULL,cam_table_age_checker,NULL);

    //zachytava prikazy uzivatela
    pthread_create(&thread_user_input,NULL,user_input,NULL);

    pthread_join(thread_checker,NULL);
    pthread_join(thread_user_input,NULL);

    for(j = 0; j < counter;j++){
        pthread_join(threads[j],NULL);
    }

}

/** Otvori zadane rozhrania a zacne na nom odchytavat pakety*/
void *open_device(void *name){

    struct stat_table *found;  //treba do struktury ulozit deskriptor rozhrania

    /*
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    char filer_exp[] = "";
    */
    //vyber z tabulky rozhranie
    found = find_stat_value((char *)name);
    if((found->handler = pcap_open_live((const char *)name,MAXBYTES2CAPTURE,
                                        PROMISCUOUS_MODE,512,errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    #ifdef DEBUG
    printf("Handler adress for device %s: %d\n",name,found->handler);
    printf("Openning device %s\n",name);
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

    //odchytavaj len prichadzajuce pakety
    if(pcap_setdirection(found->handler,PCAP_D_IN) == -1){
        fprintf(stderr,"ERROR: Can't set packet capture direction");
        exit(EXIT_FAILURE);
    };

    //spracuj prichodzie pakety pomocou process_packet
    pcap_loop(found->handler,-1,process_packet,(u_char *) name);
}

/**
 * Spracuje prichadzajuci paket, vlozi do CAM tabulky mac adresu
 * a posle ho na eth rozhrania
 */
void process_packet(u_char *incoming_port,const struct pcap_pkthdr *header, const u_char *packet){

    struct stat_table *founded;
    struct ether_header *ether;
    ether = (struct ether_header*)(packet);

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

    //vlozi mac adresu rozhrania do cam tabulky
    add_value(source_mac,(char *)incoming_port);
    //zapise statistiky
    founded = find_stat_value((char *)incoming_port);
    founded->recv_frames = founded->recv_frames + 1;
    founded->recv_bytes = founded->recv_bytes + header->len;

    pthread_mutex_unlock(&mutex);


    //ak je broadcast, tak posli broadcast
    if (make_ether_hash(dest_mac) == BROADCAST){
        #ifdef DEBUG
        printf("\n\n BROADCAST \n\n");
        #endif
        send_broadcast(packet,header,(char *)incoming_port);
        return;
    }

    //ak je cielovym portom port na switch, tak neposielaj dalej
    if(comapre_mac(get_mac_adress((char *)incoming_port),dest_mac)){
        #ifdef DEBUG
        printf("Cielova mac adresa paketu sa zhoduje s adresou portu %s, neposielam paket dalej:\n ",incoming_port);
        print_mac_adress(get_mac_adress((char *)incoming_port));
        printf("==");
        print_mac_adress(dest_mac);
        printf("\n");
        #endif
        //return;
    }

    //ak sa cielova mac nachadza v cam table, tak posli na dany port
    pthread_mutex_lock(&mutex);
    struct cam_table *cam_table_found = find_packet_value(dest_mac);
    pthread_mutex_unlock(&mutex);

    //mac adresa sa nachadza v cam tabulke
    if(cam_table_found != NULL){

        //treba posielat len pakety, ktore danej adrese patria
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

        /* treba najst spravny deskriptor a
         * poslat unicast na dane rozhranie
         */
        send_unicast(packet,header,cam_table_found->port,
                     find_stat_value(cam_table_found->port)->handler);


    }
    else{//rozhranie sa v cam tabulke nenechacza

        #ifdef DEBUG
        printf("Rozhranie som pre adresu ");
        print_mac_adress(dest_mac);
        printf("nenasiel\n");
        #endif

        send_broadcast(packet,header,(char *)incoming_port);
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
};

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
void send_unicast(const u_char *packet,const struct pcap_pkthdr *header,char *port,pcap_t *handler){

    struct stat_table *founded;

    //posle na otvorene rozhranie paket
    int sent_bytes = pcap_inject(handler,packet,header->len);

    //ak prijalo zapis statistiky
    if(sent_bytes == -1){
        fprintf(stderr,"Note: Packet not send  - %s\n",pcap_geterr(handler));

    }else{
        //zapise statistiky
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

        //ak neobsahuje ziadny zaznam
        if(stat_table_t[i] == NULL) continue;

        //port na ktory sa posiela je zhodny s odosialajucim portom, netreba posielat
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

        send_unicast(packet,header,stat_table_t[i]->port,stat_table_t[i]->handler);
    }

    #ifdef DEBUG
    printf("\n");
    #endif
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

/** Zachytava prikazy zadane uzivatelom */
void user_input(){

    char user_choice[10];

    for(;;){
        printf("switch> ");
        scanf("%s",&user_choice);
        if(strlen(user_choice) > 10) continue;

        if(strcmp(user_choice,"cam") == 0){
            print_cam_table();
            printf("\n");
        }else if(strcmp(user_choice,"stat") == 0){
            print_cam_table_stats();
            printf("\n");
        }else if(strcmp(user_choice,"igmp") == 0){
            printf("igmp\n");
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
