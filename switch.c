#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <sys/types.h>
#include <libnet.h>

#include "switch.h"
#include "cam_table.c"

#define PROMISCUOUS_MODE 1
#define NORMAL_MODE 0
#define DEFAULT_PORTS_COUNT 10


/**
 * Inicializuje switch
 */
void init_switch(){

    pthread_t *threads;
    pthread_t thread_checker;

    int threads_count = DEFAULT_PORTS_COUNT;
    pcap_if_t *d,*devices;
    int i,j,counter = 0;


    if( (pcap_findalldevs(&devices,errbuf)) == -1){
        fprintf(stderr,"ERROR: Can't find ethernet devices");
        exit(2);
    }

    //inicializacia pamate pre vlakna
    threads = (pthread_t *) calloc(DEFAULT_PORTS_COUNT,sizeof(pthread_t));
    if(threads == NULL){
        exit(-1);
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
            printf("Memory re-allocation: %d\n",threads_count * sizeof(pthread_t));
            #endif
        }

        #ifdef DEBUG
        printf("device: %s,",d->name);
        //printf("address: %d,",d->addresses);
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
    pthread_join(thread_checker,NULL);

    for(j = 0; j < counter;j++){
        pthread_join(threads[j],NULL);
    }

}

void *open_device(void *name){

    pcap_t *handler;
    const char *device_name = (char *) name;



    /*
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    char filer_exp[] = "";
    */

    #ifdef DEBUG
    printf("Handler adress for device %s: %d\n",device_name,&handler);
    printf("Openning device %s\n",device_name);
    #endif

    if((handler = pcap_open_live(device_name,MAXBYTES2CAPTURE,PROMISCUOUS_MODE,512,errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(2);
    }

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
    if(pcap_setdirection(handler,PCAP_D_IN) == -1){
        fprintf(stderr,"ERROR: Can't set packet capture direction");
    };

    pcap_loop(handler,-1,process_packet,(u_char *) name);
}

/**
 * Vlozi udaj do CAM tabulky a posle ho na eth rozhrania
 */
void process_packet(u_char *args,const struct pcap_pkthdr *header, const u_char *packet){

    struct stat_table *founded;
    struct ether_header *ether;
    ether = (struct ether_header*)(packet);

    u_char source_mac[ETHER_ADDR_LEN],dest_mac[ETHER_ADDR_LEN];
    memcpy(source_mac,ether->ether_shost,ETHER_ADDR_LEN);
    memcpy(dest_mac,ether->ether_dhost,ETHER_ADDR_LEN);

    #ifdef DEBUG
    int i = ETHER_ADDR_LEN;
    int j = 0;

    printf("-------------------------------------\n");
    printf("DEVICE: %s\n",args);
    printf("Source Address:  ");
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
    add_value(source_mac,args);
    //zapise statistiky
    founded = find_stat_value(args);
    founded->recv_frames = founded->recv_frames + 1;
    founded->recv_bytes = founded->recv_bytes + header->len;
    pthread_mutex_unlock(&mutex);
}

struct stat_table *find_stat_value(char *port){

    struct stat_table *founded;

    founded = stat_table_t[make_hash(port)];

    if(founded == NULL) return NULL;

    return founded;
}

struct stat_table *add_stat_value(char *port){

    struct stat_table *add;

    unsigned hash_value = make_hash(port);
    add = (struct stat_table *) malloc(sizeof(*add));
    add->port = port;
    add->recv_bytes = 0;
    add->recv_frames = 0;
    add->sent_bytes = 0;
    add->sent_frames = 0;
    stat_table_t[hash_value] = add;

    return add;
};
