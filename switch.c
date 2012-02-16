#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <sys/types.h>

#include "switch.h"
#include "cam_table.c"

#define PROMISCUOUS_MODE 1
#define NORMAL_MODE 0
#define DEFAULT_PORTS_COUNT 10

static char errbuf[PCAP_ERRBUF_SIZE];       //error buffer
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Inicializuje switch
 */
void init_switch(){

    pthread_t *threads;
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
        if(i % threads_count == 0) {
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

        //pocet vytvorenych vlakien
        counter++;
    }

    for(j = 0; j < counter;j++){
        pthread_join(threads[j],NULL);
    }

}

void *open_device(void *name){

    pcap_t *handler;
    const char *device_name = (char *) name;
    #ifdef DEBUG
    printf("Handler adress for device %s: %d\n",device_name,&handler);
    printf("Openning device %s\n",device_name);
    #endif
    if((handler = pcap_open_live(device_name,MAXBYTES2CAPTURE,PROMISCUOUS_MODE,512,errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(2);
    }

    pcap_loop(handler,-1,process_packet,(u_char *) name);
}

/**
 * Vlozi udaj do CAM tabulky a posle ho na eth rozhrania
 */
void process_packet(u_char *args,const struct pcap_pkthdr *header, const u_char *packet){

    struct ether_header *ether;
    ether = (struct ether_header*)(packet);

    char mac[200];
    u_char *source_mac,*dest_mac;
    source_mac = ether->ether_shost;
    dest_mac = ether->ether_dhost;

    #ifdef DEBUG
    int i = ETHER_ADDR_LEN;
    printf("DEVICE: %s\n",args);
    printf(" Source Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*source_mac++);
    }while(--i>0);
    printf("\n");

    i = ETHER_ADDR_LEN;
    printf(" Dest Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*dest_mac++);
    }while(--i>0);

    printf("\n");
    #endif

    pthread_mutex_lock(&mutex);
    //printf("MAC: %s\n",ether->ether_dhost);
    //printf("PORT: %s\n",*args);
    //add_value(ether->ether_dhost,args);
    pthread_mutex_unlock(&mutex);

}
