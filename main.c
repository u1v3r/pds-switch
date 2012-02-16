#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAXBYTES2CAPTURE 2048
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

void got_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);

struct ethernet{
    u_char dest[ETHER_ADDR_LEN];
    u_char source[ETHER_ADDR_LEN];
    u_short type_length;
};

int main(int argc, char *argv[] ){

 pcap_t *handle = NULL;
 char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;
 memset(errbuf,0,PCAP_ERRBUF_SIZE);
 struct bpf_program fp;
 bpf_u_int32 net;
 bpf_u_int32 mask;
 char filer_exp[] = "";
 pcap_if_t *alldevs,*d;


 if( argc > 1){
    device = argv[1];
 }
 else{

    if ( (device = pcap_lookupdev(errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        return 2;
    }
 }

 printf("Opening device %s\n", device);

 /* Open device in promiscuous mode */
 if ( (handle = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    return 2;
 }

 if( pcap_lookupnet(device,&net,&mask,errbuf) == -1){
    fprintf(stderr,"ERROR: Cant get netmask for device %s\n",device);
    net = 0;
    mask = 0;
    return 2;
 }

if(pcap_compile(handle,&fp,filer_exp,0,net) == -1){
    fprintf(stderr,"ERROR: Cant compile %s\n",filer_exp);
    return 2;
}

if(pcap_setfilter(handle,&fp) == -1){
    fprintf(stderr,"ERROR: Cant install filter %s\n",filer_exp);
    return 2;
}

if( (pcap_findalldevs(&alldevs,errbuf)) == -1){
    fprintf(stderr,"ERROR: Cant find devices");
    return 2;
}

for(d=alldevs; d; d=d->next){
    //if(d->addresses == NULL) continue;

    printf("device: %s,",d->name);
    printf("address: %d,",d->addresses->addr);
    printf("desc: %s,",d->description);
    printf("flag: %d\n",d->flags);
}



//pcap_loop(handle,-1,got_packet,NULL);
pcap_close(handle);

return 0;

}

void got_packet(u_char *args,const struct pcap_pkthdr *header, const u_char *packet){

    const struct ethernet *eth;
    eth = (struct ethernet*)(packet);


    u_char *source_mac,*dest_mac;
    source_mac = eth->source;
    dest_mac = eth->dest;
    int i = ETHER_ADDR_LEN;

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



   // printf("source: %d\n",eth->source[0]);
   // printf("type_length %d\n",eth->type_length);

}

/* EOF*/
