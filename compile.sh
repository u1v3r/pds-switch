#!/bin/bash
rm ./pds-switch
gcc -Wall -lpcap -pthread -lnet main.c igmp_snp.c -o pds-switch
#gcc -Wall -c -pg -lpcap -pthread -lnet main.c
#gcc -Wall -pg -lpcap -pthread -lnet main.o
