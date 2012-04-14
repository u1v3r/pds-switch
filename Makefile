# Makefile pre pre projekt na PDS

ONAME=switch
CC=gcc
CFLAGS=-Wall -w -lpcap -pthread -lnet main.c igmp_snp.c -o $(ONAME)


build:
	$(CC) $(CFLAGS)
clean:
	rm -f $(ONAME)
