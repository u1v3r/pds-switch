#!/bin/bash

gcc -lpcap -pthread -lnet main.c -o pds-switch
#gcc -Wall -c -pg -lpcap -pthread -lnet main.c
#gcc -Wall -pg -lpcap -pthread -lnet main.o
