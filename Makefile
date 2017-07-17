#Makefile
all: pcap_test


pcap_test: pcap_test.o 
	gcc -o pcap pcap_test.c -lpcap 

clearn:
	rm -f pcap_test
	rm -f *.o 