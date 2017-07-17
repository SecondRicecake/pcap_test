#include <pcap.h>
#include <stdio.h>
#define DMACLEN 6
#define SMACLEN 6
#define ETHLEN DMACLEN + SMACLEN + 2
#define IPLEN ETHLEN +20
#define TCPLEN IPLEN +20

	 int main(int argc, char *argv[])
	 {
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression THIS ONE ONLY CATCHES PORT HTTP*/
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */
	 	int pause;


		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
		while(1){
		pause = pcap_next_ex(handle, &header, &packet);
		if (pause == 0)
			continue;
		
		/* Print its length */
		printf("\n\n");
		printf("Jacked a packet with length of [%d]\n", header->len);
		printf("\n\n");
		
		/*check if IPv4 and TCP*/
		if ((*(packet+23)!=0x6||*(packet+12)!=0x8&&*(packet+13)!=0x0)){
			printf("Could not find IPv4 and TCP.\n");
			continue;
		}

		/*Print its Destination Address*/
		printf("ethernet header\n");
		printf("destination address: ");
		for (int i=0; i < (DMACLEN); i++){
			printf("%02x ", *(packet+i));
		}
		/*Print its Source Address*/
		printf("\n");
		printf("source address: ");
		for (int i=DMACLEN; i<(DMACLEN+SMACLEN); i++){
			printf("%02x ", *(packet+i));
		}
		/*Print its type*/
		printf("\n");
		printf("type: ");
		for (int i=DMACLEN+SMACLEN; i<(ETHLEN); i++){
			printf("%02x ",*(packet+i));
		}
		/*Print its Source IP*/
		printf("\n\n");
		printf("ip header\n");
		printf("source IP: ");
		for (int i=ETHLEN+12; i<(ETHLEN+16); i++){
			if (*(packet+i) != 0){
				printf("%d ",*(packet+i));
			}
		}
		/*Print its Destination IP*/
		printf("\n");
		printf("destination IP: ");
		for (int i=ETHLEN+16; i<(ETHLEN+20); i++){
			printf("%d ",*(packet+i));
		}
		/*Print its TCP Source Port*/
		printf("\n\n");
		printf("TCP header\n");
		printf("TCP source port: ");
		for (int i=IPLEN; i<(IPLEN+2); i++){
			printf("%d ",*(packet+i));
		}
		/*Print its TCP Destination Port*/
		printf("\n");
		printf("TCP destination port: ");
		for (int i=IPLEN+2; i<(IPLEN+4); i++){
			printf("%d ",*(packet+i));
		}
		/*Print its Data*/
		printf("\n");
		printf("DATA: ");
		for (int i=TCPLEN; i<(header->len); i++){
			printf("%02x ",*(packet+i));
		}	
		}
		/* And close the session */
		pcap_close(handle);
		
		return(0);
	 }


//gcc pcap_test.c -lpcap -o pcap
//./pcap
//>>Device: wlp1s0
//
//
//sudo ./pcap