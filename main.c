/**
 * @file main.c
 * @brief main source to analize pcap
 * @author khwarizmi
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<pcap.h>

#include<netinet/if_ether.h>

#define SIZE 1024

int main(int argc, char* argv[]){
  if (argc  != 2) {
		fprintf(stderr, "useage ./main [filename]\n");
		exit(1);
	}

//  FILE *fp;
//	fp = fopen(argv[1], "r");
//	if (!fp){
//		perror(argv[1]);
//	}
	
	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE];

	//p = pcap_open_offline(argv[1], errbuf);
	p = pcap_open_offline_with_tstamp_precision(argv[1], PCAP_TSTAMP_PRECISION_NANO, errbuf);

	if (!p){
		perror(argv[1]);
		exit(1);
	}
	
	int frame_num = 1;
	u_char *packet;
	//memset(packet, 0, strlen(packet));
	struct pcap_pkthdr pkthdr;
	while ((packet = pcap_next(p, &pkthdr))/* != NULL*/){
		printf("*** frame%d ***\n", frame_num);
		printf("packet length: %d byte\n", pkthdr.caplen);

		//printf("%x\n",packet[0]);

		struct ether_header *eth;
		int size = pkthdr.caplen;
		eth = (struct ether_header *) packet;
		//increment
		packet += sizeof(struct ether_header);
		size -= sizeof(struct ether_header);

		printf("dest: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
		printf("source: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);


		printf("\n\n");
		frame_num++;
	}

	printf("fin\n");

	//fclose(fp);
	pcap_close(p);
}
