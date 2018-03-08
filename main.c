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

		printf("%s\n",packet);
		
		printf("\n\n");
		frame_num++;
	}

	printf("fin\n");

	//fclose(fp);
	pcap_close(p);
}
