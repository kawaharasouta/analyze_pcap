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

u_int16_t swap_16byte(u_int16_t num);
void analyze_arp(u_char *packet, int size);

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

		printf("Ethernet\n");

		printf("dest: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
		printf("source: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
		printf("ether type: %04x\n", eth->ether_type);
		
		//u_int16_t head, tail;
		//head = (eth->ether_type & 0xff00) >> 8;
		//tail = (eth->ether_type & 0x00ff) << 8;
		//u_int16_t type_num = ((eth->ether_type & 0xff00) >> 8) + ((eth->ether_type & 0x00ff) << 8);
		u_int16_t type_num = swap_16byte(eth->ether_type);

		printf("ether type true: %04x\n", type_num);

		if (type_num == ETHERTYPE_ARP){
			printf("arp\n");
			analyze_arp(packet, size);
		}
		else if (type_num == ETHERTYPE_IP) {
			printf("ip\n");
		}


		printf("\n\n");
		frame_num++;
	}

	printf("fin\n");

	//fclose(fp);
	pcap_close(p);
}


u_int16_t swap_16byte(u_int16_t num){
	return (u_int16_t)((num & 0xff00) >> 8) + ((num & 0x00ff) << 8);
}

void analyze_arp(u_char *packet, int size){
	struct ether_arp *eth_arp;
	eth_arp = (struct ether_arp *) packet;

	//increment
	packet += sizeof(struct ether_arp);
	size -= sizeof(struct ether_arp);

	printf("ARP\n");

	u_int16_t hrd = swap_16byte(eth_arp->ea_hdr.ar_hrd);
	printf("hard type: %x\n", hrd);

	u_int16_t proto = swap_16byte(eth_arp->ea_hdr.ar_pro);
	printf("proto type: %x\n", proto);

	u_int16_t op = swap_16byte(eth_arp->ea_hdr.ar_op);
	printf("arp operation: %x\n", op);

//	if (op == ARPOP_REQUEST){
//
//	}
//	else if (op == ARPOP_REPLY){
//
//	}

	switch (op){
		case ARPOP_REQUEST:
			printf("arp_request\n");i
			arp_request()
			break;
		case ARPOP_REPLY:
			printf("arp_reply");
			arp_reply();
			break;
		default:
			break;
	}
}

void arp_request(){

}
void arp_reply(){

}
