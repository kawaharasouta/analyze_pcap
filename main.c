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

//#include<netinet/in.h>
#include<arpa/inet.h>

#include<netinet/if_ether.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>

#define SIZE 1024

u_int16_t swap_16_t(u_int16_t num);
u_int32_t swap_32_t(u_int32_t num);
char* print_mac_addr(u_int8_t *mac_addr, char *mac, size_t size);
char* print_ip_addr(u_int8_t *ip_addr, char *ip, size_t size);

void analyze_arp(u_char *packet, int size);
void arp_request(struct ether_arp *eth_arp);
void arp_reply(struct ether_arp eth_arp);
void analyze_ip(u_char *packet, int size);
void analyze_icmp(u_char *packet, int size);
void analyze_tcp(u_char *packet, int size);
void analyze_udp(u_char *packet, int size);

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

		//printf("dest: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
		//printf("source: %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
		char mac[18] = {0};
		printf("dest: %s\n", print_mac_addr(eth->ether_dhost, mac, sizeof(mac)));
		printf("source: %s\n", print_mac_addr(eth->ether_shost, mac, sizeof(mac)));
		printf("ether type: %04x\n", eth->ether_type);
		
		//u_int16_t head, tail;
		//head = (eth->ether_type & 0xff00) >> 8;
		//tail = (eth->ether_type & 0x00ff) << 8;
		//u_int16_t type_num = ((eth->ether_type & 0xff00) >> 8) + ((eth->ether_type & 0x00ff) << 8);
		u_int16_t type_num = swap_16_t(eth->ether_type);

		printf("ether type true: %04x\n", type_num);

		if (type_num == ETHERTYPE_ARP){
			printf("arp\n");
			analyze_arp(packet, size);
		}
		else if (type_num == ETHERTYPE_IP) {
			printf("ip\n");
			analyze_ip(packet, size);
		}
		else if (type_num == ETHERTYPE_IPV6){
			printf("ipv6\n");

		}


		printf("\n\n");
		frame_num++;
	}

	printf("fin\n");

	//fclose(fp);
	pcap_close(p);
}


//*****utilitys*****
u_int16_t swap_16_t(u_int16_t num){
	return (u_int16_t)((num & 0xff00) >> 8) + ((num & 0x00ff) << 8);
}

u_int32_t swap_32_t(u_int32_t num){
	return (u_int32_t)(((num & 0xff000000) >> 24) + ((num & 0x00ff0000) >> 8) + ((num & 0x0000ff00) << 8) + ((num & 0x000000ff) <<24));
}

char* print_mac_addr(u_int8_t *mac_addr, char *mac, size_t size){
	//printf("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_arp->arp_sha[0], eth_arp->arp_sha[1], eth_arp->arp_sha[2], eth_arp->arp_sha[3], eth_arp->arp_sha[4], eth_arp->arp_sha[5]);
	snprintf(mac, size, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
	return mac;
}

char* print_ip_addr(u_int8_t *ip_addr, char *ip, size_t size){
	snprintf(ip, size, "%d.%d.%d.%d", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
	return ip;
}


//*****func to analyze*****
void analyze_arp(u_char *packet, int size){
	struct ether_arp *eth_arp;
	eth_arp = (struct ether_arp *) packet;

	//increment
	packet += sizeof(struct ether_arp);
	size -= sizeof(struct ether_arp);

	printf("ARP\n");

	u_int16_t hrd = swap_16_t(eth_arp->ea_hdr.ar_hrd);
	printf("hard type: %x\n", hrd);

	u_int16_t proto = swap_16_t(eth_arp->ea_hdr.ar_pro);
	printf("proto type: %x\n", proto);

	u_int16_t op = swap_16_t(eth_arp->ea_hdr.ar_op);
	printf("arp operation: %x\n", op);

//	if (op == ARPOP_REQUEST){
//
//	}
//	else if (op == ARPOP_REPLY){
//
//	}

	switch (op){
		case ARPOP_REQUEST:
			printf("arp_request\n");
			arp_request(eth_arp);
			break;
		case ARPOP_REPLY:
			printf("arp_reply");
			//arp_reply();
			break;
		default:
			break;
	}
}

void arp_request(struct ether_arp *eth_arp){
	//printf("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_arp->arp_sha[0], eth_arp->arp_sha[1], eth_arp->arp_sha[2], eth_arp->arp_sha[3], eth_arp->arp_sha[4], eth_arp->arp_sha[5]);
	char mac[18] = {0};
	char ip[15] = {0};
	printf("Sender MAC address: %s\n", print_mac_addr(eth_arp->arp_sha, mac, sizeof(mac)));
	printf("Sender IP address: %s\n", print_ip_addr(eth_arp->arp_spa, ip, sizeof(ip)));
	printf("Target MAC address: %s\n", print_mac_addr(eth_arp->arp_tha, mac, sizeof(mac)));
	printf("Target IP address: %s\n", print_ip_addr(eth_arp->arp_tpa, ip, sizeof(ip)));
}
void arp_reply(struct ether_arp eth_arp){

}

void analyze_ip(u_char *packet, int size){
	struct ip *ip_hdr;

	ip_hdr = (struct ip *)packet;
	packet += sizeof(struct ip);
	size -= sizeof(struct ip);

	printf("version: %d\n", ip_hdr->ip_v);
	printf("header length: %d (%d byte)\n", ip_hdr->ip_hl, ip_hdr->ip_hl * 4);
	printf("total length: %d\n", swap_16_t(ip_hdr->ip_len));
	printf("identification: 0x%x\n", swap_16_t(ip_hdr->ip_id));
	
	printf("Time to Live: %d\n", ip_hdr->ip_ttl);
	printf("proto: %x\n", ip_hdr->ip_p);

	//char ip[15] = {0};
	//printf("Source: %s\n", print_ip_addr((u_int8_t)ip_hdr->ip_src.s_addr, ip, sizeof(ip)));
	//u_int8_t ip_addr[5] = {0};
	//ip_addr = (u_int8_t *)ip_hdr->ip_src.s_addr;
	//printf("%s", print_ip_addr(ip_addr, ip, sizeof(ip)));
	printf("Source IP Address: %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("Destination IP Address: %s\n", inet_ntoa(ip_hdr->ip_dst));

	switch(ip_hdr->ip_p) {//0?
		case IPPROTO_ICMP://1
			printf("icmp\n");
			//analyze_icmp();
			break;
		case IPPROTO_TCP://6
			printf("tcp\n");
			analyze_tcp(packet, size);
			break;
		case IPPROTO_UDP://17
			printf("udp\n");
			//analyze_udp();
			break;

		default:
			printf("no\n");
			break;
	}

}

void analyze_icmp(u_char *packet, int size){
	struct icmp *icmp_hdr;
	icmp_hdr = (struct icmp *)packet;

}

void analyze_tcp(u_char *packet, int size){
	struct tcphdr *tcp_hdr;
	tcp_hdr = (struct tcphdr *)packet;

	printf("Source Port: %d\n", swap_16_t(tcp_hdr->th_sport));
	printf("Destination Port: %d\n", swap_16_t(tcp_hdr->th_dport));
	printf("Sequence Number: %08x\n", swap_32_t(tcp_hdr->th_seq));
	printf("Sequence Number: %d\n", ntohl(tcp_hdr->th_seq));
	printf("Acknowledgement Number: %08x\n", swap_32_t(tcp_hdr->th_ack));
	printf("Acknowledgement Number: %d\n", ntohl(tcp_hdr->th_ack));
	
}

void analyze_udp(u_char *packet, int size){
	struct icmp *icmp_hdr;
	icmp_hdr = (struct icmp *)packet;

}



