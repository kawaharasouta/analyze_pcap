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

#include"utilitys.h"
#include"analyze.h"


void analyze_arp(u_char *packet, int size){
	struct ether_arp *eth_arp;
	eth_arp = (struct ether_arp *) packet;

	//increment
	packet += sizeof(struct ether_arp);
	size -= sizeof(struct ether_arp);

	//printf("ARP\n");

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
			printf("--arp_request--\n");
			arp_request(eth_arp);
			break;
		case ARPOP_REPLY:
			printf("--arp_reply--");
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
			printf("---ICMP---\n");
			//analyze_icmp();
			break;
		case IPPROTO_TCP://6
			printf("---TCP---\n");
			analyze_tcp(packet, size);
			break;
		case IPPROTO_UDP://17
			printf("---UDP---\n");
			analyze_udp(packet, size);
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
	//printf("Sequence Number: %d\n", ntohl(tcp_hdr->th_seq));
	printf("Acknowledgement Number: %08x\n", swap_32_t(tcp_hdr->th_ack));
	//printf("Acknowledgement Number: %d\n", ntohl(tcp_hdr->th_ack));

	//printf("%d\n", tcp_hdr->th_off);

	printf("[flugs]\n");
	tcp_hdr->th_flags & TH_FIN ?  printf("\tFIN\n") : 0 ;
	tcp_hdr->th_flags & TH_SYN ?  printf("\tSYN\n") : 0 ;
	tcp_hdr->th_flags & TH_RST ?  printf("\tRST\n") : 0 ;
	tcp_hdr->th_flags & TH_PUSH ?  printf("\tPUSH\n") : 0 ;
	tcp_hdr->th_flags & TH_ACK ?  printf("\tACK\n") : 0 ;
	tcp_hdr->th_flags & TH_URG ?  printf("\tURG\n") : 0 ;
#ifdef __APPLE
	tcp_hdr->th_flags & TH_ECE ?  printf("\tECE\n") : 0 ;
	tcp_hdr->th_flags & TH_CWR ?  printf("\tCWR\n") : 0 ;
#endif

	printf("Window size: %d\n", swap_16_t(tcp_hdr->th_win));
	printf("Checksum: 0x%04x\n", swap_16_t(tcp_hdr->th_sum));
	printf("Urgent Pointer: %x\n", swap_16_t(tcp_hdr->th_urp));
}

void analyze_udp(u_char *packet, int size){
	struct udphdr *udp_hdr;
	udp_hdr = (struct udphdr *)packet;

	printf("Source Port: %d\n", swap_16_t(udp_hdr->uh_sport));
	printf("Destination: %d\n", swap_16_t(udp_hdr->uh_dport));
	printf("Length: %d\n", swap_16_t(udp_hdr->uh_ulen));
	printf("Checksum: 0x%04x\n", swap_16_t(udp_hdr->uh_sum));

}
