#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<stdint.h>

#include"utilitys.h"

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
