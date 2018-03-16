#ifndef ANALYZE_H_
#define ANALYZE_H_

extern void analyze_arp(u_char *packet, int size);
extern void arp_request(struct ether_arp *eth_arp);
extern void arp_reply(struct ether_arp eth_arp);
extern void analyze_ip(u_char *packet, int size);
extern void analyze_icmp(u_char *packet, int size);
extern void analyze_tcp(u_char *packet, int size);
extern void analyze_udp(u_char *packet, int size);

#endif
