#ifndef UTILITYS_H_
#define UTILITYS_H_

extern u_int16_t swap_16_t(u_int16_t num);
extern u_int32_t swap_32_t(u_int32_t num);
extern char* print_mac_addr(u_int8_t *mac_addr, char *mac, size_t size);
extern char* print_ip_addr(u_int8_t *ip_addr, char *ip, size_t size);

#endif
