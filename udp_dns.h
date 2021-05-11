#ifndef UDP_DNS_H
#define UDP_DNS_H
#include "dns.h"
#include "req_data.h"
#include "parse_dns.h"

//Run udp dns 
void* run_udp(void* args);

void fwd_udp_req(int fd, unsigned char* buf, ssize_t len, struct sockaddr_storage* from, socklen_t fromlen, 
		struct pktinfo* pinfo);

void send_udp_ans(int fd, unsigned char* buf, ssize_t len, struct sockaddr_storage* from, socklen_t fromlen);

#endif
