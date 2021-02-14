#ifndef UDP_DNS_H
#define UDP_DNS_H
#include "dns.h"
#include "req_queue.h"
#include "parse_dns.h"

void* run_udp(void* args);

void fwd_udp_req(unsigned char* buf, ssize_t len, struct sockaddr_storage* from, socklen_t fromlen, 
		struct pktinfo* pinfo, uint8_t dnsn);

void send_udp_ans(unsigned char* buf, ssize_t len, struct sockaddr_storage* from, socklen_t fromlen);

#endif
