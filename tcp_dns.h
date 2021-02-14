#ifndef TCP_DNS_H
#define TCP_DNS_H
#include "dns.h"
#include "req_queue.h"
#include "parse_dns.h"

void* run_tcp(void* args);

void fwd_tcp_req(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo, uint8_t dnsn);

void send_tcp_ans(unsigned char* buf, ssize_t len, struct sockaddr_storage* from, socklen_t fromlen);

#endif

