#ifndef UDP_DNS_H
#define UDP_DNS_H
#include "req_queue.h"
#include "parse_dns.h"

void* run_udp(void* args);

void fwd_udp_req(char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen, 
		struct pktinfo* pinfo, uint8_t dnsn);

void send_udp_ans(char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen);

void udp_send_auth_error(struct iothdns_header* h, struct sockaddr_storage* from, socklen_t fromlen);

#endif
