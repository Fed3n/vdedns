#ifndef TCP_DNS_H
#define TCP_DNS_H
#include "dns.h"
#include "req_data.h"
#include "parse_dns.h"

//struct for connections from clients
struct clientconn {
    int fd;
    uint8_t state;
    unsigned char* buf;
    ssize_t buflen;
    uint16_t pktlen;
	struct sockaddr_storage from;
	socklen_t fromlen;
};

//Run tcp dns 
void* run_tcp(void* args);

void fwd_tcp_req(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo);

void send_tcp_ans(int fd, unsigned char* buf, ssize_t len, struct sockaddr_storage* from, socklen_t fromlen);

#endif

