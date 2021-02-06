#ifndef PARSE_DNS_H
#define PARSE_DNS_H
#include "req_queue.h"

struct pktinfo {
	struct iothdns_header* h;
	struct iothdns_rr* rr;
	uint16_t origid;
	char origdom[IOTHDNS_MAXNAME];
	char* opt;
	struct in6_addr baseaddr;
	uint8_t type;
};


void parse_req(int fd, char* buf, size_t len, struct sockaddr_storage* from, 
		size_t fromlen, uint8_t conn);

void parse_ans(struct req* reqhead, int fd, char* buf, size_t len, uint8_t conn);

int set_reverse_policy(char *policy_str);

#endif
