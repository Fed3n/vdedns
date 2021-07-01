#ifndef REQ_DATA_H
#define REQ_DATA_H

#include <sys/socket.h>
#include <stdint.h>
#include <time.h>
#include <iothdns.h>

#include "dns.h"
#include "hashq_data.h"
#include "const.h"

struct dnsreq {
	//save packet for fallback forwarding
	unsigned char* pktbuf;
	ssize_t pktlen;

	//dns query request fields
	struct iothdns_header h;
	uint16_t origid;
	char origdom[IOTHDNS_MAXNAME];
	
	//dns processing fields
	uint8_t type;
    uint8_t dnsn;
    char opt[BUFSIZE];
	unsigned int otip_time;
	long expire;
	
	//query connection fields
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int fd;
};

void init_reqhashq();

void free_req(struct hashq* target);

struct hashq* next_expired_req(struct hashq** start);

struct hashq* get_req(uint16_t id, const char* qname);

struct hashq* add_request(int fd, int dnsn, unsigned char* buf, ssize_t len, 
		struct pktinfo *pinfo, struct sockaddr_storage *from, ssize_t fromlen);

#endif
