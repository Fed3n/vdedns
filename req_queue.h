#ifndef REQ_QUEUE_H
#define REQ_QUEUE_H

#include <sys/socket.h>
#include <stdint.h>
#include <time.h>
#include <iothdns.h>

#include "const.h"

struct req {
	struct req *next;
	struct req *prev;
	
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

void init_req_queue(struct req** reqhead);

void freereq(struct req* reqhead, struct req* target);

struct req* next_req(struct req* reqhead, struct req **start);

struct req* next_expired_req(struct req* reqhead, struct req **start, long now);

struct req* enqueue_udp_request(struct req* reqhead, struct iothdns_header *h, uint16_t origid, char* origdom,
        uint8_t type, uint8_t dnsn, char* opt, unsigned int time, struct sockaddr_storage *from, size_t fromlen);

struct req* enqueue_tcp_request(struct req* reqhead, struct iothdns_header *h, uint16_t origid, char* origdom,
		uint8_t type, uint8_t dnsn, char* opt, unsigned int time, int fd);

void printreq();

#endif

