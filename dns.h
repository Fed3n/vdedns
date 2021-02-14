#ifndef DNS_H
#define DNS_H
#include <iothdns.h>

struct pktinfo {
	struct iothdns_header* h;
	struct iothdns_rr* rr;
	uint16_t origid;
	char* origdom;
	uint8_t type;
	char* opt;
    unsigned int otip_time;
	struct in6_addr baseaddr;
};

typedef void fwd_function_t(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo);

typedef void ans_function_t(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen);

extern struct ioth* fwd_stack;
extern struct ioth* query_stack;

extern struct iothdns* qdns;

extern int verbose, auth, forwarding;
extern long dnstimeout;

uint16_t get_unique_id();
void free_id(uint16_t id);

#endif
