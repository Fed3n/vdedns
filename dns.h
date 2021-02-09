#ifndef DNS_H
#define DNS_H
#include <iothdns.h>

struct pktinfo {
	struct iothdns_header* h;
	struct iothdns_rr* rr;
	uint16_t origid;
	char* origdom;
	char* opt;
    unsigned int otip_time;
	struct in6_addr baseaddr;
	uint8_t type;
};

typedef void fwd_function_t(int fd, char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen, 
		struct pktinfo* pinfo);

typedef void ans_function_t(int fd, char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen);

extern struct ioth* fwd_stack;
extern struct ioth* query_stack;

extern struct iothdns* qdns;

extern int verbose, auth, forwarding;
extern long dnstimeout;


#endif
