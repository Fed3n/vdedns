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
	unsigned int addr_n;
	struct in6_addr* baseaddr;
};

typedef void fwd_function_t(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo);

typedef void ans_function_t(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen);

extern struct ioth* fwd_stack;
extern struct ioth* query_stack;
extern int logging_level, auth, stacks, forwarding;
extern long dnstimeout;
extern unsigned int udp_maxbuf;
extern char* setconfigpath;
extern struct in6_addr *bindaddr;
extern pthread_mutex_t slock;

#endif
