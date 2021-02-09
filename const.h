#define BUFSIZE 64

//DNS
#define DNS_PORT 53
#define TIMEOUT 1000 
#define TTL 600

#define DEF_OTIP_PERIOD 32

//REQ TYPE
#define TYPE_BASE 0
#define TYPE_OTIP 1
#define TYPE_HASH 2

//MACROS
#define ADDR6(x) (((struct sockaddr_in6*)(x))->sin6_addr)
