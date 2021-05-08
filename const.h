#define BUFSIZE 256
#define PATH_MAX 4096
#define IP4_IP6_MAP {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, \
	0xff, 0xff, 0x0, 0x0, 0x0, 0x0}


//DNS
#define DNS_PORT 53
#define TIMEOUT 1000
#define TTL 600
#define MAX_DNS 256
#define CLIENT_TIMEOUT 3
#define LISTEN_QUEUE 256

//HASHTABLES
#define ID_TABLE_SIZE 65536
#define FD_TABLE_SIZE 2048

#define DEF_OTIP_PERIOD 32

//REQ TYPE
#define TYPE_BASE 0
#define TYPE_OTIP 1
#define TYPE_HASH 2

//MACROS
#define ADDR6(x) (((struct sockaddr_in6*)(x))->sin6_addr)

//LOG LEVELS
#define LOG_ERROR 1
#define LOG_INFO 2
#define LOG_DEBUG 3
