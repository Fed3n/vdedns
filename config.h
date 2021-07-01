#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "const.h"

struct dns_otipdom {
    char* domain;
    char* pswd;
    unsigned int time;
    struct dns_otipdom* next;
};

struct dns_hashdom {
    char* domain;
    struct dns_hashdom* next;
};

struct dns_addrinfo {
    char* domain;
    unsigned int addr4_n;
    unsigned int addr6_n;
    struct in_addr* addr4;
    struct in6_addr* addr6;
    struct dns_addrinfo* next;
};

struct dns_authinfo {
    struct in6_addr addr;
    struct in6_addr mask;
    struct dns_authinfo* next;
};

extern struct sockaddr_in6 qdns[MAX_DNS];

struct dns_otipdom* lookup_otip_domain(const char* domain);
struct dns_hashdom* lookup_hash_domain(const char* domain);
struct dns_addrinfo* lookup_domain_addr(const char* domain);
int check_auth(struct sockaddr_storage* addr);
int init_config();

#endif
