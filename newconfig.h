#ifndef CONFIG_H
#define CONFIG_H

#include <sys/socket.h>
#include <stdint.h>
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
    struct in_addr* addr4;
    struct in6_addr* addr6;
    struct dns_addrinfo* next;
};

struct dns_authinfo {
    struct sockaddr_storage addr;
    struct sockaddr_storage mask;
    struct dns_authinfo* next;
};

extern struct sockaddr_storage qdns[MAX_DNS];

struct dns_otipdom* lookup_otip_domain(char* domain);
struct dns_hashdom* lookup_hash_domain(char* domain);
struct dns_addrinfo* lookup_domain_addr(char* domain);
int check_auth(struct sockaddr_storage* addr);
int init_config();

#endif
