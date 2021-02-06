#ifndef CONFIG_UTILS_H
#define CONFIG_UTILS_H

#include <sys/socket.h>
#include <stdint.h>

struct ifinfo {
    char* id;
    char* type;
    char* net;
    char* ipv6addr;
    char* ipv4addr;
    char* gwaddr;
    struct ioth* stack;
    struct ifinfo* next;
};

struct fwdinfo {
    char* type;
    char* domain;
    char* addr;
    char* opt;
    struct fwdinfo* next;
};

struct authinfo {
    struct sockaddr_storage addr;
    struct sockaddr_storage mask;
    struct authinfo* next;
};

void set_stacks();
int load_fwdconfig();
int load_ifconfig();
int load_authconfig();
struct fwdinfo* get_fwdinfo(char* domain);
struct ifinfo* get_ifinfo(char* id);
int get_authinfo(struct sockaddr_storage* addr);

#endif

