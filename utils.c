#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>

#include "utils.h"

//PRINTS
void printsockaddr6(struct sockaddr_storage *store){
    char buf[64];
    inet_ntop(AF_INET6, (void*)((struct in6_addr*)&((struct sockaddr_in6*)store)->sin6_addr), buf, 64);
    printf("%s\n", buf);
}

void printsockaddr(struct sockaddr_storage *store){
    char buf[64];
    inet_ntop(AF_INET, (void*)((struct in_addr*)&((struct sockaddr_in*)store)->sin_addr), buf, 64);
    printf("%s\n", buf);
}

void printaddr6(struct in6_addr *addr){
	char buf[64];
    inet_ntop(AF_INET6, addr, buf, 64);
    printf("%s\n", buf);
}

void printaddr(struct in_addr *addr){
	char buf[64];
    inet_ntop(AF_INET, addr, buf, 64);
    printf("%s\n", buf);
}


//STRING MANIPULATION
size_t get_subdom(char* dst, char* full, char* match){
	size_t flen = strnlen(full, IOTHDNS_MAXNAME);
	size_t mlen = strnlen(match, IOTHDNS_MAXNAME);
	if((int)(flen-mlen-1) <= 0) return 0;
	strncpy(dst, full, (flen-mlen-1));
	return (flen-mlen);
}

//returns pointer to first char of string after '.' symbol
//returns NULL if no '.' symbols remaining in string
char* next_domain_label(char* domain){
    char* res = domain;
    while(*res != '\0'){
        if(*res == '.') {
            return ++res;
        }
        res++;
    }
    return NULL;
}


//ADDRESSING
int is_converted_ipv4(struct in6_addr *addr){
    struct in6_addr format = {{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0}}};
    return (memcmp(&format, addr, 12)==0);
}



//TIMER FUNCTIONS
static struct timespec timer;
static long timer_expire;

long get_time_ms(){
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (long)((now.tv_sec*1.E03) + (now.tv_nsec/1.0E6));
}

void set_timer(long ms){
	clock_gettime(CLOCK_MONOTONIC, &timer);
	timer_expire = ms;
}

int check_timer_expire(){
	struct timespec current;
	clock_gettime(CLOCK_MONOTONIC, &current);
	long currentms = (current.tv_sec*1.E03) + (current.tv_nsec/1.0E6);
	if((long)(currentms > timer_expire)){
		return 1;
	} else return 0;
}

