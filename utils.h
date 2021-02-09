#ifndef UTILS_H
#define UTILS_H
#include <sys/socket.h>
#include <sys/types.h>
#include <iothdns.h>

struct iothdns {
	struct ioth *stack;
	pthread_mutex_t mutex;
	struct sockaddr_storage sockaddr[IOTHDNS_MAXNS];
	char *search;
};


void printsockaddr6(struct sockaddr_storage *store);

void printsockaddr(struct sockaddr_storage *store);

void printaddr6(struct in6_addr *addr);

void printaddr(struct in_addr *addr);

size_t get_subdom(char* dst, char* full, char* match);

char* next_domain_label(char* domain);

int is_converted_ipv4(struct in6_addr *addr);

long get_time_ms();

void set_timer(long ms);

int check_timer_expire();

#endif
