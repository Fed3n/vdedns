#ifndef UTILS_H
#define UTILS_H
#include <sys/socket.h>
#include <sys/types.h>
#include <iothdns.h>

void printsockaddr6(char* buf, struct sockaddr_in6 *store);

void printaddr6(char* buf, struct in6_addr *addr);

int start_logging();

void printlog(int level, const char *format, ...);

ssize_t get_subdom(char* dst, char* full, char* match);

char* next_domain_label(char* domain);

int is_converted_ipv4(struct in6_addr *addr);

long get_time_ms();

long set_timer(long ms);

int check_timer_expire(long expire);

void save_pid(char* path);

#endif
