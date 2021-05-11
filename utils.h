#ifndef UTILS_H
#define UTILS_H
#include <sys/socket.h>
#include <sys/types.h>
#include <iothdns.h>

//Print ipv6 as string into buf given struct sockaddr_in6
void printsockaddr6(char* buf, struct sockaddr_in6 *store);

//Print ipv6 as string into buf given struct in6_addr
void printaddr6(char* buf, struct in6_addr *addr);

//Logs into /var/logs/vdedns.log instead of stdout
int start_logging();

//Printing function, prints only if level is equal or higher to current
void printlog(int level, const char *format, ...);

//Get subdomain from full domain and base domain
ssize_t get_subdom(char* dst, char* full, char* match);

//Get next domain label from domain, returns NULL if there are no more labels
char* next_domain_label(char* domain);

//Checks if address is in mapped ipv4 format
int is_converted_ipv4(struct in6_addr *addr);

//Get current time in ms
long get_time_ms();

//Set a timer in ms
long set_timer(long ms);

//Returns 1 if timer is expired
int check_timer_expire(long expire);

//Save process pidfile in path
void save_pid(char* path);

#endif
