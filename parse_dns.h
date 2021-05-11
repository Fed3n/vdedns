#ifndef PARSE_DNS_H
#define PARSE_DNS_H
#include "dns.h"
#include "req_data.h"

//Parses dns request given a packet forwarding function and a packet answering function
int parse_req(int fd, unsigned char* buf, ssize_t len, struct sockaddr_storage* from, 
		ssize_t fromlen, fwd_function_t *fwd_fun, ans_function_t *ans_fun);

//Parses dns answer given a packet answering function
void parse_ans(unsigned char* buf, ssize_t len, ans_function_t *ans_fun);

#endif
