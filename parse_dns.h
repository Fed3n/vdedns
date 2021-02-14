#ifndef PARSE_DNS_H
#define PARSE_DNS_H
#include "dns.h"
#include "req_queue.h"

void parse_req(int fd, unsigned char* buf, ssize_t len, struct sockaddr_storage* from, 
		ssize_t fromlen, fwd_function_t *fwd_fun, ans_function_t *ans_fun);

void parse_ans(struct req* reqhead, unsigned char* buf, ssize_t len, ans_function_t *ans_fun);

int set_reverse_policy(char *policy_str);

#endif
