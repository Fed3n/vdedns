#ifndef PARSE_DNS_H
#define PARSE_DNS_H
#include "dns.h"
#include "req_queue.h"

void parse_req(int fd, char* buf, size_t len, struct sockaddr_storage* from, 
		size_t fromlen, fwd_function_t *fwd_fun, ans_function_t *ans_fun);

void parse_ans(struct req* reqhead, int fd, char* buf, size_t len, ans_function_t *ans_fun);

int set_reverse_policy(char *policy_str);

#endif
