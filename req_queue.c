#include <stdlib.h>
#include <stdio.h>

#include "dns.h"
#include "req_queue.h"
#include "utils.h"

void init_req_queue(struct req** reqhead){
	*reqhead = malloc(sizeof(struct req));
	(*reqhead)->next = (*reqhead)->prev = *reqhead;
}

void freereq(struct req* reqhead, struct req* target){
    struct req *iter;
    for(iter = reqhead->next; iter != reqhead; iter = iter->next){
        if(iter == target){
			iter->prev->next = iter->next;
			iter->next->prev = iter->prev;
			if(iter->h.qname != NULL) free(iter->h.qname);
            free(iter);
            break;
        }
    }
}

//call with starting point of queue, if NULL starting from beginning
//returns expired req on success, NULL on end of queue
struct req* next_expired_req(struct req* reqhead, struct req **start, long now){
	struct req *res;
	if(*start == NULL) *start = reqhead->next;
	//if(*start!= reqhead) printf("expire: %ld  now: %ld\n", (*start)->expire, now);
	//requests are queued so if i get a non-expired request
	//all the followings are also non-expired
	if(*start != reqhead && now > (*start)->expire) {
		res = *start;
		*start = (*start)->next;
		return res;
	}
	return NULL;
}

//call with starting point of queue, if NULL starting from beginning
//returns req on success, NULL on end of queue
struct req* next_req(struct req* reqhead, struct req **start){
	struct req* res = NULL;
	if(*start == NULL) {
		res = reqhead->next;
		*start = res->next;
	} else {
		res = *start;
		*start = res->next;
	}
	return res == reqhead ? NULL : res;
}

static struct req* _enqueue_request(struct req* reqhead, struct iothdns_header *h, uint16_t origid, 
		char* origdom, uint8_t type, uint8_t dnsn, char* opt, unsigned int time, int fd, 
		struct sockaddr_storage *from, ssize_t fromlen){
	struct req *new = calloc(1, sizeof(struct req));
	new->h = *h;
	new->h.qname = strndup(h->qname, IOTHDNS_MAXNAME);
	new->origid = origid;
    new->dnsn = dnsn;

	if(origdom != NULL) strncpy(new->origdom, origdom, IOTHDNS_MAXNAME);
	new->type = type;
	new->expire = get_time_ms() + dnstimeout;
	if(opt != NULL) strncpy(new->opt, opt, BUFSIZE);
	new->otip_time = time;
	
	//TCP
	new->fd = fd;

	//UDP
	if(from != NULL) new->addr = *from;
	new->addrlen = fromlen;
	
	new->prev = reqhead->prev;
	reqhead->prev->next = new;
	new->next = reqhead;
	reqhead->prev = new;
	return new;
}

struct req* enqueue_udp_request(struct req* reqhead, struct iothdns_header *h, uint16_t origid, 
		char* origdom, uint8_t type, uint8_t dnsn, char* opt, unsigned int time, 
		struct sockaddr_storage *from, ssize_t fromlen){
	return _enqueue_request(reqhead, h, origid, origdom, type, dnsn, opt, time, 0, from, fromlen);
}
struct req* enqueue_tcp_request(struct req* reqhead, struct iothdns_header *h, uint16_t origid, 
		char* origdom, uint8_t type, uint8_t dnsn, char* opt, unsigned int time, int fd, 
		struct sockaddr_storage *from, ssize_t fromlen){
	return _enqueue_request(reqhead, h, origid, origdom, type, dnsn, opt, time, fd, NULL, 0);
}

void printreq(struct req* reqhead){
   struct req *iter;
   for(iter=reqhead->next; iter!=reqhead; iter=iter->next){
        printf("ID %d  ORIGID %d\n", iter->h.id, iter->origid);
    }
}

