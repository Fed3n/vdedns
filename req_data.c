/*   
 *   vdedns: proxy dns for resolution of hash based IPv6 addresses
 *   
 *   Copyright 2021 Federico De Marchi - Virtual Square Team 
 *   University of Bologna - Italy
 *   
 *   This file is part of vdedns.
 *
 *   vdedns is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   vdedns is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include "dns.h"
#include "req_data.h"
#include "utils.h"

static __thread struct hashq* queue_h;
static __thread struct hashq** hash_h;

struct reqdata_args{
	uint16_t id;
	const char* qname;
};

void init_reqhashq(){
	init_hashq(&queue_h, &hash_h, REQ_TABLE_SIZE);
}

void free_req(struct hashq* target){
	struct dnsreq *data = (struct dnsreq*)free_hashq(target);
	free(data->pktbuf);
	if(data->h.qname) free((void*)data->h.qname);
	free(data);
}

struct hashq* next_expired_req(struct hashq** start){
	return next_expired_hashq(queue_h, start, get_time_ms());
}

//Returns 1 if id and domain name match, 0 else
int reqdata_getcmpfun(void* arg1, void* arg2){
	return((((struct reqdata_args*)arg1)->id == ((struct dnsreq*)arg2)->h.id) &&
			strncmp(((struct reqdata_args*)arg1)->qname, ((struct dnsreq*)arg2)->h.qname, 
				IOTHDNS_MAXNAME) == 0);
}
struct hashq* get_req(uint16_t id, const char* qname){
	struct reqdata_args args = {id, qname};
	return get_hashq(hash_h, id, REQ_TABLE_SIZE, (void*)&args, reqdata_getcmpfun);
}

struct hashq* add_request(int fd, int dnsn, unsigned char* buf, ssize_t len,
		struct pktinfo *pinfo, struct sockaddr_storage *from, ssize_t fromlen){
	struct dnsreq *req = calloc(1, sizeof(struct dnsreq));
	
	//slighly optimize structure size by allocating only needed memory
	//instead of MAXSIZE
	req->pktbuf = malloc(len);
	memcpy(req->pktbuf, buf, len);
	req->pktlen = len;

	req->h = *pinfo->h;
	req->h.qname = strndup(pinfo->h->qname, IOTHDNS_MAXNAME);
	req->origid = pinfo->origid;
    req->dnsn = dnsn;

	if(pinfo->origdom != NULL) {
		strncpy(req->origdom, pinfo->origdom, IOTHDNS_MAXNAME);
		req->origdom[IOTHDNS_MAXNAME-1] = '\0';
	}
	req->type = pinfo->type;
	if(pinfo->opt != NULL) {
		strncpy(req->opt, pinfo->opt, BUFSIZE);
		req->opt[BUFSIZE-1] = '\0';
	}
	req->otip_time = pinfo->otip_time;
	
	//TCP
	req->fd = fd;

	//UDP
	if(from != NULL) req->addr = *from;
	req->addrlen = fromlen;
	
	//add to queue
	return add_hashq(queue_h, hash_h, pinfo->h->id, REQ_TABLE_SIZE,
            get_time_ms()+dnstimeout, (void*)req);
}
