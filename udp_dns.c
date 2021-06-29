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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <ioth.h>
#include <iothdns.h>

#include "dns.h"
#include "udp_dns.h"
#include "parse_dns.h"
#include "config.h"
#include "id_table.h"
#include "utils.h"
#include "const.h"


static __thread int sfd, qfd;

void send_udp_ans(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen){
	//packet truncation check
	//if a packet is longer than 512 bytes (or larger custom buffer, but this is rare) 
	//we send an empty answer with truncation bit on
	if(len > udp_maxbuf){
		struct iothdns_header h;
		char qname[IOTHDNS_MAXNAME];
    	struct iothdns_pkt* pkt = iothdns_get_header(&h, buf, len, qname);
		iothdns_free(pkt);
		h.flags |= IOTHDNS_TRUNC;
		pkt = iothdns_put_header(&h);
		ioth_sendto(sfd, iothdns_buf(pkt), iothdns_buflen(pkt), 0, 
				(struct sockaddr *) from, fromlen);
	} else {
		ioth_sendto(sfd, buf, len, 0, 
				(struct sockaddr *) from, fromlen);
	}
}

static void _fwd_udp_req(unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo, uint8_t dnsn){
	struct sockaddr_in6 to = qdns[dnsn];
	char addrbuf[64];
	printsockaddr6(addrbuf, &to);
	printlog(LOG_DEBUG, "Forwarding UDP request to DNS %s\n", addrbuf);
	if(ioth_sendto(qfd, buf, len, 0, (struct sockaddr *) &to, sizeof(to)) > 0){
		add_request(qfd, dnsn, buf, len, pinfo, from, fromlen);
	} else {
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error forwarding UDP request to DNS %s: %s\n", addrbuf,  errbuf);
	}
}

void fwd_udp_req(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo){
	_fwd_udp_req(buf, len, from, fromlen, pinfo, 0);
}

static void get_udp_ans(){
    unsigned char buf[udp_maxbuf];
    int len;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
		
	if((len = ioth_recvfrom(qfd, buf, udp_maxbuf, 0, (struct sockaddr*) &from, &fromlen)) <= 0){
		char addrbuf[64];
		printsockaddr6(addrbuf, (struct sockaddr_in6*)&from);
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error receiving UDP answer from DNS %s: %s\n", addrbuf, errbuf);
		return;
	}
    
    parse_ans(buf, len, send_udp_ans);
}

static void get_udp_req(){
    unsigned char buf[udp_maxbuf];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
    int len;
	if((len = ioth_recvfrom(sfd, buf, udp_maxbuf, 0, (struct sockaddr*) &from, &fromlen)) <= 0){
		char addrbuf[64];
		printsockaddr6(addrbuf, (struct sockaddr_in6*)&from);
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error receiving UDP request from %s: %s\n", addrbuf, errbuf);
		return;
	}

	parse_req(sfd, buf, len, &from, fromlen, fwd_udp_req, send_udp_ans);
}

static void manage_udp_req_queue(){
    struct hashq *current = NULL;
	struct hashq *iter;
    while((iter = next_expired_req(&current)) != NULL){
		struct dnsreq *req = (struct dnsreq*)iter->data;
		printlog(LOG_DEBUG, "Expired UDP Request ID: %d Query: %s\n", req->h.id, req->h.qname);
		//free id previously in use
		free_id(req->h.id);
		//if there are more available dns we query them aswell
		if(qdns[++req->dnsn].sin6_family != 0){
			char origdom[IOTHDNS_MAXNAME];
			struct pktinfo pinfo;

			//generate new id
			pinfo.h = &req->h;
			pinfo.h->id = get_unique_id(); 
			req->pktbuf[0] = pinfo.h->id >> 8;
			req->pktbuf[1] = pinfo.h->id;

			pinfo.origdom = origdom;
			pinfo.origid = req->origid;
			strncpy(pinfo.origdom, req->origdom, IOTHDNS_MAXNAME);
			pinfo.type = req->type;
			pinfo.opt = req->opt;
			_fwd_udp_req(req->pktbuf, req->pktlen, 
					&req->addr, req->addrlen, &pinfo, req->dnsn);
		}
		free_req(iter);
	}
}

void* run_udp(void* args){
	long expire;
	init_reqhashq();

    struct sockaddr_in6 saddr;	
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET6;
	if(bindaddr != NULL){
		saddr.sin6_addr = *bindaddr;
	} else {
    	saddr.sin6_addr = in6addr_any;
	}
    saddr.sin6_port = htons(DNS_PORT);
   	
    //UDP MSOCKET
    if((sfd = ioth_msocket(fwd_stack, AF_INET6, SOCK_DGRAM, 0)) < 0){
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error creating UDP accepting socket: %s\n", errbuf);
        exit(1);
    }
    if((qfd = ioth_msocket(query_stack, AF_INET6, SOCK_DGRAM, 0)) < 0){
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error creating UDP query socket: %s\n", errbuf);
        exit(1);
    }
	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){0}, sizeof(int));
	if(ioth_bind(sfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error binding UDP accepting socket: %s\n", errbuf);
        exit(1);
    }

	struct pollfd fds[] = {{sfd, POLLIN, 0}, {qfd, POLLIN, 0}};
	expire = set_timer(dnstimeout);
    for(;;){
        if(poll(fds, 2, dnstimeout) == 0){
            //if it times out we check for expired requests
            manage_udp_req_queue();
			expire = set_timer(dnstimeout);
            continue;
        }
        if(fds[0].revents) {
            //queries are from the forwarder fd
			printlog(LOG_DEBUG, "Received UDP connection query\n");
            get_udp_req();
        }
        if(fds[1].revents) {
            //answers are from the querier fd
			printlog(LOG_DEBUG, "Received UDP connection answer\n");
            get_udp_ans();
        }
		if(check_timer_expire(expire)){
            manage_udp_req_queue();
			expire = set_timer(dnstimeout);
		}
    } 
}
