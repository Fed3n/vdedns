#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <ioth.h>
#include <iothdns.h>

#include "dns.h"
#include "parse_dns.h"
#include "config.h"
#include "utils.h"
#include "const.h"


static __thread int sfd, qfd;
static __thread struct req* reqhead;

void send_udp_ans(int fd, char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen){
	ioth_sendto(sfd, buf, len, 0, (struct sockaddr *) from, fromlen);
}

static void _fwd_udp_req(char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen, 
		struct pktinfo* pinfo, uint8_t dnsn){
	struct sockaddr_storage to = qdns->sockaddr[dnsn];
	if(verbose) {
		printf("querying dns: ");
		printsockaddr(&to);
	}
	if(ioth_sendto(qfd, buf, len, 0, (struct sockaddr *) &to, sizeof(to)) > 0){
		enqueue_udp_request(reqhead, pinfo->h, pinfo->origid, pinfo->origdom, pinfo->type,
				dnsn, pinfo->opt, pinfo->otip_time, from, fromlen);
	} else {
		perror("udp req send");
	}
}

void fwd_udp_req(int fd, char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen, 
		struct pktinfo* pinfo){
	_fwd_udp_req(buf, len, from, fromlen, pinfo, 0);
}

static void get_udp_ans(){
    char buf[IOTHDNS_UDP_MAXBUF];
    int len;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
		
	if((len = ioth_recvfrom(qfd, buf, IOTHDNS_UDP_MAXBUF, 0, (struct sockaddr*) &from, &fromlen)) <= 0){
		perror("udp recv ans");
		return;
	}
    
    parse_ans(reqhead, qfd, buf, len, send_udp_ans);
}

static void get_udp_req(){
    char buf[IOTHDNS_UDP_MAXBUF];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
    int len;
	if((len = ioth_recvfrom(sfd, buf, IOTHDNS_UDP_MAXBUF, 0, (struct sockaddr*) &from, &fromlen)) <= 0){
		perror("udp recv req");
		return;
	}

	parse_req(sfd, buf, len, &from, fromlen, fwd_udp_req, send_udp_ans);
}

static void manage_udp_req_queue(){
    struct req *current = NULL;
	struct req *iter;
    long now = get_time_ms();
    while((iter = next_expired_req(reqhead, &current, now)) != NULL){
		if(verbose){
			printf("################\n");
			printf("Expired ID: %d Query: %s", iter->h.id, iter->h.qname);
		}
		//if there are more available dns we query them aswell
		if(qdns->sockaddr[++iter->dnsn].ss_family != 0){
			char origdom[IOTHDNS_MAXNAME];
			struct pktinfo pinfo;
			pinfo.h = &iter->h;
			pinfo.h->id = random();
			pinfo.origdom = origdom;
			pinfo.origid = iter->origid;
			strncpy(pinfo.origdom, iter->origdom, IOTHDNS_MAXNAME);
			pinfo.type = iter->type;
			pinfo.opt = iter->opt;
			struct iothdns_pkt *pkt = iothdns_put_header(pinfo.h);
			_fwd_udp_req(iothdns_buf(pkt), iothdns_buflen(pkt), 
					&iter->addr, iter->addrlen, &pinfo, iter->dnsn);
			iothdns_free(pkt);
		}
		freereq(reqhead, iter);
	}
}

void* run_udp(void* args){
	init_req_queue(&reqhead);

    struct sockaddr_in6 saddr;	
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET6;
    saddr.sin6_addr = in6addr_any;
    saddr.sin6_port = htons(DNS_PORT);
    
    //UDP MSOCKET
    if((sfd = ioth_msocket(fwd_stack, AF_INET6, SOCK_DGRAM, 0)) < 0){
        perror("server msocket udp");
        exit(1);
    }
    if((qfd = ioth_msocket(fwd_stack, AF_INET6, SOCK_DGRAM, 0)) < 0){
        perror("query msocket udp");
        exit(1);
    }
    if(ioth_bind(sfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
        perror("bind udp");
        exit(1);
    }

	struct pollfd fds[] = {{sfd, POLLIN, 0}, {qfd, POLLIN, 0}};
	set_timer(dnstimeout);
    for(;;){
        if(poll(fds, 2, dnstimeout) == 0){
            //if it times out we check for expired requests
            manage_udp_req_queue();
			set_timer(dnstimeout);
            continue;
        }
        if(verbose) 
			printf("################\n");
        if(fds[0].revents) {
            //queries are from the forwarder fd
            if(verbose) 
				printf("UDP connection (query)\n");
            get_udp_req();
        }
        if(fds[1].revents) {
            //answers are from the querier fd
            if(verbose) 
				printf("UDP connection (answer)\n");
            get_udp_ans();
        }
		if(check_timer_expire()){
            manage_udp_req_queue();
			set_timer(dnstimeout);
		}
    } 
}
