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

#include "parse_dns.h"
#include "config.h"
#include "utils.h"
#include "const.h"


__thread int sfd, qfd;
__thread struct req* reqhead;

extern struct ioth* server_stack;
extern struct ioth* fwd_stack;
extern struct ioth* query_stack;

extern struct iothdns* qdns;

extern int verbose, auth;

void udp_send_auth_error(struct iothdns_header* h, struct sockaddr_storage* from, socklen_t fromlen){
    h->flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_EPERM);
	struct iothdns_pkt *pkt = iothdns_put_header(h);
	ioth_sendto(sfd, iothdns_buf(pkt), iothdns_buflen(pkt), 0, (struct sockaddr*)from, fromlen);
}


void send_udp_ans(char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen){
	ioth_sendto(sfd, buf, len, 0, (struct sockaddr *) from, fromlen);
}

 void fwd_udp_req(char* buf, size_t len, struct sockaddr_storage* from, size_t fromlen, 
		struct pktinfo* pinfo, uint8_t dnsn){
	struct sockaddr_storage to = qdns->sockaddr[dnsn];
	if(ioth_sendto(qfd, buf, len, 0, (struct sockaddr *) &to, sizeof(to)) > 0){
		enqueue_udp_request(reqhead, pinfo->h, pinfo->origid, pinfo->origdom, pinfo->type,
				dnsn, pinfo->opt, from, fromlen);
	} else {
		perror("udp req send");
	}
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
    
    parse_ans(reqhead, qfd, buf, len, UDP_CONN);
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

	parse_req(sfd, buf, len, &from, fromlen, UDP_CONN);
}

static void manage_udp_req_queue(){
    struct req *current = NULL;
	struct req *iter;
    time_t now = time(NULL);
    while((iter = next_expired_req(reqhead, &current, now)) != NULL){
		//printf("Expired ID: %d dnsn: %d\n", iter->h.id, iter->dnsn);
		//if there are more available dns we query them aswell
		if(qdns->sockaddr[++iter->dnsn].ss_family != 0){
			iter->h.id = random();
			iter->expire = time(NULL)+TIMEOUT; 
			struct sockaddr_storage to = qdns->sockaddr[iter->dnsn];
			struct iothdns_pkt *pkt = iothdns_put_header(&iter->h);
			ioth_sendto(qfd, iothdns_buf(pkt), iothdns_buflen(pkt), 0, (struct sockaddr *) &to, sizeof(to));
			enqueue_udp_request(reqhead, &iter->h, iter->origid, iter->origdom, iter->type, iter->dnsn,
						iter->opt, &iter->addr, iter->addrlen);
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
    saddr.sin6_port = htons(PORT);
    
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
	set_timer(TIMEOUT*1000);
    for(;;){
        if(poll(fds, 2, TIMEOUT*1000) == 0){
            //if it times out we check for expired requests
            manage_udp_req_queue();
			set_timer(TIMEOUT*1000);
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
			set_timer(TIMEOUT*1000);
		}
    } 
}
