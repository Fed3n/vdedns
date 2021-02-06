#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <ioth.h>
#include <iothaddr.h>
#include <iothdns.h>

#include "config.h"
#include "utils.h"
#include "parse_dns.h"
#include "udp_dns.h"
#include "revdb.h"
#include "const.h"

extern int verbose, auth;


static enum {NEVER, ALWAYS, SAME, NET} reverse_policy = NEVER;
static char *reverse_policy_str[] = {"never", "always", "same", "net"};

static int check_reverse_policy(struct in6_addr *addr, struct in6_addr *fromaddr) {
	switch (reverse_policy) {
		case ALWAYS:
			return 1;
		case SAME:
			return memcmp(addr, fromaddr, 16) == 0;
		case NET:
			return memcmp(addr, fromaddr, 8) == 0;
		default:
			return 0;
	}
}

int set_reverse_policy(char *policy_str) {
	int i;
	for (i = 0; i < sizeof(reverse_policy_str)/sizeof(reverse_policy_str[0]); i++) {
		if (strcmp(policy_str, reverse_policy_str[i]) == 0) {
			reverse_policy = i;
			return 0;
		}
	}
	fprintf(stderr, "unknown reverse policy: %s\n", policy_str);
	return -1;
}

#define REVTAIL "ip6.arpa."

static int getrevaddr(char *name, struct in6_addr *addr) {
	int i,j;
	if (verbose)
		printf("Resolving PTR: %s\n", name);
	//TODO never passes guard because domain names not always ending with .
	/*
	if (strlen(name) != 73 || strcmp(name+64,REVTAIL) != 0)
		return 0;
	*/
	for (i=0,j=60; i<16; i++,j-=4) {
		char byte[3]={0, 0, 0};
		if (name[j+1] != '.' || name[j+3] != '.' || 
				!isxdigit(name[j]) || !isxdigit(name[j+2]))
			return 0;
		byte[0]=name[j+2],byte[1]=name[j];
		addr->s6_addr[i] = strtol(byte,NULL, 16);
	}
	return 1;
}


//fills structure pktinfo with otip/hash address dns resource record it it's AAAA
static void solve_hashing(struct pktinfo* pinfo){
	struct iothdns_header *h = pinfo->h;
    if(h->qtype == IOTHDNS_TYPE_AAAA){
		if(pinfo->type == TYPE_HASH){
			char buf[IOTHDNS_MAXNAME];
			//hashes address only if it's a subdomain for base domain, else returns unhashed base address
			if(get_subdom(buf, pinfo->origdom, h->qname) > 0){
				iothaddr_hash((void*)&pinfo->baseaddr, pinfo->origdom, NULL, 0);
			}
		} else {
			iothaddr_hash((void*)&pinfo->baseaddr, h->qname, pinfo->opt, iothaddr_otiptime(DEF_OTIP_PERIOD, 0));
		}
        pinfo->rr = malloc(sizeof(struct iothdns_rr)); 
		*pinfo->rr = (struct iothdns_rr){.name=h->qname, .type=IOTHDNS_TYPE_AAAA, .class=IOTHDNS_CLASS_IN, .ttl=TTL};
	}
}

//returns IOTHDNS_TYPE_A for ipv4, IOTHDNS_TYPE_AAAA for ipv6, 0 else
int get_packet_answer(void* buf, size_t len, void* byteaddr){
    char name[IOTHDNS_MAXNAME];
    struct iothdns_pkt *pkt;
	struct iothdns_header h;
    struct iothdns_rr rr;
    int section;
    pkt = iothdns_get_header(&h, buf, len, name);
    while((section = iothdns_get_rr(pkt, &rr, name)) != 0){
        if(section == IOTHDNS_SEC_ANSWER){
			if(rr.type == IOTHDNS_TYPE_AAAA){
				iothdns_get_aaaa(pkt, byteaddr);
                return IOTHDNS_TYPE_AAAA;
			}
			if(rr.type == IOTHDNS_TYPE_A){
				iothdns_get_a(pkt, byteaddr);
                return IOTHDNS_TYPE_A;
			}
        } 
	}
    return 0;
}


void parse_ans(struct req* reqhead, int fd, char* buf, size_t len, uint8_t conn){
    struct req *current = NULL;
    struct req *iter;
	struct pktinfo* pinfo = calloc(1, sizeof(struct pktinfo));
	struct iothdns_header h;
	pinfo->h = &h;
	char qname[IOTHDNS_MAXNAME];
    struct iothdns_pkt* pkt = iothdns_get_header(&h, buf, len, qname);
	//checks if it was actually a suspended request
	if(IOTHDNS_IS_RESPONSE(h.flags)){
		while((iter = next_req(reqhead, &current)) != NULL){
			if(iter->h.id == h.id && strncmp(iter->h.qname, h.qname, IOTHDNS_MAXNAME) == 0){
				if(verbose) 
					printf("qname: %s id: %d\n", h.qname, h.id);
				//replace answer with original request id
				h.id = iter->origid;
				if(iter->type == TYPE_OTIP || iter->type == TYPE_HASH){
				//CASE OTIP || HASH
					//start filling pktinfo structure
					pinfo->type = iter->type;
					pinfo->opt = iter->opt;
					strncpy(pinfo->origdom, iter->origdom, IOTHDNS_MAXNAME);
					//getting ipv6 baseaddr from master dns answer for otip/hash solving
					//it is solved only if it's aaaa
					if(h.qtype==IOTHDNS_TYPE_AAAA && get_packet_answer((conn==UDP_CONN ? buf : buf+2), 
								len, &pinfo->baseaddr)==IOTHDNS_TYPE_AAAA){
						solve_hashing(pinfo);
						//if hash type && reverse policy is met, add addr to reverse db
						if(pinfo->type == TYPE_HASH && check_reverse_policy(&pinfo->baseaddr, &ADDR6(&iter->addr))){
							ra_add(pinfo->origdom, &pinfo->baseaddr);
							if(verbose){
								printf("added address to revdb\n");
							}
						}
					}
					//replace solved domain with original requested domain
					strncpy(h.qname, pinfo->origdom, IOTHDNS_MAXNAME);
					pkt = iothdns_put_header(&h);
					if(pinfo->rr != NULL) {
						iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, pinfo->rr);
						iothdns_put_aaaa(pkt, &pinfo->baseaddr);
						free(pinfo->rr);
					}
					if(conn == UDP_CONN){
						send_udp_ans(iothdns_buf(pkt), iothdns_buflen(pkt), &iter->addr, iter->addrlen);
					} else {
						printf("TODO tcp\n");
					}
				} else {
				//CASE GENERIC
				//packet is not parsed but left as is except for id
					if(conn == UDP_CONN){
						//id is first 2 bytes
						buf[0] = h.id >> 8;
						buf[1] = h.id;
						send_udp_ans(buf, len, &iter->addr, iter->addrlen);
					} else {
						//id is second 2 bytes
						buf[2] = h.id >> 8;
						buf[3] = h.id;
						printf("TODO tcp\n");
					}
				}
				freereq(reqhead, iter);
				break;
			}
		}
	}
	iothdns_free(pkt);
	free(pinfo);
}

//populates pktinfo structure with hashing resolve information
//and checks if vdedns has ip
//have ip? send response : continue forwarding to master dns
static int parse_hashing(struct iothdns_header *h, struct fwdinfo* finfo, 
		struct pktinfo* pinfo){
	pinfo->type = strcmp("hash", finfo->type) == 0 ? TYPE_HASH : TYPE_OTIP;
	pinfo->opt = finfo->opt;	
	strncpy(pinfo->origdom, h->qname, IOTHDNS_MAXNAME);
	strncpy(h->qname, finfo->domain, IOTHDNS_MAXNAME);
	if(finfo->addr != NULL){
		//prepare packet for answering
		if(verbose)
			printf("have base address!\n");
		inet_pton(AF_INET6, finfo->addr, &pinfo->baseaddr);
		solve_hashing(pinfo);
		return 1;
	} else {
		//prepare packet for forwarding
		return 0;
	}
}

//fills a pktinfo structure by parsing a request
//then either forwards the request or answers it
void parse_req(int fd, char* buf, size_t len, struct sockaddr_storage* from, 
		size_t fromlen, uint8_t conn){
	struct iothdns_header h;
	struct fwdinfo* finfo;
	struct pktinfo* pinfo = calloc(1, sizeof(struct pktinfo));
	pinfo->h = &h;
	char qname[IOTHDNS_MAXNAME];
    struct iothdns_pkt* pkt = iothdns_get_header(&h, buf, len, qname);
	iothdns_free(pkt);
	//if authorization is on and address is not authorized refuses request
	if(!(auth || get_authinfo(from))){
		if(conn == UDP_CONN){
			udp_send_auth_error(&h, from, fromlen);
		} else {
			//return tcp_send_auth_error(fd, &h, &from, fromlen);
			printf("TODO tcp\n");
		}
		free(pinfo);
		iothdns_free(pkt);
		return;
	}

	if(IOTHDNS_IS_QUERY(h.flags)){
		if(verbose) printf("Query for %s\n", h.qname);

		//checking if it's a reverse query
		//if it is and it's in the reverse db it gets solved, else forwarded as usual
		if(h.qtype == IOTHDNS_TYPE_PTR){
			if(verbose) printf("Reverse query\n");
			char* name;
			struct in6_addr raddr;
			if(getrevaddr(h.qname, &raddr) && (name=ra_search(&raddr)) != NULL){
				h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_OK);
				pkt = iothdns_put_header(&h);
				struct iothdns_rr rr = {.name=h.qname, .type=IOTHDNS_TYPE_PTR, .class=IOTHDNS_CLASS_IN, .ttl=TTL};
				iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, &rr);
				iothdns_put_name(pkt, name);
				if(conn == UDP_CONN){
					send_udp_ans(iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
				} else {
					printf("TODO tcp\n");
				}
				free(pinfo);
				iothdns_free(pkt);
				return;
			}
			char buf[64];
			inet_ntop(AF_INET6, &raddr, buf, 64);
			printf("addr: %s\n", buf);
		}

		//if it's a listed domain for vdedns, returns a fwdinfo struct
		if((finfo = get_fwdinfo(h.qname)) != NULL){
			if(verbose) printf("hashing req\n");
			//returns 1 if vdedns has base address
			if(parse_hashing(&h, finfo, pinfo)){
				//if we already have requested address, no forwarding and we answer the request
				h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_OK);
				strncpy(h.qname, pinfo->origdom, IOTHDNS_MAXNAME);
				pkt = iothdns_put_header(&h);
				//if it's a vdedns address and it's not AAAA, we send an empty record
				if(pinfo->rr != NULL) {
					iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, pinfo->rr);
					iothdns_put_aaaa(pkt, &pinfo->baseaddr);
					free(pinfo->rr);
				}
				//if hash type && reverse policy is met, add addr to reverse db
				if(pinfo->type == TYPE_HASH && check_reverse_policy(&pinfo->baseaddr, &ADDR6(from))){
					ra_add(pinfo->origdom, &pinfo->baseaddr);
					printf("added address to revdb\n");
				}
				if(conn == UDP_CONN){
					send_udp_ans(iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
				} else {
					printf("TODO tcp\n");
				}
				free(pinfo);
				iothdns_free(pkt);
				return;
			}
		} else{
			if(verbose) printf("generic req\n");
		}
		pinfo->origid = h.id;
		h.id = random();
		pinfo->h = &h;
		pkt = iothdns_put_header(&h);
		if(conn == UDP_CONN){
			fwd_udp_req(iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen, pinfo, 0);	
		} else {
			printf("TODO tcp\n");
		}
	}
	free(pinfo);
	iothdns_free(pkt);
}
