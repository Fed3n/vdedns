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

#include "dns.h"
#include "config.h"
#include "utils.h"
#include "parse_dns.h"
#include "udp_dns.h"
#include "tcp_dns.h"
#include "revdb.h"
#include "const.h"

static enum {NEVER, ALWAYS, SAME, NET} reverse_policy = ALWAYS;
static char *reverse_policy_str[] = {"never", "always", "same", "net"};

static int check_reverse_policy(struct in6_addr *addr, struct in6_addr *fromaddr) {
	if(verbose){
		printf("Checking RP\n");
		printf("\tsolved: ");
		printaddr6(addr);
		printf("\tsender: ");
		printaddr6(fromaddr);
	}
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

#define REVTAIL "ip6.arpa"

static int getrevaddr(char *name, struct in6_addr *addr) {
	int i,j;
	if (verbose)
		printf("Resolving PTR: %s\n", name);
	if (strlen(name) != 72 || strcmp(name+64,REVTAIL) != 0)
		return 0;
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


//returns IOTHDNS_TYPE_A for ipv4, IOTHDNS_TYPE_AAAA for ipv6, 0 else
int get_packet_answer(void* buf, ssize_t len, void* byteaddr){
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

//fills structure pktinfo with otip/hash address dns resource record if it's AAAA
static void solve_hashing(struct pktinfo* pinfo){
    if(pinfo->h->qtype == IOTHDNS_TYPE_AAAA){
		if(pinfo->type == TYPE_HASH){
			char buf[IOTHDNS_MAXNAME];
			//hashes address only if it's a subdomain for base domain, else returns unhashed base address
			if(get_subdom(buf, pinfo->origdom, pinfo->h->qname) > 0){
				iothaddr_hash((void*)&pinfo->baseaddr, pinfo->origdom, NULL, 0);
			}
		} else {
			iothaddr_hash((void*)&pinfo->baseaddr, pinfo->h->qname, pinfo->opt, 
					iothaddr_otiptime(pinfo->otip_time ? pinfo->otip_time : DEF_OTIP_PERIOD, 0));
		}
		pinfo->rr = malloc(sizeof(struct iothdns_rr));
        *pinfo->rr = (struct iothdns_rr){.name=pinfo->h->qname, .type=IOTHDNS_TYPE_AAAA,
			.class=IOTHDNS_CLASS_IN, .ttl=TTL};
	}
}

//retrieves the forwarded packet info from the requests queue
//if it's a vdedns domain it solves it accordingly
//else it sends the unmodified answer back changing to the right packet id
void parse_ans(struct req* reqhead, unsigned char* buf, ssize_t len, ans_function_t *ans_fun){
    struct req *current = NULL;
    struct req *iter;
	struct pktinfo pinfo;
	struct iothdns_header h;
	char qname[IOTHDNS_MAXNAME];
	char origdom[IOTHDNS_MAXNAME];
    struct iothdns_pkt* pkt = iothdns_get_header(&h, buf, len, qname);
	pinfo.h = &h;
	pinfo.opt = NULL;
	pinfo.rr = NULL;
	//checks if it was actually a suspended request
	if(IOTHDNS_IS_RESPONSE(h.flags)){
		while((iter = next_req(reqhead, &current)) != NULL){
			if(iter->h.id == h.id /*&& strncmp(iter->h.qname, h.qname, IOTHDNS_MAXNAME) == 0*/){
			//FOUND SUSPENDED REQUEST
				if(verbose) 
					printf("qname: %s id: %d\n", h.qname, h.id);
				free_id(iter->h.id);
				//replaces answer with original request id
				h.id = iter->origid;
				if(iter->type == TYPE_OTIP || iter->type == TYPE_HASH){
				//CASE OTIP || HASH
					//start filling pktinfo structure
					pinfo.origdom = origdom;
					pinfo.type = iter->type;
					pinfo.opt = iter->opt;
					pinfo.otip_time = iter->otip_time;
					strncpy(pinfo.origdom, iter->origdom, IOTHDNS_MAXNAME);
					//getting ipv6 baseaddr from master dns answer for otip/hash solving
					//it is solved only if it's aaaa
					if(get_packet_answer(buf, len, &pinfo.baseaddr)==IOTHDNS_TYPE_AAAA){
						solve_hashing(&pinfo);
						//if hash type && reverse policy is met, add addr to reverse db
						if(pinfo.type == TYPE_HASH && check_reverse_policy(&pinfo.baseaddr, &ADDR6(&iter->addr))){
							ra_add(pinfo.origdom, &pinfo.baseaddr);
							if(verbose) printf("added address to revdb\n");
						}
					}
					//replaces solved domain with original requested domain
					strncpy(h.qname, pinfo.origdom, IOTHDNS_MAXNAME);
					pkt = iothdns_put_header(&h);
					//if it's a vdedns domain but query is not AAAA, we send an empty record
					if(pinfo.rr != NULL) {
						iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, pinfo.rr);
						iothdns_put_aaaa(pkt, &pinfo.baseaddr);
						free(pinfo.rr);
					}
						ans_fun(iter->fd, iothdns_buf(pkt), iothdns_buflen(pkt), &iter->addr, iter->addrlen);
				} else {
				//CASE GENERIC
				//packet is not parsed but left as is except for id
						//id is first 2 bytes
						buf[0] = h.id >> 8;
						buf[1] = h.id;
						ans_fun(iter->fd, buf, len, &iter->addr, iter->addrlen);
				}
				freereq(reqhead, iter);
				break;
			}
		}
	}
	iothdns_free(pkt);
}

//populates pktinfo structure with hashing resolve information
//and checks if vdedns has ip
//have ip? send response : continue forwarding to master dns
static int parse_hashing(struct fwdinfo* finfo, struct pktinfo* pinfo){
	pinfo->type = strcmp("hash", finfo->type) == 0 ? TYPE_HASH : TYPE_OTIP;
	pinfo->opt = finfo->opt;
	pinfo->otip_time = finfo->time;
	strncpy(pinfo->origdom, pinfo->h->qname, IOTHDNS_MAXNAME);
	strncpy(pinfo->h->qname, finfo->domain, IOTHDNS_MAXNAME);
	if(finfo->addr != NULL){
		//prepare packet for answering
		if(verbose)
			printf("have base address!\n");
		if(pinfo->h->qtype == IOTHDNS_TYPE_AAAA){
			inet_pton(AF_INET6, finfo->addr, &pinfo->baseaddr);
			solve_hashing(pinfo);
		}
		return 1;
	} else {
		//prepare packet for forwarding
		return 0;
	}
}

//fills a pktinfo structure by parsing a request
//then either forwards the request or answers it
void parse_req(int fd, unsigned char* buf, ssize_t len, struct sockaddr_storage* from, 
		ssize_t fromlen, fwd_function_t *fwd_fun, ans_function_t *ans_fun){
	struct iothdns_header h;
	struct fwdinfo* finfo;
	struct pktinfo pinfo;
	char qname[IOTHDNS_MAXNAME];
	char origdom[IOTHDNS_MAXNAME];
    struct iothdns_pkt* pkt = iothdns_get_header(&h, buf, len, qname);
	pinfo.h = &h;
	pinfo.opt=pinfo.origdom = NULL;
	pinfo.rr = NULL;
	pinfo.type = TYPE_BASE;
	iothdns_free(pkt);

	//if authorization is on and address is not authorized refuses request
	if(!(auth || get_authinfo(from))){
		h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_EPERM);
		pkt = iothdns_put_header(&h);
		ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
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
				ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
				iothdns_free(pkt);
				return;
			}
		}

		//if it's a listed domain for vdedns, returns a fwdinfo struct
		if((finfo = get_fwdinfo(h.qname)) != NULL){
			if(verbose) printf("hashing req\n");
			//domain is gonna be changed so parse_hashing will make use of origdom to save previous one
			pinfo.origdom = origdom;
			//returns 1 if vdedns has base address
			if(parse_hashing(finfo, &pinfo)){
			//if we already have requested address, no forwarding and we answer the request
				h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_OK);
				//header might have been modified by parsing, so we restore domain name
				strncpy(h.qname, pinfo.origdom, IOTHDNS_MAXNAME);
				pkt = iothdns_put_header(&h);
				//if it's a vdedns domain but query is not AAAA, we send an empty record
				if(pinfo.rr != NULL) {
					iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, pinfo.rr);
					iothdns_put_aaaa(pkt, &pinfo.baseaddr);
					free(pinfo.rr);
				}
				//if hash type && reverse policy is met, add addr to reverse db
				if(h.qtype==IOTHDNS_TYPE_AAAA && pinfo.type == TYPE_HASH && 
						check_reverse_policy(&pinfo.baseaddr, &ADDR6(from))){
					ra_add(pinfo.origdom, &pinfo.baseaddr);
					if(verbose) printf("added address to revdb\n");
				}
				ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
				iothdns_free(pkt);
				return;
			}
		} else{
			if(verbose) printf("generic req\n");
		}
		//will forward only if forwarding is active
		//else it will answer with a domain not found error
		if(forwarding){
			//forward request to master dns
			pinfo.origid = pinfo.h->id;
			pinfo.h->id = get_unique_id(); 
			pkt = iothdns_put_header(pinfo.h);
			fwd_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen, &pinfo);
		} else {
			h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_ENOENT);
			//if domain was changed to match we replace it
			h.qname = pinfo.origdom ? pinfo.origdom : h.qname;
			pkt = iothdns_put_header(&h);
			ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
		}
		iothdns_free(pkt);
	}
}
