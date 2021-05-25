#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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
#include "id_table.h"
#include "const.h"

//fills pktinfo structure with ipv6 addresses and number of addresses from response pkt
static int get_packet_answer(void* buf, ssize_t len, struct pktinfo* pinfo, uint16_t type){
    char name[IOTHDNS_MAXNAME];
    struct iothdns_pkt *pkt;
	struct iothdns_header h;
    struct iothdns_rr rr;
    int section;
	pinfo->addr_n = 0;
    pkt = iothdns_get_header(&h, buf, len, name);
    while((section = iothdns_get_rr(pkt, &rr, name)) != 0){
        if(section == IOTHDNS_SEC_ANSWER && rr.type == type){
			pinfo->baseaddr = realloc(pinfo->baseaddr, (pinfo->addr_n+1)*(sizeof(struct in6_addr)));
			iothdns_get_aaaa(pkt, &pinfo->baseaddr[pinfo->addr_n]);
			pinfo->addr_n++;
        } 
	}
	iothdns_free(pkt);
    return pinfo->addr_n;
}


#define MAX_RR 256
#define RR_MAXSIZE 1024
//transfers all RRs from packet buffer to ioth_dns packet structure
static void transfer_pkt_rr(struct iothdns_pkt* dest_pkt, void* buf, ssize_t len){
    char name[IOTHDNS_MAXNAME];
	struct iothdns_header h;
	struct iothdns_pkt* src_pkt = iothdns_get_header(&h, buf, len, name);
	struct iothdns_rr *rr = malloc(sizeof(struct iothdns_rr)*MAX_RR);
	void **data = malloc(MAX_RR);
	int section;
	int i = 0;
    while((section = iothdns_get_rr(src_pkt, rr+i, h.qname)) != 0 && i < MAX_RR){
		if(section == IOTHDNS_SEC_ADDITIONAL){
			data[i] = malloc(RR_MAXSIZE);
			iothdns_get_data(src_pkt, data[i], rr[i].rdlength);
			i++;
		}
	}
	int amount = i;
	printlog(LOG_DEBUG, "Found %d additional Resource Records in packet for domain %s.\n",
			amount, h.qname); 
	for(i = 0; i < amount; i++){
		iothdns_put_rr(IOTHDNS_SEC_ADDITIONAL, dest_pkt, &rr[i]);
		iothdns_put_data(dest_pkt, data[i], rr[i].rdlength);
		free(data[i]);
	}
	iothdns_free(src_pkt);
	free(rr);
	free(data);
}

//fills structure pktinfo with otip/hash address dns resource record if it's AAAA
static void solve_hashing(struct pktinfo* pinfo){
    if(pinfo->h->qtype == IOTHDNS_TYPE_AAAA){
		int i;
		for(i=0; i < pinfo->addr_n; i++){
			if(pinfo->type & TYPE_OTIP){
				iothaddr_hash((void*)&pinfo->baseaddr[i], pinfo->h->qname, pinfo->opt, 
						iothaddr_otiptime(pinfo->otip_time ? pinfo->otip_time : DEF_OTIP_PERIOD, 0));
			}
			else if(pinfo->type & TYPE_HASH){
				char buf[IOTHDNS_MAXNAME];
				//hashes address only if it's a subdomain for base domain, else returns unhashed base address
				if(get_subdom(buf, pinfo->origdom, pinfo->h->qname) > 0){
					iothaddr_hash((void*)&pinfo->baseaddr[i], pinfo->origdom, NULL, 0);
				}
			}
			pinfo->rr = malloc(sizeof(struct iothdns_rr));
			//if it's otip response TLL has to be 0
			*pinfo->rr = (struct iothdns_rr){.name=pinfo->h->qname, .type=IOTHDNS_TYPE_AAAA,
				.class=IOTHDNS_CLASS_IN, .ttl=(pinfo->type & TYPE_OTIP) ? 1 : TTL};
		}
	}
}

//retrieves the forwarded packet info from the requests queue
//if it's a vdedns domain it solves it accordingly
//else it sends the unmodified answer back changing to the right packet id
void parse_ans(unsigned char* buf, ssize_t len, ans_function_t *ans_fun){
    struct hashq *iter;
	struct pktinfo pinfo;
	struct iothdns_header h;
	char qname[IOTHDNS_MAXNAME];
	char origdom[IOTHDNS_MAXNAME];
    struct iothdns_pkt* pkt = iothdns_get_header(&h, buf, len, qname);
	int i;
	memset(&pinfo, 0, sizeof(struct pktinfo));
	pinfo.h = &h;
	pinfo.opt = NULL;
	pinfo.rr = NULL;
	//checks if it was actually a suspended request
	if(IOTHDNS_IS_RESPONSE(h.flags)){
		if((iter = get_req(h.id, h.qname)) != NULL){
		struct dnsreq *req = (struct dnsreq*)iter->data;
		//FOUND SUSPENDED REQUEST
			printlog(LOG_DEBUG, "Found suspended request qname: %s id: %d\n", h.qname, h.id);
			free_id(req->h.id);
			//replaces answer with original request id
			h.id = req->origid;
			if(req->type & TYPE_OTIP || req->type & TYPE_HASH){
			//CASE OTIP || HASH
				//start filling pktinfo structure
				pinfo.origdom = origdom;
				pinfo.type = req->type;
				pinfo.opt = req->opt;
				pinfo.otip_time = req->otip_time;
				strncpy(pinfo.origdom, req->origdom, IOTHDNS_MAXNAME);
				//getting ipv6 baseaddr from master dns answer for otip/hash solving
				//it is solved only if it's aaaa
				if(h.qtype == IOTHDNS_TYPE_AAAA && 
						get_packet_answer(buf, len, &pinfo, IOTHDNS_TYPE_AAAA)){
					solve_hashing(&pinfo);
					//if hash type && reverse policy is met, add addr to reverse db
					if(pinfo.type == TYPE_HASH){
						for(i=0; i < pinfo.addr_n; i++){
							if(check_reverse_policy(&pinfo.baseaddr[i], &ADDR6(&req->addr))){
								ra_add(pinfo.origdom, &pinfo.baseaddr[i]);
								char addrbuf[64];
								printaddr6(addrbuf, &pinfo.baseaddr[i]);
								printlog(LOG_INFO, "Address %s with domain %s added address to revdb\n", 
										addrbuf, pinfo.origdom);
							}
						}
					}
				}
				//replaces solved domain with original requested domain
				strncpy(h.qname, pinfo.origdom, IOTHDNS_MAXNAME);
				iothdns_free(pkt);
				pkt = iothdns_put_header(&h);
				//if it's a vdedns domain but query is not AAAA, we send an empty record
				if(pinfo.rr != NULL) {
					for(i=0; i < pinfo.addr_n; i++){
						iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, pinfo.rr);
						iothdns_put_aaaa(pkt, &pinfo.baseaddr[i]);
					}
					free(pinfo.rr);
					free(pinfo.baseaddr);
				}
				//transparently pass on all additional records
				transfer_pkt_rr(pkt, buf, len);
				ans_fun(req->fd, iothdns_buf(pkt), iothdns_buflen(pkt), &req->addr, req->addrlen);
			} else {
			//CASE GENERIC
			//packet is not parsed but left as is except for id
					//id is first 2 bytes
					buf[0] = h.id >> 8;
					buf[1] = h.id;
					ans_fun(req->fd, buf, len, &req->addr, req->addrlen);
			}
			free_req(iter);
		}
	}
	iothdns_free(pkt);
}

//fills a pktinfo structure by parsing a request
//and checking it against local dns information
//then either forwards the request or answers it
//returns -1 on invalid packet or unauthorized
int parse_req(int fd, unsigned char* buf, ssize_t len, struct sockaddr_storage* from, 
		ssize_t fromlen, fwd_function_t *fwd_fun, ans_function_t *ans_fun){
	int i;
	struct iothdns_header h;
	struct dns_otipdom* odom;
	struct dns_hashdom* hdom;
	struct dns_addrinfo* addri;
	struct pktinfo pinfo;
	char qname[IOTHDNS_MAXNAME];
	char origdom[IOTHDNS_MAXNAME];
    struct iothdns_pkt* pkt = iothdns_get_header(&h, buf, len, qname);
	memset(&pinfo, 0, sizeof(struct pktinfo));
	pinfo.h = &h;
	pinfo.type = TYPE_BASE;
	pinfo.opt=pinfo.origdom = NULL;
	pinfo.rr = NULL;
	iothdns_free(pkt);

	char addrbuf[64];
	printsockaddr6(addrbuf, (struct sockaddr_in6*)from);

	//if authorization is on and address is not authorized refuses request
	if(!(auth || check_auth(from))){
		printlog(LOG_INFO, "Unauthorized request from: %s\n", addrbuf);
		h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_EPERM);
		pkt = iothdns_put_header(&h);
		ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
		iothdns_free(pkt);
		return -1;
	}

	if(IOTHDNS_IS_QUERY(h.flags)){
		printlog(LOG_DEBUG, "Received query for domain %s\n", h.qname);

		//checking if it's a reverse query
		//if it is and it's in the reverse db it gets solved, else forwarded as usual
		if(h.qtype == IOTHDNS_TYPE_PTR){
			printlog(LOG_DEBUG, "%s is a reverse query (TYPE PTR)\n", h.qname);
			char* name;
			struct in6_addr raddr;
			if(getrevaddr(h.qname, &raddr) && (name=ra_search(&raddr)) != NULL){
				h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_OK);
				pkt = iothdns_put_header(&h);
				struct iothdns_rr rr = {.name=h.qname, .type=IOTHDNS_TYPE_PTR, 
					.class=IOTHDNS_CLASS_IN, .ttl=TTL};
				iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, &rr);
				iothdns_put_name(pkt, name);
				ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
				iothdns_free(pkt);
				return 0;
			}
		}
		//checks if domain matches as otip domain
		if((odom = lookup_otip_domain(h.qname)) != NULL){
			pinfo.type |= TYPE_OTIP;
			pinfo.opt = odom->pswd;
			pinfo.otip_time = odom->time;
			//domain unchanged in otip
			pinfo.origdom = h.qname;
		}
		//checks if domain matches as hash subdomain
		if((hdom = lookup_hash_domain(h.qname)) != NULL){
			pinfo.type |= TYPE_HASH;
			//domain might change in hash (i.e. matching)
			strncpy(origdom, h.qname, IOTHDNS_MAXNAME);
			origdom[IOTHDNS_MAXNAME-1] = '\0';
			pinfo.origdom = origdom;
			pinfo.h->qname = hdom->domain;
		}
		//checks if domain address exists in local record
		if((addri = lookup_domain_addr(h.qname)) != NULL){
			h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_OK);
			//hash/otip resolution for ipv6 only
			if(pinfo.type != TYPE_BASE){
				if(h.qtype == IOTHDNS_TYPE_AAAA && addri->addr6 != NULL){
					pinfo.baseaddr = malloc(addri->addr6_n*sizeof(struct in6_addr));
					memcpy(pinfo.baseaddr, addri->addr6, addri->addr6_n*sizeof(struct in6_addr)); 
					pinfo.addr_n = addri->addr6_n;
					solve_hashing(&pinfo);
					//if hash type && reverse policy is met, add addr to reverse db
					if(pinfo.type == TYPE_HASH){
						for(i=0; i < pinfo.addr_n; i++){
							if(check_reverse_policy(&pinfo.baseaddr[i], &ADDR6(from))){
								ra_add(pinfo.origdom, &pinfo.baseaddr[i]);
								char addrbuf[64];
								printaddr6(addrbuf, &pinfo.baseaddr[i]);
								printlog(LOG_INFO, "Address %s with domain %s added address to revdb\n", 
										addrbuf, pinfo.origdom);
							}
						}
					}
				}
				h.qname = pinfo.origdom;
				pkt = iothdns_put_header(&h);
				//putting response only when it's ipv6
				if(pinfo.rr != NULL) {
					for(i=0; i < pinfo.addr_n; i++){
						iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, pinfo.rr);
						iothdns_put_aaaa(pkt, &pinfo.baseaddr[i]);
					}
					free(pinfo.rr);
					free(pinfo.baseaddr);
				}
			} else {
			//generic resolution
				pkt = iothdns_put_header(&h);
				int i;
				if(h.qtype == IOTHDNS_TYPE_A && addri->addr4 != NULL){
					struct iothdns_rr rr = {.name=pinfo.h->qname, .type=IOTHDNS_TYPE_A, 
						.class=IOTHDNS_CLASS_IN, .ttl=TTL};
					for(i=0; i < addri->addr4_n; i++){
						iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, &rr);
						iothdns_put_a(pkt, &addri->addr4[i]);
					}
				} else if(h.qtype == IOTHDNS_TYPE_AAAA && addri->addr6 != NULL){
					struct iothdns_rr rr = {.name=pinfo.h->qname, .type=IOTHDNS_TYPE_AAAA, 
						.class=IOTHDNS_CLASS_IN, .ttl=TTL};
					for(i=0; i < addri->addr6_n; i++){
						iothdns_put_rr(IOTHDNS_SEC_ANSWER, pkt, &rr);
						iothdns_put_aaaa(pkt, &addri->addr6[i]);
					}
				}
			}
			ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);
			iothdns_free(pkt);
			return 0;
		}
		//will forward only if forwarding is active
		//else it will answer with a domain not found error
		if(forwarding){
			//forward request to master dns
			pinfo.origid = pinfo.h->id;
			pinfo.h->id = get_unique_id(); 
			pkt = iothdns_put_header(pinfo.h);
			//transparently pass on all additional records
			transfer_pkt_rr(pkt, buf, len);
			fwd_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen, &pinfo);
		} else {
			h.flags = (IOTHDNS_RESPONSE | IOTHDNS_RCODE_ENOENT);
			//if domain was changed to match we replace it
			h.qname = pinfo.origdom ? pinfo.origdom : h.qname;
			pkt = iothdns_put_header(&h);
			ans_fun(fd, iothdns_buf(pkt), iothdns_buflen(pkt), from, fromlen);	
		}
		iothdns_free(pkt);
		return 0;
	} else {
		//not a dns query
		return -1;
	}
}
