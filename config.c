#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <ioth.h>
#include <iothconf.h>

#include "utils.h"
#include "config.h"

#define MAXLEN 64
#define FWDCONFIG "fwdconfig.txt"
#define IFCONFIG "ifconfig.txt"
#define AUTHCONFIG "authconfig.txt"

extern struct ioth* server_stack;
extern struct ioth* fwd_stack;
extern struct ioth* query_stack;

extern int verbose;

static struct fwdinfo* finfo;
static struct authinfo* ainfo;

void print_fwdinfo(){
    struct fwdinfo* iterinfo;
	for(iterinfo=finfo; iterinfo!=NULL; iterinfo=iterinfo->next){
		printf("%s %s %s\n", iterinfo->type,iterinfo->domain,iterinfo->opt ? iterinfo->opt : "");
	}
}

void set_stacks(){
    FILE* f = fopen("./stackconfig.txt", "r");
    if(f == NULL){
		printf("Could not find stack configuration file.\n");
		exit(1);
	}
	char* line=NULL;
	size_t linesize=0;
	while((linesize=getline(&line, &linesize, f)) != -1){
        if(line[0] == '#') continue;
		char *arg, *type, *vnl, *config;
		arg=type=config=NULL;
		sscanf(line,"%ms %ms %ms %ms", &arg, &type, &vnl, &config);
		if(arg && type && config){
			int i, server, forwarder, querier;
			i=server=forwarder=querier=0;
			while(arg[i] != '\0'){
				if(arg[i]=='s' || arg[i]=='S')
					server=1;
				if(arg[i]=='f' || arg[i]=='F')
					forwarder=1;
				if(arg[i]=='q' || arg[i]=='Q')
					querier=1;
				i++;
			}
			struct ioth	*stack = ioth_newstack(type, vnl);
			ioth_config(stack, config);
			if(server) {
				server_stack = stack;
				if(verbose)
					printf("Server stack of %s type on %s vnl with config %s\n", type, vnl, config);
			}
			if(forwarder) {
				fwd_stack = stack;
				if(verbose)
					printf("Forwarder stack of %s type on %s vnl with config %s\n", type, vnl, config);
			}
			if(querier) {
				query_stack = stack;
				if(verbose)
					printf("Querier stack of %s type on %s vnl with config %s\n", type, vnl, config);
			}
		}
		if(arg) free(arg);
		if(type) free(type);
		if(config) free(config);
	}
	if(verbose) printf("Done setting up stacks!\n");
}

int load_fwdconfig(){
    FILE* f = fopen(FWDCONFIG, "r");
    if(f == NULL) return -1;
	char* line=NULL;
	size_t linesize=0;
	finfo = NULL;
	struct fwdinfo* iterinfo = finfo;
	while((linesize=getline(&line, &linesize, f)) != -1){
        if(line[0] == '#') continue;
		struct fwdinfo *sinfo = malloc(sizeof(struct fwdinfo));
        char *type, *domain, *addr, *opt;
        type=domain=opt=NULL;
		sscanf(line,"%ms %ms %ms %ms", &type, &domain, &addr, &opt);
        if((    (strcmp(type, "otip")==0) || (strcmp(type, "hash")==0))
                && domain != NULL ){
            sinfo->type = type;
            sinfo->domain = domain;
			sinfo->addr = strcmp(addr, "#")==0 ? NULL : addr;
			if(sinfo->addr == NULL) free(addr);
            sinfo->opt = opt;
            sinfo->next = NULL;
			
            if(finfo == NULL) {
				finfo=iterinfo=sinfo;
			} else {
                iterinfo->next = sinfo;
                iterinfo = sinfo;
            }
        } else{
            if(type) free(type);
            if(domain) free(domain);
			if(addr) free(addr);
            if(opt) free(opt);
			free(sinfo);
        }
	}
    if(line) free(line);
    return finfo ? 0 : -1;
}

int load_authconfig(){
    FILE* f = fopen(AUTHCONFIG, "r");
    if(f == NULL) return -1;
	char* line=NULL;
	size_t linesize=0;
	ainfo = NULL;
	struct authinfo* iterinfo = ainfo;
	while((linesize=getline(&line, &linesize, f)) != -1){
        if(line[0] == '#') continue;
		struct authinfo *sinfo = malloc(sizeof(struct authinfo));
        char *addr = NULL;
		char *mask = NULL;
		sscanf(line,"%ms %ms", &addr, &mask);
		//printf("%s %s\n", addr, mask);
		if(inet_pton(AF_INET6, addr, &((struct sockaddr_in6*)&sinfo->addr)->sin6_addr)==1
				&& inet_pton(AF_INET6, mask, &((struct sockaddr_in6*)&sinfo->mask)->sin6_addr)==1){
			sinfo->addr.ss_family = AF_INET6;
            if(ainfo == NULL) ainfo=iterinfo=sinfo;
            else {
                iterinfo->next = sinfo;
                iterinfo = sinfo;
            }
		} else if(inet_pton(AF_INET, addr, &((struct sockaddr_in*)&sinfo->addr)->sin_addr)==1
				&& inet_pton(AF_INET, mask, &((struct sockaddr_in*)&sinfo->mask)->sin_addr)==1){ 
			sinfo->addr.ss_family = AF_INET;
            if(ainfo == NULL) ainfo=iterinfo=sinfo;
            else {
                iterinfo->next = sinfo;
                iterinfo = sinfo;
            }
		} else free(sinfo);
		if(addr) free(addr);
		if(mask) free(mask);
	}
    if(line) free(line);
    return ainfo ? 0 : -1;
} 

//matches longest corresponding domain and returns finfo struct, NULL if not found
struct fwdinfo* get_fwdinfo(char* domain){
    struct fwdinfo* info;
    while(domain != NULL){
        info = finfo;
        while(info != NULL){
            if(strncmp(info->domain, domain, MAXLEN) == 0){
                return info;
            }
			info = info->next;
        }
        domain = next_domain_label(domain);
    }
    return NULL;
}

//returns 1 if addr matches for authorization
//how: input is always a ipv6 sockaddr which could be either real ipv6 or converted ipv4
//if it's a real ipv6 we copy it to a 16byte array and compare it with authorized ips using masks
//else we copy the last 4bytes into a uint32_t and compare it with ipv4 authorized ips and masks
int get_authinfo(struct sockaddr_storage* addr){
	struct authinfo* iter;
	uint32_t addr4;
	uint8_t addr6[16];
	memcpy(addr6, &((struct sockaddr_in6*)addr)->sin6_addr, 16);
	int is_ip4 = is_converted_ipv4(&((struct sockaddr_in6*)addr)->sin6_addr);
	if(is_ip4) {
		memcpy(&addr4, addr6+12, sizeof(uint32_t));
	}
    for(iter=ainfo; iter!=NULL; iter=iter->next){
		//skips comparison if families are different
		if((is_ip4 && iter->addr.ss_family == AF_INET) || (!is_ip4 && iter->addr.ss_family == AF_INET6) ){
			if(!is_ip4){
				uint8_t mask[16], auth[16];
				int i;
				memcpy(mask, &((struct sockaddr_in6*)&iter->mask)->sin6_addr.s6_addr, 16);
				memcpy(auth, &((struct sockaddr_in6*)&iter->addr)->sin6_addr.s6_addr, 16);
				for(i=0; i < 16; i++){
					if((mask[i] & addr6[i]) != (mask[i] & auth[i])) break;
				}
				if(i == 16) return 1;
			} else {
				uint32_t mask = ((struct sockaddr_in*)&iter->mask)->sin_addr.s_addr;
				uint32_t auth = ((struct sockaddr_in*)&iter->addr)->sin_addr.s_addr;
				if((mask & addr4) == (mask & auth)) return 1;
			}
		} 	
    }
	return 0;
}

#if 0
int main(int argc, char** argv){
    load_authconfig();
	printf("############################\n");	
	struct sockaddr_storage test1;
	struct sockaddr_storage test2;
	struct sockaddr_storage test3;
	struct sockaddr_storage test4;
	inet_pton(AF_INET6, "fc00:aaaa::24:13", &((struct sockaddr_in6*)&test1)->sin6_addr);
	inet_pton(AF_INET6, "fc00:aabb::24:13", &((struct sockaddr_in6*)&test2)->sin6_addr);
	inet_pton(AF_INET6, "::ffff:192.168.1.1", &((struct sockaddr_in6*)&test3)->sin6_addr);
	inet_pton(AF_INET6, "::ffff:192.166.2.2", &((struct sockaddr_in6*)&test4)->sin6_addr);
	test1.ss_family = test2.ss_family = AF_INET6;
	test3.ss_family = test4.ss_family = AF_INET6;

	printf("TEST1: %d\n", get_authinfo(&test1));
	printf("TEST2: %d\n", get_authinfo(&test2));
	printf("TEST3: %d\n", get_authinfo(&test3));
	printf("TEST4: %d\n", get_authinfo(&test4));



	/*
    struct fwdinfo* a = get_fwdinfo("dom.secret", "otip");
    printf("res: %s\n", a ? a->domain : "NULL");
    a = get_fwdinfo("no.dom.secret", "otip");
    printf("res: %s\n", a ? a->domain : "NULL");
    a = get_fwdinfo("otip.dom.secret", "otip");
    printf("res: %s\n", a ? a->domain : "NULL");
    a = get_fwdinfo("no.fail", "otip");
    printf("res: %s\n", a ? a->domain : "NULL");
	*/
}
#endif

