#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libconfig.h>
#include <ioth.h>
#include <iothconf.h>

#include "dns.h"
#include "utils.h"
#include "newconfig.h"
#include "const.h"

#define CONFIGFILE "dnsconfig.cfg"

static struct dns_otipdom* otip_h;
static struct dns_hashdom* hash_h;
static struct dns_addrinfo* addr_h;
static struct dns_authinfo* auth_h;

struct sockaddr_storage qdns[MAX_DNS];


struct dns_otipdom* lookup_otip_domain(char* domain){
	struct dns_otipdom* iter;
	for(iter=otip_h; iter != NULL; iter=iter->next){
		if(strncmp(domain, iter->domain, IOTHDNS_MAXNAME) == 0){
			return iter;
		}
	}
	return NULL;
}

//matches longest corresponding domain and returns dns_hashdom struct, NULL if not found
struct dns_hashdom* lookup_hash_domain(char* domain){
    struct dns_hashdom* iter;
    while(domain != NULL){
        iter = hash_h;
        while(iter != NULL){
            if(strncmp(iter->domain, domain, IOTHDNS_MAXNAME) == 0){
                return iter;
            }
			iter = iter->next;
        }
        domain = next_domain_label(domain);
    }
    return NULL;
}

struct dns_addrinfo* lookup_domain_addr(char* domain){
	struct dns_addrinfo* iter;
	for(iter=addr_h; iter != NULL; iter=iter->next){
		if(strncmp(domain, iter->domain, IOTHDNS_MAXNAME) == 0){
			return iter;
		}
	}
	return NULL;
}

//returns 1 if addr matches for authorization
//how: input is always a ipv6 sockaddr which could be either real ipv6 or converted ipv4
//if it's a real ipv6 we copy it to a 16byte array and compare it with authorized ips using masks
//else we copy the last 4bytes into a uint32_t and compare it with ipv4 authorized ips and masks
int check_auth(struct sockaddr_storage* addr){
	struct dns_authinfo* iter;
	uint32_t addr4;
	uint8_t addr6[16];
	memcpy(addr6, &((struct sockaddr_in6*)addr)->sin6_addr, 16);
	int is_ip4 = is_converted_ipv4(&((struct sockaddr_in6*)addr)->sin6_addr);
	if(is_ip4) {
		memcpy(&addr4, addr6+12, sizeof(uint32_t));
	}
    for(iter=auth_h; iter!=NULL; iter=iter->next){
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

int init_config(){
	memset(qdns, 0, MAX_DNS*sizeof(struct sockaddr_storage));

	config_t cfg;
	config_setting_t *setting, *list;

	config_init(&cfg);

	if(!config_read_file(&cfg, CONFIGFILE)){
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
				config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return 1;	
	}

	//DNS SERVERS CONFIG
	list = config_lookup(&cfg, "dns_servers");
	if(list != NULL){
		int count = config_setting_length(list);
		int total = 0;
		int i;
		for(i = 0; i < count; i++){
			config_setting_t* tmp = config_setting_get_elem(list, i);
			const char* addr = config_setting_get_string(tmp);
			//verifying address string for either ipv4 or ipv6
			struct sockaddr_in saddr;
			struct sockaddr_in6 saddr6;
			if(inet_pton(AF_INET6, addr, &saddr6.sin6_addr) == 1){
				saddr6.sin6_family = AF_INET6;
				saddr6.sin6_port = htons(DNS_PORT);
				qdns[total] = *(struct sockaddr_storage*)&saddr6;
			} else if(inet_pton(AF_INET, addr, &saddr.sin_addr) == 1){
				saddr.sin_family = AF_INET;
				saddr.sin_port = htons(DNS_PORT);
				qdns[total] = *(struct sockaddr_storage*)&saddr;
			} else {
				continue;
			}
			total++;
		}
		if(total < 1){
			fprintf(stderr, "Configuration requires at least one valid dns server address in the dns_servers field.");
			return 1;
		}
	} else {
		fprintf(stderr, "Configuration requires dns_servers field with at least one valid address.");
		return 1;	
	}

	//DOMAINS CONFIG
	setting = config_lookup(&cfg, "domains");
	list = config_setting_lookup(setting, "hash");
	if(list != NULL){
		int count = config_setting_length(list);
		int i;
		for(i = 0; i < count; i++){
			config_setting_t* tmp = config_setting_get_elem(list, i);
			const char* dom = config_setting_get_string(tmp);
			struct dns_hashdom* new = malloc(sizeof(struct dns_hashdom));
			new->domain = strndup(dom, IOTHDNS_MAXNAME);
			if(hash_h == NULL){
				new->next = NULL;
				hash_h = new;
			} else {
				new->next = hash_h;
				hash_h = new;
			}
		}
	}
	list = config_setting_lookup(setting, "otip");
	if(list != NULL){
		int count = config_setting_length(list);
		int i;
		for(i = 0; i < count; i++){
			config_setting_t* tmp = config_setting_get_elem(list, i);
			const char* dom, *pswd;
			dom=pswd=NULL;
			int time;
			if(!(config_setting_lookup_string(tmp, "dom", &dom) &&config_setting_lookup_string(tmp, "pswd", &pswd))){
				continue;
			}
			if(!config_setting_lookup_int(tmp, "time", &time)){
				time = 0;
			}
			struct dns_otipdom* new = malloc(sizeof(struct dns_otipdom));
			new->domain = strndup(dom, IOTHDNS_MAXNAME);
			new->pswd = strndup(pswd, IOTHDNS_MAXNAME);
			new->time = time;
			if(otip_h == NULL){
				new->next = NULL;
				otip_h = new;
			} else {
				new->next = otip_h;
				otip_h = new;
			}
		}
	}

	//ADDRESSES CONFIG
	list = config_lookup(&cfg, "addresses");
	if(list != NULL){
		int count = config_setting_length(list);
		int i, valid4, valid6;
		struct in_addr addr4;
		struct in6_addr addr6;
		for(i = 0; i < count; i++){
			config_setting_t* tmp = config_setting_get_elem(list, i);
			const char* dom, *ip4, *ip6;
			valid4=valid6=0;
			dom=ip4=ip6=NULL;
			if(!config_setting_lookup_string(tmp, "dom", &dom)){
				continue;
			}
			config_setting_lookup_string(tmp, "ip4", &ip4);
			config_setting_lookup_string(tmp, "ip6", &ip6);
			if(ip4 != NULL) valid4 = inet_pton(AF_INET, ip4, &addr4);
			if(ip6 != NULL) valid6 = inet_pton(AF_INET6, ip6, &addr6);
			if(!(valid4==1 || valid6==1)) continue;
			struct dns_addrinfo* new = malloc(sizeof(struct dns_addrinfo));
			new->domain = strndup(dom, IOTHDNS_MAXNAME);
			if(valid4 == 1){
				new->addr4 = malloc(sizeof(struct sockaddr_storage));
				*new->addr4 = addr4;
			} else{
				new->addr4 = NULL;
			}
			if(valid6 == 1){
				new->addr6 = malloc(sizeof(struct sockaddr_storage));
				*new->addr6 = addr6;
			} else {
				new->addr6 = NULL;
			}
			if(addr_h == NULL){
				new->next = NULL;
				addr_h = new;
			} else {
				new->next = addr_h;
				addr_h = new;
			}
		}
	}

	//VIRTUAL INTERFACES CONFIG
	if(stacks){
		const char* type, *vnl, *conf;
		type=vnl=conf=NULL;
		if((setting = config_lookup(&cfg, "vinterfaces.both"))){
			if((config_setting_lookup_string(setting, "type", &type) &&
					config_setting_lookup_string(setting, "vnl", &vnl) &&
					config_setting_lookup_string(setting, "config", &conf))){
				struct ioth	*stack = ioth_newstack(type, vnl);
				ioth_config(stack, (char*)conf);
				fwd_stack=query_stack=stack;
				printf("Forwarder and query stack of %s type on %s vnl with config %s\n", type, vnl, conf);
			}
		} else {
			if((setting = config_lookup(&cfg, "vinterfaces.accept"))){
				if((config_setting_lookup_string(setting, "type", &type) &&
						config_setting_lookup_string(setting, "vnl", &vnl) &&
						config_setting_lookup_string(setting, "config", &conf))){
					struct ioth	*stack = ioth_newstack(type, vnl);
					ioth_config(stack, (char*)conf);
					fwd_stack=stack;
					printf("Forwarder stack of %s type on %s vnl with config %s\n", type, vnl, conf);
				}	
			}
			if((setting = config_lookup(&cfg, "vinterfaces.query"))){
				if((config_setting_lookup_string(setting, "type", &type) &&
						config_setting_lookup_string(setting, "vnl", &vnl) &&
						config_setting_lookup_string(setting, "config", &conf))){
					struct ioth	*stack = ioth_newstack(type, vnl);
					ioth_config(stack, (char*)conf);
					query_stack=stack;
					printf("Query stack of %s type on %s vnl with config %s\n", type, vnl, conf);
				}	
			}
		}
	}

	//AUTHORIZATION CONFIG
	list = config_lookup(&cfg, "authorization");
	if(list != NULL){
		int count = config_setting_length(list);
		int i;
		for(i = 0; i < count; i++){
			config_setting_t* tmp = config_setting_get_elem(list, i);
			struct sockaddr_storage ssaddr, ssmask;
			const char* addr, *mask;
			addr=mask=NULL;
			if(!(config_setting_lookup_string(tmp, "ip", &addr) && config_setting_lookup_string(tmp, "mask", &mask))){
				continue;
			}
			if(!((inet_pton(AF_INET, addr, &ssaddr)==1 && inet_pton(AF_INET, mask, &ssmask)==1) ||
					(inet_pton(AF_INET6, addr, &ssaddr)==1 && inet_pton(AF_INET6, mask, &ssmask)==1))){
				continue;
			}
			struct dns_authinfo* new = malloc(sizeof(struct dns_authinfo));
			new->addr=ssaddr;
			new->mask=ssmask;
			if(auth_h == NULL){
				new->next = NULL;
				auth_h = new;
			} else {
				new->next = auth_h;
				auth_h = new;
			}
		}		
	}	

	config_destroy(&cfg);
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


