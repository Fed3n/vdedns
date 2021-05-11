#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libconfig.h>
#include <ioth.h>
#include <iothconf.h>

#include "dns.h"
#include "utils.h"
#include "config.h"
#include "const.h"

#define CONFIGFILE "vdedns.cfg"

static struct dns_otipdom* otip_h;
static struct dns_hashdom* hash_h;
static struct dns_addrinfo* addr_h;
static struct dns_authinfo* auth_h;

struct sockaddr_in6 qdns[MAX_DNS];


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
		//if does not match for domain, try next subdomain
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
int check_auth(struct sockaddr_storage* addr){
	struct dns_authinfo* iter;
	uint8_t addr6[16];
	memcpy(addr6, &((struct sockaddr_in6*)addr)->sin6_addr, 16);
    for(iter=auth_h; iter!=NULL; iter=iter->next){
		uint8_t mask[16], auth[16];
		int i;
		memcpy(mask, &iter->mask, 16);
		memcpy(auth, &iter->addr, 16);
		for(i=0; i < 16; i++){
			if((mask[i] & addr6[i]) != (mask[i] & auth[i])) break;
		}
		if(i == 16) return 1;
    }
	return 0;
}

int init_config(){
	memset(qdns, 0, MAX_DNS*sizeof(struct sockaddr_in6));

	config_t cfg;
	config_setting_t *setting, *list;

	config_init(&cfg);

	char manualpath[PATH_MAX];
	if(geteuid() == 0){
		sprintf(manualpath, "/usr/local/etc/%s", CONFIGFILE);
	} else {
		sprintf(manualpath, "/home/%s/.config/%s", getlogin(), CONFIGFILE);
	}
	
	char* configpath = setconfigpath ? setconfigpath : manualpath;

	if(access(configpath, R_OK) != 0){
		printlog(LOG_ERROR, "Error cannot access configuration file %s\n", configpath);
		return(1);
	}
	
	if(!config_read_file(&cfg, configpath)){
		printlog(LOG_ERROR, "Error with config file %s, line %d: %s.\n", config_error_file(&cfg),
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
			uint8_t addr6[16] = IP4_IP6_MAP;
			if(inet_pton(AF_INET, addr, addr6+12) || inet_pton(AF_INET6, addr, addr6)){
				qdns[total].sin6_family = AF_INET6;
				qdns[total].sin6_port = htons(DNS_PORT);
				memcpy(&qdns[total].sin6_addr, addr6, 16);
			}
			total++;
		}
		if(total < 1){
			printlog(LOG_ERROR, "Warning: no master DNS set in configuration file. No request will be forwarded.\n");
			forwarding = 0;
		}
	} else {
		printlog(LOG_ERROR, "Warning: no master DNS set in configuration file. No request will be forwarded.\n");
		forwarding = 0;
	}

	//DOMAINS CONFIG
	setting = config_lookup(&cfg, "rules");
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
	list = config_lookup(&cfg, "records");
	if(list != NULL){
		int count = config_setting_length(list);
		int i;
		for(i = 0; i < count; i++){
			config_setting_t* tmp = config_setting_get_elem(list, i);
			const char* dom = NULL;
			struct in_addr* addr4 = NULL;
			struct in6_addr* addr6 = NULL;
			int n4, n6;
			n4=n6=0;
			config_setting_t* ip4set, *ip6set;
			ip4set=ip6set=NULL;
			if(!config_setting_lookup_string(tmp, "dom", &dom)){
				continue;
			}
			//variable number of addresses
			//gets dinamically allocated on a in_addr struct
			ip4set = config_setting_lookup(tmp, "ip4");
			if(ip4set != NULL){
				int count4 = config_setting_length(ip4set);
				int j;
				for(j=0; j < count4; j++){
					struct in_addr tmpaddr4;
					config_setting_t* tmp4;
					tmp4 = config_setting_get_elem(ip4set, j);
					const char* ip4 = config_setting_get_string(tmp4);
					if(ip4 != NULL){
						if(inet_pton(AF_INET, ip4, &tmpaddr4) == 1){
							addr4 = realloc(addr4, (n4+1)*sizeof(struct in_addr));
							addr4[n4] = tmpaddr4;
							n4++;
						}
					}
				}
			}
			ip6set = config_setting_lookup(tmp, "ip6");
			if(ip6set != NULL){
				int count6 = config_setting_length(ip6set);
				int j;
				for(j=0; j < count6; j++){
					struct in6_addr tmpaddr6;
					config_setting_t* tmp6;
					tmp6 = config_setting_get_elem(ip6set, j);
					const char* ip6 = config_setting_get_string(tmp6);
					if(ip6 != NULL){
						if(inet_pton(AF_INET6, ip6, &tmpaddr6) == 1){
							addr6 = realloc(addr6, (n6+1)*sizeof(struct in6_addr));
							addr6[n6] = tmpaddr6;
							n6++;
						}
					}
				}
			}
			if(!(n4 > 0 || n6 > 0)) continue;
			struct dns_addrinfo* new = malloc(sizeof(struct dns_addrinfo));
			new->domain = strndup(dom, IOTHDNS_MAXNAME);
			new->addr4 = addr4;
			new->addr4_n = n4;
			new->addr6 = addr6;
			new->addr6_n = n6;
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
		if((setting = config_lookup(&cfg, "vinterface.both"))){
			if((config_setting_lookup_string(setting, "type", &type) &&
					config_setting_lookup_string(setting, "vnl", &vnl) &&
					config_setting_lookup_string(setting, "config", &conf))){
				struct ioth	*stack = ioth_newstack(type, vnl);
				ioth_config(stack, (char*)conf);
				fwd_stack=query_stack=stack;
				printlog(LOG_INFO, "Forwarder and query stack of %s type on %s vnl with config %s\n", type, vnl, conf);
			}
		} else {
			if((setting = config_lookup(&cfg, "vinterface.dns"))){
				if((config_setting_lookup_string(setting, "type", &type) &&
						config_setting_lookup_string(setting, "vnl", &vnl) &&
						config_setting_lookup_string(setting, "config", &conf))){
					struct ioth	*stack = ioth_newstack(type, vnl);
					ioth_config(stack, (char*)conf);
					fwd_stack=stack;
					printlog(LOG_INFO, "Forwarder stack of %s type on %s vnl with config %s\n", type, vnl, conf);
				}	
			}
			if((setting = config_lookup(&cfg, "vinterface.query"))){
				if((config_setting_lookup_string(setting, "type", &type) &&
						config_setting_lookup_string(setting, "vnl", &vnl) &&
						config_setting_lookup_string(setting, "config", &conf))){
					struct ioth	*stack = ioth_newstack(type, vnl);
					ioth_config(stack, (char*)conf);
					query_stack=stack;
					printlog(LOG_INFO, "Query stack of %s type on %s vnl with config %s\n", type, vnl, conf);
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
			uint8_t saddr[16] = IP4_IP6_MAP;
			uint8_t smask[16] = IP4_IP6_MAP;
			const char* addr, *mask;
			addr=mask=NULL;
			if(!(config_setting_lookup_string(tmp, "ip", &addr) && config_setting_lookup_string(tmp, "mask", &mask))){
				continue;
			}
			if(!((inet_pton(AF_INET, addr, saddr+12)==1 && inet_pton(AF_INET, mask, smask+12)==1) || 
						(inet_pton(AF_INET6, addr, saddr)==1 && inet_pton(AF_INET6, mask, smask)==1))){
				continue;
			}
			struct dns_authinfo* new = malloc(sizeof(struct dns_authinfo));
			memcpy(&new->addr, saddr, 16);
			memcpy(&new->mask, smask, 16);
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
