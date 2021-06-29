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
 *
 *   hashdns.c: HASH based DNS
 *   revdb: data structure to hold data for reverse resolution
 *   
 *   Copyright 2016 Renzo Davoli - Virtual Square Team 
 *   University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "const.h"
#include "utils.h"

static unsigned int revtimeout = 3600;
static unsigned int nrecords;
static unsigned int maxrecords = 32768;

struct revaddr {
	struct revaddr *next;
	struct in6_addr addr;
	time_t expire;
	char name[];
};

static struct revaddr *rah;
static pthread_mutex_t ralock;

void ra_init(){
	pthread_mutex_init(&ralock, NULL);	
}


static void _ra_add(char *name, struct in6_addr *addr){
	struct revaddr *scan=rah;
	while (scan) {
		if (memcmp (&(scan->addr),addr,sizeof(* addr)) == 0) {
			scan->expire = time(NULL) + revtimeout;
			return;
		}
		scan = scan->next;
	}
	if (nrecords < maxrecords) {
		struct revaddr *ra=malloc(sizeof(struct revaddr)+strlen(name)+1);
		ra->addr = *addr;
		ra->expire = time(NULL) + revtimeout;
		ra->next = rah;
		strcpy(ra->name,name);
		nrecords++;
		rah = ra;
	}
}
void ra_add(char *name, struct in6_addr *addr){
	pthread_mutex_lock(&ralock);
	_ra_add(name, addr);
	pthread_mutex_unlock(&ralock);
}

static char *_ra_search(struct in6_addr *addr){
	struct revaddr *scan=rah;
	while (scan) {
		if (memcmp (&(scan->addr),addr,sizeof(* addr)) == 0){
			pthread_mutex_unlock(&ralock);
			return scan->name;
		}
		scan=scan->next;
	}
	return NULL;
}
char *ra_search(struct in6_addr *addr){
	char* res;
	pthread_mutex_lock(&ralock);
	res = _ra_search(addr);
	pthread_mutex_unlock(&ralock);
	return res;
}

static void _ra_clean(void){
	static time_t last;
	time_t now=time(NULL);
	if (now > last) {
		struct revaddr **prec=&rah;
		struct revaddr *scan;
		while (*prec) {
			scan=*prec;
			if (scan->expire < now) {
				*prec = scan->next;
				nrecords--;
				free(scan);
			} else
				prec = &(scan->next);
		}
		last=now;
	}
}
void ra_clean(void){
	pthread_mutex_lock(&ralock);
	_ra_clean();
	pthread_mutex_unlock(&ralock);
}

void ra_set_timeout(unsigned int timeout) {
	revtimeout = timeout;
}

unsigned int ra_get_timeout(void) {
	return revtimeout;
}

static enum {NEVER, ALWAYS, SAME, NET} reverse_policy = ALWAYS;
static char *reverse_policy_str[] = {"never", "always", "same", "net"};

int check_reverse_policy(struct in6_addr *addr, struct in6_addr *fromaddr) {
	char solved[64];
	char sender[64];
	printaddr6(solved, addr);
	printaddr6(sender, addr);
	printlog(LOG_DEBUG, "Checking Reverse Policy\n\tsolved: %s\n\tsender: %s\n", solved, sender);
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
	printlog(LOG_ERROR, "Error unknown reverse policy: %s\n", policy_str);
	return -1;
}

#define REVTAIL "ip6.arpa"

int getrevaddr(char *name, struct in6_addr *addr) {
	int i,j;
	printlog(LOG_DEBUG, "Resolving PTR: %s\n", name);
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

