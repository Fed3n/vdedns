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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>

#include "dns.h"
#include "utils.h"
#include "const.h"

//PRINTS
void printsockaddr6(char* buf, struct sockaddr_in6 *store){
	struct in6_addr *addr = (struct in6_addr*)&store->sin6_addr;
	if(is_converted_ipv4(addr)){
    	inet_ntop(AF_INET, ((uint8_t*)addr)+12, buf, 64);
	} else {
    	inet_ntop(AF_INET6, (uint8_t*)addr, buf, 64);
	}
}

void printaddr6(char* buf, struct in6_addr *addr){
	if(is_converted_ipv4(addr)){
    	inet_ntop(AF_INET, ((uint8_t*)addr)+12, buf, 64);
	} else {
    	inet_ntop(AF_INET6, (uint8_t*)addr, buf, 64);
	}
}

//LOG PRINTING

#define LOGPATH "/var/log/vdedns.log"
static FILE* logfile;

int start_logging(){
	logfile = fopen(LOGPATH, "a");
	if(logfile == NULL) return 1;
	else return 0;
}

void printlog(int level, const char *format, ...){
	if(level <= logging_level){
		va_list arg;

		va_start(arg, format);
		
		char buf[20];
		struct tm *t;

		time_t now = time(NULL);
		t = localtime(&now);
		strftime(buf, 20, "%Y-%m-%d %H:%M:%S", t);

		if(logfile){
			fprintf(logfile, "[ %s ] ", buf);
			vfprintf(logfile, format, arg);
			fflush(logfile);
		} else {
			printf("[ %s ] ", buf);
			vprintf(format, arg);
		}
		va_end(arg);
	}
}


//STRING MANIPULATION
ssize_t get_subdom(char* dst, const char* full, const char* match){
	ssize_t flen = strnlen(full, IOTHDNS_MAXNAME);
	ssize_t mlen = strnlen(match, IOTHDNS_MAXNAME);
	if((flen-mlen-1) <= 0) return 0;
	strncpy(dst, full, (flen-mlen-1));
	return (flen-mlen);
}

//returns pointer to first char of string after '.' symbol
//returns NULL if no '.' symbols remaining in string
char* next_domain_label(const char* domain){
    char* res = (char*)domain;
    while(*res != '\0'){
        if(*res == '.') {
            return ++res;
        }
        res++;
    }
    return NULL;
}


//ADDRESSING
int is_converted_ipv4(struct in6_addr *addr){
    struct in6_addr format = {{IP4_IP6_MAP}};
    return (memcmp(&format, addr, 12)==0);
}


//TIMER FUNCTIONS
long get_time_ms(){
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	//ms conversion
	return (long)((now.tv_sec*1.E03) + (now.tv_nsec/1.0E6));
}

//returns expire time in ms
long set_timer(long ms){
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	//ms conversion
	return (long)(ms + ((now.tv_sec*1.E03) + (now.tv_nsec/1.0E6)));
}

int check_timer_expire(long expire){
	struct timespec current;
	clock_gettime(CLOCK_MONOTONIC, &current);
	//ms conversion
	long currentms = (current.tv_sec*1.E03) + (current.tv_nsec/1.0E6);
	if((long)(currentms > expire)){
		return 1;
	} else return 0;
}


//LOGGING
void save_pid(char* path){
	char fullpath[PATH_MAX];

	//get either relative or absolute path
	if(path[0] != '/'){
		char cwd[PATH_MAX];
		snprintf(fullpath, PATH_MAX, "%s/%s", getcwd(cwd, PATH_MAX), path);
	} else {
		snprintf(fullpath, PATH_MAX, "%s", path);	
	}
	int fd = open(path, O_WRONLY | O_CREAT,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	FILE *f = fdopen(fd, "w");
	if(f == NULL){
		printlog(LOG_ERROR, "Failed to open pidfile at %s", path);
		exit(1);
	}
	if(fprintf(f, "%ld\n", (long)getpid()) <= 0){
		printlog(LOG_ERROR, "Failed to write pidfile at %s", path);
		exit(1);
	}
	fclose(f);
	close(fd);
}
