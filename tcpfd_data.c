#include <stdlib.h>
#include <stdio.h>

#include "dns.h"
#include "tcp_dns.h"
#include "tcpfd_data.h"
#include "req_data.h"
#include "utils.h"

static __thread struct hashq* queue_h;
static __thread struct hashq** hash_h;

void init_fdhashq(){
	init_hashq(&queue_h, &hash_h, FD_TABLE_SIZE);
}

void free_fd(int fd){
	struct hashq *target = get_fd(fd);
	struct tcpfd_data *data = (struct tcpfd_data*)free_hashq(target);
	if(data->fd_data->buf != NULL) free(data->fd_data->buf);
	free(data->fd_data);
	free(data);
}

struct hashq* next_expired_fd(struct hashq** start){
	return next_expired_hashq(queue_h, start, time(NULL));
}

//Returns 1 if id and domain name match, 0 else
int fddata_getcmpfun(void* arg1, void* arg2){
	return(*(int*)arg1 == *(int*)arg2);
}
struct hashq* get_fd(int fd){
	return get_hashq(hash_h, fd, FD_TABLE_SIZE, (void*)&fd, fddata_getcmpfun);
}

struct hashq* add_fd(int fd, struct clientconn* dataptr){
	struct tcpfd_data *data = malloc(sizeof(struct tcpfd_data));
	data->fd = fd;
	data->fd_data = dataptr;
	//add to queue
	return add_hashq(queue_h, hash_h, fd, time(NULL)+CLIENT_TIMEOUT, (void*)data);
}

void update_fd(int fd){
	struct hashq *target = get_fd(fd);
	moveto_tail(queue_h, target);
}
