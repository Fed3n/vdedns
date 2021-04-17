#ifndef TCPFD_DATA_H
#define TCPFD_DATA_H

#include <sys/socket.h>
#include <stdint.h>
#include <time.h>
#include <iothdns.h>

#include "dns.h"
#include "hashq_data.h"
#include "const.h"

struct tcpfd_data {
	int fd;
	struct clientconn* fd_data;	
};

void init_fdhashq();

//Free all epoll data associated with fd and remove it from data structures
void free_fd(int fd);

struct hashq* next_expired_fd(struct hashq** start);

struct hashq* get_fd(int fd);

struct hashq* add_fd(int fd, struct clientconn* dataptr);

void update_fd(int fd);

#endif
