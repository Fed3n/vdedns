#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <ioth.h>
#include <iothdns.h>

#include "dns.h"
#include "tcp_dns.h"
#include "config.h"
#include "utils.h"
#include "const.h"

//EPOLL
#define MAX_EVENTS 2048
#define CEFD(event) (((struct clientconn*)(event.data.ptr))->fd)
#define QEFD(event) (((struct conn*)(event.data.ptr))->fd)
#define CESTATE(event) (((struct clientconn*)(event.data.ptr))->state)
#define QESTATE(event) (((struct conn*)(event.data.ptr))->state)
#define CEBUF(event) (((struct clientconn*)(event.data.ptr))->buf)
#define CEADDR(event) (((struct clientconn*)(event.data.ptr))->from)
#define CEADDRLEN(event) (((struct clientconn*)(event.data.ptr))->fromlen)

//STATE
#define LISTENER 0
#define RECV_REQ_LEN 1
#define RECV_REQ_PKT 2
#define RECV_ANS_LEN 3
#define RECV_ANS_PKT 4

struct conn {
	int fd;
	uint8_t state;
    unsigned char* buf;
    ssize_t buflen;
    uint16_t pktlen;
};

struct clientconn {
    int fd;
    uint8_t state;
    unsigned char* buf;
    ssize_t buflen;
    uint16_t pktlen;
	struct sockaddr_storage from;
	socklen_t fromlen;
};

static __thread int efd, qfd[MAX_DNS];
static __thread struct hashq* queue_h;
static __thread struct hashq** hash_h;

//allocates tcp dns packet from udp packet
void *make_tcp_pkt(void* buf, ssize_t *len){
	unsigned char* tcpbuf = malloc(*len+2);
	tcpbuf[0] = (*len) >> 8;
	tcpbuf[1] = (*len);
	memcpy(tcpbuf+2, buf, *len);
	*len += 2;
	return (void*)tcpbuf;
}

void send_tcp_ans(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen){
	void* pkt = make_tcp_pkt(buf, &len);
	ioth_send(fd, pkt, len, 0);
	free(pkt);
}

static void _fwd_tcp_req(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo, uint8_t dnsn){
	void* pkt = make_tcp_pkt(buf, &len);
	if(send(qfd[dnsn], pkt, len, 0) > 0){
		printf("sent to qfd\n");
		add_request(queue_h, hash_h, fd, dnsn, pinfo, from, fromlen);	
	} else {
		perror("tcp fwd req");
	}
	free(pkt);
}
void fwd_tcp_req(int fd, unsigned char* buf, ssize_t len, 
		struct sockaddr_storage* from, socklen_t fromlen, struct pktinfo* pinfo){
	_fwd_tcp_req(fd, buf, len, from, fromlen, pinfo, 0);
}

//returns 0 on success, -1 on failure
//on success changes state to pkt recving
//on failure client fd gets closed, querier fd retries
int recv_len(int fd, struct conn *data, 
		ssize_t recv_fun(int sockfd, void *buf, size_t len, int flags)){
    unsigned char *buf = malloc(IOTHDNS_TCP_MAXBUF);
    if(recv_fun(fd, buf, 2, 0) < 2){
        //wrong format or error
        printf("bad length recv\n");
		free(buf);
        return -1;
    }
    uint16_t pktlen = (buf[0] << 8 | buf[1]);
    printf("pktlen: %d\n", pktlen);
	//not taking length bytes into buffer, there is no need once saved
	//since it will be parsed as a udp packet anyway
    data->buf = buf;
    data->buflen = 0;
    data->pktlen = pktlen;
	return 0;
}
void recv_req_len(int fd, struct clientconn* data){
	if(recv_len(fd, (struct conn*)data, ioth_recv) == -1){
		epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
		close(fd);
		free(data);
	} else{
		data->state = RECV_REQ_PKT;
	}
}
void recv_ans_len(int fd, struct conn* data){
	if(recv_len(fd, data, recv) == 0){
		data->state = RECV_ANS_PKT;
	} 
}

//on unfinished read state is unchanged
//on finished read parses request/answer and resets state
//on failure client fd gets closed, querier fd resets state
int recv_pkt(int fd, struct conn *data, 
		ssize_t recv_fun(int sockfd, void *buf, size_t len, int flags)){
    unsigned char* buf = data->buf;
    ssize_t len;
    if((len=recv_fun(fd, buf+data->buflen, (data->pktlen)-(data->buflen), 0)) <= 0){
        //wrong format or error
		perror("recv req pkt");
		return -1;
    }
    printf("pktlen:%d buflen: %lu len: %lu\n", data->pktlen, data->buflen+len, len);
    if((len + data->buflen) == data->pktlen){
    //finished read
        printf("recv_req complete read\n");
		return 1;
    } else if((len + data->buflen) < data->pktlen){
    //unfinished read
        printf("recv_req incomplete read\n");
        data->buflen += len;
		return 0;
    } else {
    //wrong format
		return -1;
    }
}
void recv_req_pkt(int fd, struct clientconn *data){
	int res = recv_pkt(fd, (struct conn*)data, ioth_recv);
	switch(res){
		case 1:
			parse_req(fd, data->buf, data->pktlen, &data->from,
					data->fromlen, fwd_tcp_req, send_tcp_ans);
			data->state = RECV_REQ_LEN;
			if(data->buf != NULL) free(data->buf);
			data->buf = NULL;
			break;
		case -1:
			epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
			close(fd);
			if(data->buf != NULL) free(data->buf);
			free(data);
			break;
	}
}
void recv_ans_pkt(int fd, struct conn *data){
	int res = recv_pkt(fd, (struct conn*)data, recv);
	switch(res){
		case 1:
			parse_ans(hash_h, data->buf, data->pktlen, send_tcp_ans);
			data->state = RECV_ANS_LEN;
			if(data->buf != NULL) free(data->buf);
			data->buf = NULL;
			break;
		case -1:
			//reset data but don't close thread socket
			printf("resetting...\n");
			if(data->buf != NULL) free(data->buf);
			data->buflen = 0;
			data->pktlen = 0;
			free(data);
			break;
	}
}

struct querier_args {
	int sfd;
	struct sockaddr_in6* dnsaddr;
};
void* run_querier(void* args){
	struct querier_args* qa = (struct querier_args*)args;
	int sfd = qa->sfd;
	struct sockaddr_in6* dnsaddr = qa->dnsaddr;
	int mfd;
	unsigned char buf[IOTHDNS_TCP_MAXBUF];
	int connected = 0;
	int i, nbytes, count;
	struct epoll_event event, events[MAX_EVENTS];
	memset(&event, 0, sizeof(struct epoll_event));

	efd = epoll_create1(0);

    event.events = EPOLLIN;
    event.data.fd = sfd;
    epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);

	for(;;){
		count = epoll_wait(efd, events, MAX_EVENTS, -1);
		for(i=0; i < count; i++){
			//QUERY REQ FROM MAIN THREAD
			if(events[i].data.fd == sfd){
				//connect to master dns if not yet connected or connection expired
				printf("QUERY REQ FROM SERVER\n");
				printf("event: %x\n", events[i].events);
				//emptying recv buffer before knowing if connection is successful
				//so polling does not loop in case connection fails
				nbytes = recv(sfd, buf, IOTHDNS_TCP_MAXBUF, 0);
				printf("pktlen %d\n", nbytes);
				if(!connected){
					//pthread_mutex_lock(&slock);
					if((mfd = ioth_msocket(query_stack, AF_INET6, SOCK_STREAM, 0)) < 0){
						perror("socket mfd");
						exit(1);
					}
					//pthread_mutex_unlock(&slock);
					if(ioth_connect(mfd, (struct sockaddr*)dnsaddr, sizeof(*dnsaddr)) < 0){
						perror("mfd connect");
						break;
					}
					connected = 1;
					event.events = EPOLLIN | EPOLLRDHUP;
					event.data.fd = mfd;
					epoll_ctl(efd, EPOLL_CTL_ADD, mfd, &event);
				}
				ioth_send(mfd, buf, nbytes, 0);
			}
			//RESPONSE OR HANGUP FROM MASTER DNS
			else{
				printf("EVENT FROM DNS\n");
				//master dns hangup
				printf("event: %x\n", events[i].events);
				if(events[i].events & EPOLLRDHUP){
					printf("hangup\n");
                    epoll_ctl(efd, EPOLL_CTL_DEL, mfd, NULL);
					ioth_close(mfd);
					connected = 0;
				} else if(events[i].events & EPOLLIN){
				//response from master dns
					printf("response\n");
					nbytes = ioth_recv(mfd, buf, IOTHDNS_TCP_MAXBUF, 0);
					printf("pktlen %d\n", nbytes);
					send(sfd, buf, nbytes, 0);
				}
			}
		}
	}
}

static void manage_tcp_req_queue(){
    struct hashq *current = NULL;
	struct hashq *iter;
    long now = get_time_ms();
    while((iter = next_expired_req(queue_h, &current)) != NULL){
		struct dnsreq *req = (struct dnsreq*)iter->data;
		if(verbose){
			printf("################\n");
			printf("Expired ID: %d Query: %s\n", req->h.id, req->h.qname);
		}
		free_id(req->h.id);
		//if there are more available dns we query them aswell
		if(qdns[++req->dnsn].sin6_family != 0){
			char origdom[IOTHDNS_MAXNAME];
			struct pktinfo pinfo;
			pinfo.h = &req->h;
			pinfo.h->id = get_unique_id();
			pinfo.origdom = origdom;
			pinfo.origid = req->origid;
			strncpy(pinfo.origdom, req->origdom, IOTHDNS_MAXNAME);
			pinfo.type = req->type;
			pinfo.opt = req->opt;
			struct iothdns_pkt *pkt = iothdns_put_header(pinfo.h);
			_fwd_tcp_req(req->fd, iothdns_buf(pkt), iothdns_buflen(pkt), 
					&req->addr, req->addrlen, &pinfo, req->dnsn);
			iothdns_free(pkt);
		}
		free_req(iter);
	}
}

void* run_tcp(void* args){
	init_hashq(&queue_h, &hash_h, ID_TABLE_SIZE);

    int sfd, cfd, sp[2];
	int i, count;
	long expire;
	pthread_t query_t;
    struct sockaddr_in6 saddr;
    struct epoll_event event, events[MAX_EVENTS];

    //SERVER
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET6;
    saddr.sin6_addr = in6addr_any;
    saddr.sin6_port = htons(DNS_PORT);
    if((sfd = ioth_msocket(fwd_stack, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0){
        perror("socket sfd");
        exit(1);
    }
	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if(ioth_bind(sfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
        perror("bind tcp");
        exit(1);
    }
	//TODO what should this be
    if(ioth_listen(sfd, 256) < 0){
        perror("listen6");
        exit(1);
    }

	efd = epoll_create1(0);
    
	//QUERY THREADS AND FDS
	//creates a querying thread for each master dns in configuration
	//threads are connected through a unix socket
	i = 0;
	while(qdns[i].sin6_family != 0 && i < MAX_DNS){
		if(socketpair(AF_LOCAL, SOCK_STREAM, 0, sp) < 0){
			perror("socketpair");
			exit(1);
		}
		qfd[i] = sp[0];
		struct querier_args* qa = malloc(sizeof(struct querier_args));
		*qa = (struct querier_args){sp[1], &qdns[i]};
		pthread_create(&query_t, NULL, run_querier, (void*)qa);
		event.events = EPOLLIN;
		event.data.ptr = malloc(sizeof(struct conn));
		QEFD(event) = qfd[i];
		QESTATE(event) = RECV_ANS_LEN;
		epoll_ctl(efd, EPOLL_CTL_ADD, qfd[i], &event);
		i++;
	}
	
	//SERVER FD
    event.events = EPOLLIN;
    event.data.ptr = malloc(sizeof(struct clientconn));
    CEFD(event) = sfd;
    CESTATE(event) = LISTENER;
    epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);


    for(;;){
        count = epoll_wait(efd, events, MAX_EVENTS, dnstimeout);
		if(count == 0){
            //if it times out we check for expired requests
            manage_tcp_req_queue();
			expire = set_timer(dnstimeout);
            continue;	
		}
        for(i=0; i < count; i++){
            switch(((struct conn*)(events[i].data.ptr))->state){
                case LISTENER:
                    printf("connection, event: %x\n", events[i].events);
					struct sockaddr_storage caddr;
					socklen_t caddrlen = sizeof(caddr);
					//accept is non-blocking, will immediately fail if no client
                    if((cfd = ioth_accept(sfd, (struct sockaddr*)&caddr, &caddrlen)) <= 0){
                        perror("accept");
                        break;
                    }
                    event.events = EPOLLIN | EPOLLRDHUP;
                    event.data.ptr = malloc(sizeof(struct clientconn));
                    CEFD(event) = cfd;
                    CESTATE(event) = RECV_REQ_LEN;
					CEADDR(event) = caddr;
					CEADDRLEN(event) = caddrlen;
                    epoll_ctl(efd, EPOLL_CTL_ADD, cfd, &event);
                    break;
                case RECV_REQ_LEN:
                    if(events[i].events & EPOLLRDHUP){
                        //connection closed from client, m8b check pending queries
                        printf("EPOLLRDHUP CLIENT\n");
                        ioth_close(CEFD(events[i]));
                        epoll_ctl(efd, EPOLL_CTL_DEL, CEFD(events[i]), NULL);
                        free((struct clientconn*)(events[i].data.ptr));
                    } else {
                        printf("POLLIN CLIENT LEN\n");
                        recv_req_len(CEFD(events[i]), (struct clientconn*)(events[i].data.ptr));
                    }
                    break;
                case RECV_REQ_PKT:
                    if(events[i].events & EPOLLRDHUP){
                        //connection closed from client, m8b check pending queries
                        printf("EPOLLRDHUP CLIENT\n");
                        ioth_close(CEFD(events[i]));
                        epoll_ctl(efd, EPOLL_CTL_DEL, CEFD(events[i]), NULL);
                        if(CEBUF(events[i]) != NULL) free(CEBUF(events[i]));
                        free((struct clientconn*)(events[i].data.ptr));
                    } else {
                        printf("POLLIN CLIENT PKT\n");
                        recv_req_pkt(CEFD(events[i]), (struct clientconn*)(events[i].data.ptr));
                    }
                    break;
				case RECV_ANS_LEN:
					//receive response
					printf("POLLIN SERVER LEN\n");
					recv_ans_len(QEFD(events[i]), (struct conn*)(events[i].data.ptr));
					break;
				case RECV_ANS_PKT:
					//receive response
					printf("POLLIN SERVER PKT\n");
					recv_ans_pkt(QEFD(events[i]), (struct conn*)(events[i].data.ptr));
					break;
            }
        }
		if(check_timer_expire(expire)){
			manage_tcp_req_queue();
			expire = set_timer(dnstimeout);
		}
    }
}

