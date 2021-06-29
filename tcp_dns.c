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
#include "tcpfd_data.h"
#include "id_table.h"
#include "config.h"
#include "utils.h"
#include "const.h"

//EPOLL
#define MAX_EVENTS 2048
#define EFD(event) (((struct conn*)(event.data.ptr))->fd)
#define ESTATE(event) (((struct conn*)(event.data.ptr))->state)
#define EBUF(event) (((struct clientconn*)(event.data.ptr))->buf)
#define CEADDR(event) (((struct clientconn*)(event.data.ptr))->from)
#define CEADDRLEN(event) (((struct clientconn*)(event.data.ptr))->fromlen)

//STATE
#define LISTENER 0
#define RECV_REQ_LEN 1
#define RECV_REQ_PKT 2
#define RECV_ANS_LEN 3
#define RECV_ANS_PKT 4
#define THREAD_MSG 5

static __thread int efd; 
static int qfd[MAX_DNS], msgfd[MAX_DNS];

//basic struct
struct conn {
	int fd;
	uint8_t state;
};

//struct for connections from master dns
struct serverconn {
	int fd;
	uint8_t state;
    unsigned char* buf;
    ssize_t buflen;
    uint16_t pktlen;
	int tfd;
};

//struct for connection between threads
struct threadconn {
	int fd;
	uint8_t state;
	struct serverconn *connptr;
};


//allocates tcp dns packet from udp packet
static void *make_tcp_pkt(void* buf, ssize_t *len){
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
		printlog(LOG_DEBUG, "Forwarding TCP request to query thread.\n");
		add_request(fd, dnsn, buf, len, pinfo, from, fromlen);	
	} else {
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error forwarding TCP request to query thread: %s\n", errbuf);
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
static int recv_len(int fd, struct serverconn *data, 
		ssize_t recv_fun(int sockfd, void *buf, size_t len, int flags)){
    unsigned char *buf = malloc(IOTHDNS_TCP_MAXBUF);
    if(recv_fun(fd, buf, 2, 0) < 2){
        //wrong format or error
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error receiving TCP request length from fd %d: %s\n", fd, errbuf);
		free(buf);
		data->buf = NULL;
        return -1;
    }
    uint16_t pktlen = (buf[0] << 8 | buf[1]);
	//not taking length bytes into buffer, there is no need once saved
	//since it will be parsed as a udp packet anyway
    data->buf = buf;
    data->buflen = 0;
    data->pktlen = pktlen;
	return 0;
}
static void recv_req_len(int fd, struct clientconn* data){
	if(recv_len(fd, (struct serverconn*)data, ioth_recv) == -1){
		epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
		free_fd(fd);
		close(fd);
	} else{
		data->state = RECV_REQ_PKT;
	}
}
static void recv_ans_len(int fd, struct serverconn* data){
	if(recv_len(fd, data, recv) == 0){
		data->state = RECV_ANS_PKT;
	} else {
		//reset buffer
		//send close server connection signal in querier thread
		char buf[] = {'\0'};
		send(data->tfd, buf, 1, 0);		
	}
}

//on unfinished read state is unchanged
//on finished read parses request/answer and resets state
//on failure client fd gets closed, querier fd resets state
static int recv_pkt(int fd, struct serverconn *data, 
		ssize_t recv_fun(int sockfd, void *buf, size_t len, int flags)){
    unsigned char* buf = data->buf;
    ssize_t len;
    if((len=recv_fun(fd, buf+data->buflen, (data->pktlen)-(data->buflen), 0)) <= 0){
        //wrong format or error
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error receiving TCP request packet from fd %d: %s\n", fd, errbuf);
		return -1;
	}
	printlog(LOG_DEBUG, "Received TCP packet. Expecting len: %d Current len: %lu Pkt len: %lu\n", 
			data->pktlen, data->buflen+len, len);
    if((len + data->buflen) == data->pktlen){
    //finished read
        printlog(LOG_DEBUG, "recv_req completed packet reassembly.\n");
		return 1;
    } else if((len + data->buflen) < data->pktlen){
    //unfinished read
        printlog(LOG_DEBUG, "recv_req incomplete packet.\n");
        data->buflen += len;
		return 0;
    } else {
    //wrong format
		return -1;
    }
}
static void recv_req_pkt(int fd, struct clientconn *data){
	int res = recv_pkt(fd, (struct serverconn*)data, ioth_recv);
	switch(res){
		case 1:
			if(parse_req(fd, data->buf, data->pktlen, &data->from,
					data->fromlen, fwd_tcp_req, send_tcp_ans) != 0){
				//not a valid query packet/not authorized
				epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
				free_fd(fd);
				close(fd);		
			} else {
				data->state = RECV_REQ_LEN;
				if(data->buf != NULL) free(data->buf);
				data->buf = NULL;
			}
			break;
		case -1:
			epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
			free_fd(fd);
			close(fd);
			break;
	}
}
static void recv_ans_pkt(int fd, struct serverconn *data){
	int res = recv_pkt(fd, (struct serverconn*)data, recv);
	switch(res){
		case 1:
			parse_ans(data->buf, data->pktlen, send_tcp_ans);
			data->state = RECV_ANS_LEN;
			if(data->buf != NULL) free(data->buf);
			data->buf = NULL;
			break;
		case -1:
			//reset data and empty buffer
			//send close server connection signal in querier thread
			data->state = RECV_ANS_LEN;
			if(data->buf != NULL) free(data->buf);
			data->buf = NULL;
			char buf[] = {'\0'};
			send(data->tfd, buf, 1, 0);	
			break;
	}
}

struct querier_args {
	int sfd;
	int msgfd;
	struct sockaddr_in6* dnsaddr;
};
void* run_querier(void* args){
	struct querier_args* qa = (struct querier_args*)args;
	int sfd = qa->sfd;
	int msgfd = qa->msgfd;
	struct sockaddr_in6* dnsaddr = qa->dnsaddr;
	int mfd;
	unsigned char buf[IOTHDNS_TCP_MAXBUF];
	int connected = 0;
	int i, nbytes, count;

	char addrbuf[64];
	printsockaddr6(addrbuf, dnsaddr);

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
				printlog(LOG_DEBUG, "TCP query request from main thread in querier of DNS %s.\n",
						addrbuf);
				//emptying recv buffer before knowing if connection is successful
				//so polling does not loop in case connection fails
				nbytes = recv(sfd, buf, IOTHDNS_TCP_MAXBUF, 0);
				if(!connected){
					if((mfd = ioth_msocket(query_stack, AF_INET6, SOCK_STREAM, 0)) < 0){
						char errbuf[64];
						strerror_r(errno, errbuf, 64);
						printlog(LOG_ERROR, "Error creating TCP querying socket to %s: %s\n", addrbuf, errbuf);
						exit(1);
					}
					if(ioth_connect(mfd, (struct sockaddr*)dnsaddr, sizeof(*dnsaddr)) < 0){
						char errbuf[64];
						strerror_r(errno, errbuf, 64);
						printlog(LOG_ERROR, "Error creating TCP querying socket to %s: %s\n", addrbuf, errbuf);
						break;
					}
					connected = 1;
					event.events = EPOLLIN | EPOLLRDHUP;
					event.data.fd = mfd;
					epoll_ctl(efd, EPOLL_CTL_ADD, mfd, &event);
				}
				if(ioth_send(mfd, buf, nbytes, 0) <= 0){			
					char errbuf[64];
					strerror_r(errno, errbuf, 64);
					printlog(LOG_ERROR, "Error forwarding data to DNS %s: %s\n", addrbuf,  errbuf);
				}
			}
			//SIGNAL FROM MAIN THREAD
			else if(events[i].data.fd == msgfd) {
				printlog(LOG_DEBUG, "Received error signal from main thread in TCP querier of DNS %s.\n",
						addrbuf);
				//packet error, close connection
				epoll_ctl(efd, EPOLL_CTL_DEL, mfd, NULL);
				ioth_close(mfd);
				connected = 0;
				char buf[BUFSIZE];
				recv(mfd, buf, BUFSIZE, 0);
			}
			//RESPONSE OR HANGUP FROM MASTER DNS
			else{
				//master dns hangup
				if(events[i].events & EPOLLRDHUP){
					printlog(LOG_DEBUG, "Hangup from TCP DNS %s\n", addrbuf);
                    epoll_ctl(efd, EPOLL_CTL_DEL, mfd, NULL);
					ioth_close(mfd);
					connected = 0;
				} else if(events[i].events & EPOLLIN){
				//response from master dns
					printlog(LOG_DEBUG, "TCP response from DNS %s.\n", addrbuf);
					if((nbytes = ioth_recv(mfd, buf, IOTHDNS_TCP_MAXBUF, 0)) <= 0){
						char errbuf[64];
						strerror_r(errno, errbuf, 64);
						printlog(LOG_ERROR, "Error receiving data from TCP DNS %s: %s\n", addrbuf,  errbuf);
					}
					send(sfd, buf, nbytes, 0);
				}
			}
		}
	}
}

static void manage_tcp_req_queue(){
    struct hashq *current = NULL;
	struct hashq *iter;
    while((iter = next_expired_req(&current)) != NULL){
		struct dnsreq *req = (struct dnsreq*)iter->data;
		printlog(LOG_DEBUG, "Expired UDP Request ID: %d Query: %s\n", req->h.id, req->h.qname);
		//free id previously in use
		free_id(req->h.id);
		//if there are more available dns we query them aswell
		if(qdns[++req->dnsn].sin6_family != 0){
			char origdom[IOTHDNS_MAXNAME];
			struct pktinfo pinfo;
			
			//generate new id
			pinfo.h = &req->h;
			pinfo.h->id = get_unique_id();
			req->pktbuf[0] = pinfo.h->id >> 8;
			req->pktbuf[1] = pinfo.h->id;
			
			pinfo.origdom = origdom;
			pinfo.origid = req->origid;
			strncpy(pinfo.origdom, req->origdom, IOTHDNS_MAXNAME);
			pinfo.type = req->type;
			pinfo.opt = req->opt;
			_fwd_tcp_req(req->fd, req->pktbuf, req->pktlen, 
					&req->addr, req->addrlen, &pinfo, req->dnsn);
		}
		free_req(iter);
	}
}

//Closes inactive client connections and frees associated data structures
static void manage_fd_timeout(){
	struct hashq *current = NULL;
	struct hashq *iter;
    while((iter = next_expired_fd(&current)) != NULL){
		struct tcpfd_data *data = (struct tcpfd_data*)iter->data;
		printlog(LOG_DEBUG, "TCP FD %d connection timeout.\n", data->fd);
		ioth_close(data->fd);
		epoll_ctl(efd, EPOLL_CTL_DEL, data->fd, NULL);
		free_fd(data->fd);	
	}
}

void* run_tcp(void* args){
	init_reqhashq();
	init_fdhashq();

    int sfd, cfd, sp1[2], sp2[2];
	int i, count;
	long expire;
	pthread_t query_t;
    struct sockaddr_in6 saddr;
    struct epoll_event event, events[MAX_EVENTS];

    //SERVER
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET6;
	if(bindaddr != NULL){
		saddr.sin6_addr = *bindaddr;
	} else {
		saddr.sin6_addr = in6addr_any;
	}
    saddr.sin6_port = htons(DNS_PORT);
    if((sfd = ioth_msocket(fwd_stack, AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0){
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error creating TCP accepting socket: %s\n", errbuf);
        exit(1);
    }
	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){0}, sizeof(int));
    if(ioth_bind(sfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error binding TCP accepting socket: %s\n", errbuf);
        exit(1);
    }
	//TODO what should this be
    if(ioth_listen(sfd, LISTEN_QUEUE) < 0){
		char errbuf[64];
		strerror_r(errno, errbuf, 64);
		printlog(LOG_ERROR, "Error setting TCP listening socket: %s\n", errbuf);
        exit(1);
    }

	efd = epoll_create1(0);
    
	//QUERY THREADS AND FDS
	//creates a querying thread for each master dns in configuration
	//threads are connected through unix sockets
	i = 0;
	while(qdns[i].sin6_family != 0 && i < MAX_DNS){
		//socket for dns packets forwarding
		if(socketpair(AF_LOCAL, SOCK_STREAM, 0, sp1) < 0){
			char errbuf[64];
			strerror_r(errno, errbuf, 64);
			printlog(LOG_ERROR, "Error creating socketpair: %s\n", errbuf);
			exit(1);
		}
		//socket for signal passing
		qfd[i] = sp1[0];
		if(socketpair(AF_LOCAL, SOCK_STREAM, 0, sp2) < 0){
			char errbuf[64];
			strerror_r(errno, errbuf, 64);
			printlog(LOG_ERROR, "Error creating socketpair: %s\n", errbuf);
			exit(1);
		}
		msgfd[i] = sp2[0];
		//setup EPOLL for both fds
		//forward fd
		event.events = EPOLLIN;
		void* tmp = event.data.ptr = malloc(sizeof(struct serverconn));
		EFD(event) = qfd[i];
		ESTATE(event) = RECV_ANS_LEN;
		EBUF(event) = NULL;
		((struct serverconn*)event.data.ptr)->tfd = msgfd[i];
		epoll_ctl(efd, EPOLL_CTL_ADD, qfd[i], &event);
		//signal passing fd
		event.events = EPOLLIN;
		event.data.ptr = malloc(sizeof(struct threadconn));
		EFD(event) = msgfd[i];
		ESTATE(event) = THREAD_MSG;
		((struct threadconn*)event.data.ptr)->connptr = tmp;
		epoll_ctl(efd, EPOLL_CTL_ADD, msgfd[i], &event);
		//launch thread
		struct querier_args* qa = malloc(sizeof(struct querier_args));
		*qa = (struct querier_args){sp1[1], sp2[1], &qdns[i]};
		pthread_create(&query_t, NULL, run_querier, (void*)qa);
		i++;
	}
	
	//SERVER FD
    event.events = EPOLLIN;
    event.data.ptr = malloc(sizeof(struct clientconn));
    EFD(event) = sfd;
    ESTATE(event) = LISTENER;
    epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
	
	//set time limit for suspended request queue check
	expire = set_timer(dnstimeout);
    for(;;){
        count = epoll_wait(efd, events, MAX_EVENTS, dnstimeout);
		if(count == 0){
            //if it times out we check for expired requests
            manage_tcp_req_queue();
			manage_fd_timeout();
			expire = set_timer(dnstimeout);
            continue;	
		}
        for(i=0; i < count; i++){
            switch(((struct conn*)(events[i].data.ptr))->state){
                case LISTENER:
					{
					struct sockaddr_storage caddr;
					socklen_t caddrlen = sizeof(caddr);
					//accept is non-blocking, will immediately fail if no client
                    if((cfd = ioth_accept(sfd, (struct sockaddr*)&caddr, &caddrlen)) <= 0){
						if(errno != EWOULDBLOCK){
							char errbuf[64];
							strerror_r(errno, errbuf, 64);
							printlog(LOG_ERROR, "Error accepting new TCP connection: %s\n", errbuf);
						}
                        break;
                    }
					//add fd in timeout queue
                    event.events = EPOLLIN | EPOLLRDHUP;
                    event.data.ptr = malloc(sizeof(struct clientconn));
                    EFD(event) = cfd;
                    ESTATE(event) = RECV_REQ_LEN;
					EBUF(event) = NULL;
					CEADDR(event) = caddr;
					CEADDRLEN(event) = caddrlen;
                    epoll_ctl(efd, EPOLL_CTL_ADD, cfd, &event);
					add_fd(cfd, event.data.ptr);
                    break;
					}
                case RECV_REQ_LEN:
                    if(events[i].events & EPOLLRDHUP){
                        //connection closed from client, m8b check pending queries
						char addrbuf[64];
						printsockaddr6(addrbuf, (struct sockaddr_in6*)&CEADDR(events[i]));
						printlog(LOG_DEBUG, "TCP client %s hangup.\n", addrbuf);
                        ioth_close(EFD(events[i]));
                        epoll_ctl(efd, EPOLL_CTL_DEL, EFD(events[i]), NULL);
						free_fd(EFD(events[i]));
                    } else {
						//update activity time
						update_fd(EFD(events[i]));
                        recv_req_len(EFD(events[i]), (struct clientconn*)(events[i].data.ptr));
                    }
                    break;
                case RECV_REQ_PKT:
                    if(events[i].events & EPOLLRDHUP){
                        //connection closed from client, m8b check pending queries
						char addrbuf[64];
						printsockaddr6(addrbuf, (struct sockaddr_in6*)&CEADDR(events[i]));
						printlog(LOG_DEBUG, "TCP client %s hangup.\n", addrbuf);
                        ioth_close(EFD(events[i]));
                        epoll_ctl(efd, EPOLL_CTL_DEL, EFD(events[i]), NULL);
						free_fd(EFD(events[i]));
                    } else {
						//update activity time
						update_fd(EFD(events[i]));
                        recv_req_pkt(EFD(events[i]), (struct clientconn*)(events[i].data.ptr));
                    }
                    break;
				case RECV_ANS_LEN:
					//receive response
					recv_ans_len(EFD(events[i]), (struct serverconn*)(events[i].data.ptr));
					break;
				case RECV_ANS_PKT:
					//receive response
					recv_ans_pkt(EFD(events[i]), (struct serverconn*)(events[i].data.ptr));
					break;
				/*
				case THREAD_MSG:
					//do something if needed
					break;
				*/
            }
        }
		if(check_timer_expire(expire)){
			manage_tcp_req_queue();
			manage_fd_timeout();
			expire = set_timer(dnstimeout);
		}
    }
}
