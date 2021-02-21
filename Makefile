CC=gcc
CFLAGS=-I. -g -Wall

OBJS=dns.o utils.o config.o req_queue.o udp_dns.o tcp_dns.o parse_dns.o revdb.o newconfig.o

dns: $(OBJS)
	$(CC) -g -o dns $(OBJS) -liothdns -lioth -liothconf -liothaddr -lpthread -lconfig

clean:
	rm -f dns *.o

