CC=gcc
CFLAGS=-I. -g -Wall

OBJS=dns.o utils.o config.o req_queue.o udp_dns.o parse_dns.o revdb.o

dns: $(OBJS)
	$(CC) -g -o dns $(OBJS) -liothdns -lioth -liothconf -liothaddr -lpthread

clean:
	rm -f dns *.o

