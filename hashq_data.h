#ifndef HASHQ_DATA_H
#define HASHQ_DATA_H

#include <sys/socket.h>
#include <stdint.h>
#include <time.h>
#include <iothdns.h>

#include "const.h"

//Hashtable+Queue structure
//Extract matching element from hashtable ~O(1)
//
//Given expiration value, extract first expired value
//knowing that if an element is expired it is first in queue O(1)
//as they are in rising order

struct hashq {
	struct hashq *qnext;
	struct hashq *qprev;

	struct hashq *hnext;
	struct hashq *hprev;
	
	long expire;
	void* data;
};

typedef int cmpfun_t(void* arg1, void* arg2);

//Initialize queue and hashtable heads
void init_hashq(struct hashq** queue_h, struct hashq*** hash_h, int tablesize);

//Frees hashq structure and returns data
void* free_hashq(struct hashq* target);

//Returns data of first element of queue if higher than value, else NULL
struct hashq* next_expired_hashq(struct hashq* queue_h, struct hashq** start,
		long value);

//Moves element to tail of queue
void moveto_tail(struct hashq* queue_h, struct hashq* target);

//Returns hashq data according to search function and parameters, else NULL
struct hashq* get_hashq(struct hashq** hash_h, int hashval, 
		int hashsize, void* params, cmpfun_t fun);

//Appends new element to queue and  adds to hashtable in corresponding position
struct hashq* add_hashq(struct hashq* queue_h, struct hashq** hash_h, 
		int hashval, long expire, void* data);

#endif
