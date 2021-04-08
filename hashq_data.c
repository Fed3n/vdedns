#include <stdlib.h>
#include <stdio.h>

#include "dns.h"
#include "hashq_data.h"
#include "utils.h"

void init_hashq(struct hashq** queue_h, struct hashq*** hash_h, int tablesize){
	*queue_h = calloc(1, sizeof(struct hashq));
	(*queue_h)->qnext = (*queue_h)->qprev = *queue_h;
	int i;
	(*hash_h) = calloc(tablesize, sizeof(struct hashq*));
	for(i=0; i < tablesize; i++){
		(*hash_h)[i] = calloc(1, sizeof(struct hashq));
		(*hash_h)[i]->hnext = (*hash_h)[i]->hprev = (*hash_h)[i];
	}
}

void* free_hashq(struct hashq* target){
	void* data = target->data;
	target->qprev->qnext = target->qnext;
	target->qnext->qprev = target->qprev;
	target->hprev->hnext = target->hnext;
	target->hnext->hprev = target->hprev;
	free(target);
	return data;
}

struct hashq* next_expired_hashq(struct hashq* queue_h, struct hashq** start, long expire){
	struct hashq *res;
	if(*start == NULL) *start = queue_h->qnext;
	if(*start != queue_h && expire > (*start)->expire) {
		res = (*start);
		*start = (*start)->qnext;
		return res;
	}
	return NULL;
}

struct hashq* get_hashq(struct hashq** hash_h, int hashval, 
		void* params, cmpfun_t fun){
	struct hashq *iter;
	for(iter=hash_h[hashval]->hnext; iter != hash_h[hashval]; iter=iter->hnext){
		if(fun(params, iter->data)){
			return iter;
		}
	}
	return NULL;
}

struct hashq* add_hashq(struct hashq* queue_h, struct hashq** hash_h, int hashval, void* data){
	struct hashq* new = malloc(sizeof(struct hashq));
	new->data = data;
	new->qprev = queue_h->qprev;
	queue_h->qprev->qnext = new;
	new->qnext = queue_h;
	queue_h->qprev = new;
	//add to hashtable
	new->hprev = hash_h[hashval]->hprev;
	hash_h[hashval]->hprev->hnext = new;
	new->hnext = hash_h[hashval];
	hash_h[hashval]->hprev = new;
	return new;
}
