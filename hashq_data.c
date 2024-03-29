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
		int hashsize, void* params, cmpfun_t fun){
	struct hashq *iter;
	int pos = hashval%hashsize; 
	for(iter=hash_h[pos]->hnext; iter != hash_h[pos]; iter=iter->hnext){
		if(fun(params, iter->data)){
			return iter;
		}
	}
	return NULL;
}

void moveto_tail(struct hashq* queue_h, struct hashq* target, long expire){
    target->expire = expire;
	target->qprev->qnext = target->qnext;
	target->qnext->qprev = target->qprev;
	target->qprev = queue_h->qprev;
	target->qnext = queue_h;
	queue_h->qprev->qnext = target;
	queue_h->qprev = target;
}

struct hashq* add_hashq(struct hashq* queue_h, struct hashq** hash_h, 
		int hashval, long expire, void* data){
	struct hashq* new = malloc(sizeof(struct hashq));
	new->expire = expire;
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
