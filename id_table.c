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

#define __GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/random.h>

#include "const.h"
#include "utils.h"

static uint8_t id_table[ID_TABLE_SIZE];
static pthread_mutex_t idlock;


void init_idtable(){
	pthread_mutex_init(&idlock, NULL);
	memset(id_table, 0, ID_TABLE_SIZE);
}

//tries to generate unique packet ids across both threads
//algorithm is optimistic and will give up after some tries
//hoping not to cause a packet mismatch
#define MAX_RETRY 8
uint16_t get_unique_id(){
	int i;
	uint16_t id;
	pthread_mutex_lock(&idlock);
	for(i = 0; i < MAX_RETRY; i++){
		id = random();
		if(id_table[id] == 0) {
			id_table[id]++;
			break;
		}
	}
	if(i >= MAX_RETRY) {
		printlog(LOG_ERROR, "Failed to generate unique ID.\n");
		id_table[id]++;
	}
	pthread_mutex_unlock(&idlock);
	return id;
}

void free_id(uint16_t id){
	pthread_mutex_lock(&idlock);
	id_table[id]--;
	pthread_mutex_unlock(&idlock);
}

