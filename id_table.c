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
	//printf("ID AMOUNT IS NOW %d\n", id_table[id]);
	pthread_mutex_unlock(&idlock);
}

