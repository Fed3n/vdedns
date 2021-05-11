#ifndef ID_TABLE_H
#define ID_TABLE_H
#include <stdint.h>

//Initialize mutex lock and table
void init_idtable();

//Get unique dns packet ID (does not repeat IDs in suspended packets)
//Fails after a few tries and gives a repeated id
uint16_t get_unique_id();

//Frees used id
void free_id(uint16_t id);



#endif
