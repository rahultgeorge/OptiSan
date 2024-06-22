//
// Created by Rahul Titus George on 10/7/21.
//

#ifndef ALLOCATOR_H

#include "address_constants.h"
#include "list.h"

#define ALLOCATOR_H

//Allocator exposes some variables
char *heap_start;
char *heap_end;
size_t heap_size;  // the size of the heap in bytes

// Buddy allocator constants
//#define NUM_BINS 48
#define FREE 0
#define USED 1

extern void *stack_bottom;

extern slot_id_type max_slot_id;
extern slot_id_type heap_first_legal_slot_id;

extern unsigned char *baggy_bounds_table;

extern list_node_t *dummy_first[NUM_BINS];
extern list_node_t *dummy_last[NUM_BINS];


static inline slot_id_type get_slot_id(char *);

static inline void table_mark(char *, size_t , unsigned char);

static inline unsigned char get_slot_metadata(slot_id_type);

static inline void set_slot_metadata(slot_id_type, unsigned char);

static inline unsigned char form_metadata(unsigned char, unsigned char);

static inline unsigned char is_used(unsigned char);

static inline unsigned char get_logsize(unsigned char);

static inline unsigned int get_log2(size_t);

void *baggy_malloc(size_t);

void *baggy_realloc(void *, size_t);

void baggy_free(void *);

void *baggy_calloc(size_t num, size_t size);


#endif //ALLOCATOR_H
