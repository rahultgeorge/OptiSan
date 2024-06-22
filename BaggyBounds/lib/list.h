
#define NUM_BINS 49

struct list_node_t {
	struct list_node_t* prev;
	struct list_node_t* next;
	unsigned int is_dummy;
};
typedef struct list_node_t list_node_t;

list_node_t *dummy_first[NUM_BINS];
list_node_t *dummy_last[NUM_BINS];

static inline unsigned int list_empty(unsigned int bin_id) {
	return dummy_first[bin_id]->next->is_dummy;
}

static inline void list_append(list_node_t* ptr, unsigned int bin_id) {
	ptr->is_dummy = 0;
	ptr->prev = dummy_first[bin_id];
	ptr->next = dummy_first[bin_id]->next;
	dummy_first[bin_id]->next->prev = ptr;
	dummy_first[bin_id]->next = ptr;
}

static inline void list_remove(list_node_t* ptr) {
	list_node_t* prev = ptr->prev;
	list_node_t* next = ptr->next;
	ptr->next->prev = prev;
	prev->next = next;
}


