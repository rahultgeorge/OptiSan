#include <math.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include "allocator.h"


/**
 * Mark the relevant slots for heap objects
 * @param ptr - address of the object
 * @param size - size in bytes (must be a power of two)
 * @param used  - 0 means set the size(log2) as is or else mark used/invalid (MSB)
 */
static inline void table_mark(char *ptr, size_t size, unsigned char used) {
    assert((size & (size - 1)) == 0);
    unsigned int log2_size = get_log2(size);
    slot_id_type first_slot_id = get_slot_id(ptr);
    slot_id_type slot_id = first_slot_id;
    size_t num_of_slots = (size_t) (size / SLOT_SIZE);

    for (size_t i = 0; i < num_of_slots; i++) {
        // TODO(aanastasov): try to optimize by just setting the first slot not all of them
        set_slot_metadata(slot_id, form_metadata(log2_size, used));
        slot_id += 1;
    }

    //Ensures we marked the right slots
    assert(slot_id - first_slot_id == num_of_slots);
}

/**
 * Return slot id used only for heap objects
 * @param ptr
 * @return
 */
static inline slot_id_type get_slot_id(char *ptr) {

    slot_id_type slot_id = 0;
    slot_id = ((slot_id_type) ptr >> get_log2(SLOT_SIZE));
    return slot_id;
}

static inline unsigned char get_slot_metadata(slot_id_type slot_id) {
    return (unsigned char) baggy_bounds_table[slot_id];
}

static inline void set_slot_metadata(slot_id_type slot_id, unsigned char value) {
    baggy_bounds_table[slot_id] = value;
}

/**
 *
 * @param logsize - log of allocation size to the base 2
 * @param is_used - 1 or 0. Can be used to created invalid
 * @return - Returns the metadata (1 byte)
 */
static inline unsigned char form_metadata(unsigned char logsize, unsigned char is_used) {
    return logsize | (is_used << 7);
}

static inline unsigned char is_used(unsigned char metadata) {
    return (metadata & 128) >> 7;
}

static inline unsigned char get_logsize(unsigned char metadata) {
    return metadata & 127;
}

// returns smallest x such that 2^x >= size
// requires size > 0
static inline unsigned int get_log2(size_t size) {
    unsigned char res = 0;
    size--;
    while (size > 0) {
        size >>= 1;
        ++res;
    }
    return res;
}

static inline bool is_aligned(const void *ptr, size_t allocation_size) {
    return ((size_t) ptr & (allocation_size - 1)) == 0;
}

static inline char *increase_heap_size_and_get_ptr(size_t size_to_allocate,
                                                   unsigned int *_bin_id) {
    size_t size_allocated;
    char *ptr = NULL;
    char *aligned_ptr = NULL;
    heap_end = sbrk(0);

    do {
        unsigned int bin_id = 0;
        //TODO - WHat does this do? How do they figure out what block needs to be made?
        //Adds blocks (remember buddy allocator) so say
        while ((heap_size & ((size_t) 1 << bin_id)) == 0) {
            bin_id++;
        }
        size_allocated = (size_t) 1 << bin_id;
        *_bin_id = bin_id;
        ptr = (char *) sbrk(size_allocated);
        if (ptr < 0) { // sbrk failed
            break;
        }
        if (size_allocated >= SLOT_SIZE) {
            // The ptr needs to be aligned to the allocation size not just the slot boundary
            if (!is_aligned(ptr, size_allocated)) {
                //Align it
                aligned_ptr = (char *) (((slot_id_type) (ptr + size_allocated - 1)) & ~(size_allocated - 1));
                assert(is_aligned(aligned_ptr, size_allocated) && "Failed to align it");
                //Extra space needed for the alignment
                size_t extra_bytes = aligned_ptr - ptr;
                if (sbrk(extra_bytes) < 0) {
                    break;
                }
                //TODO - Can put the bytes used for alignment in another bin
                ptr = aligned_ptr;
//                heap_size += extra_bytes;
                heap_end += extra_bytes;
            }
            table_mark(ptr, size_allocated, FREE);
            list_append((list_node_t *) ptr, bin_id);
        } else {
            // too small (can't fit one SLOT_SIZE entry), throw away
        }
        heap_end += size_allocated;
        heap_size += size_allocated;
        assert(heap_end == (char *) sbrk(0));
    } while (size_to_allocate > size_allocated);
    return ptr;
}


void buddy_allocator_init() {

    heap_start = (char *) 0;
    heap_end = (char *) sbrk(0);  // allocated heap is [heap_start, heap_end)
    heap_start = heap_end;

    // initialize the free lists
    unsigned int bin_id;
    for (bin_id = 0; bin_id < NUM_BINS; ++bin_id) {
        dummy_first[bin_id] = (list_node_t *) sbrk(sizeof(list_node_t));
        dummy_last[bin_id] = (list_node_t *) sbrk(sizeof(list_node_t));
        dummy_first[bin_id]->is_dummy = 1;
        dummy_first[bin_id]->prev = NULL;
        dummy_first[bin_id]->next = dummy_last[bin_id];
        dummy_last[bin_id]->is_dummy = 1;
        dummy_last[bin_id]->prev = dummy_first[bin_id];
        dummy_last[bin_id]->next = NULL;
    }


    heap_end = (char *) sbrk(0);  // allocated heap is [heap_start, heap_end)

    // align heap_end to a multiple of SLOT_SIZE
    size_t slot_size_reminder = SLOT_SIZE - ((unsigned long long) heap_end) % SLOT_SIZE;
    if (slot_size_reminder < SLOT_SIZE) {
        sbrk(slot_size_reminder);  // throw away
        heap_end = (char *) sbrk(0);
    }
    heap_size = ((unsigned long long) heap_end) - ((unsigned long long) heap_start);
    assert(((unsigned long long) heap_end) % SLOT_SIZE == 0);

    //Smart monitor:New indexing scheme less internal fragmentation

    /*
//     update the baggy table so the data after TABLE_END and before the beginning of the real heap can't be reused

    slot_id_type slot_id = 0;
    while (((unsigned long long) heap_start) + slot_id * SLOT_SIZE < ((unsigned long long) heap_end)) {
        set_slot_metadata(slot_id, form_metadata(get_log2(SLOT_SIZE), USED));
        slot_id++;
    }
     */

    // Smart monitor: Setting heap start to current heap state (i.e which cannot be compromised if subsequent stack and heap operations are protected and loader etc is protected)
    heap_start = heap_end;

}

void *baggy_malloc(size_t size) {
    if (size == 0) {
        size = SLOT_SIZE;
    }
    // allocate the smallest sufficient power of two block >= size
    size_t size_to_allocate = (size_t) 1 << ((unsigned int) get_log2(size));
    if (size_to_allocate < SLOT_SIZE) {
        size_to_allocate = SLOT_SIZE;
    }
    char *ptr = NULL;
    unsigned char log2 = get_log2(size_to_allocate);
    unsigned int bin_id;
    // find first-fit block
    for (bin_id = log2; bin_id < NUM_BINS; ++bin_id) {
        if (dummy_first[bin_id]->next->is_dummy == 0)
            break;
    }

    if (bin_id < NUM_BINS) {
        // grab the first element from the list
        ptr = (void *) dummy_first[bin_id]->next;
    } else {
        // try increasing the size of the heap until can allocate the required block
        ptr = (void *) increase_heap_size_and_get_ptr(size_to_allocate, &bin_id);
        if (ptr < 0) {
            return NULL;
        }
    }

    assert(ptr != NULL);
    assert(!is_used(get_slot_metadata(get_slot_id(ptr))));
    assert(get_logsize(get_slot_metadata(get_slot_id(ptr))) == bin_id);

    // if the block is too big, split into pieces, and populate bins
    // TODO - Check this. When does this occur?
    while (((size_t) 1 << (bin_id - 1)) >= size_to_allocate) {
        char *right_half_ptr = ptr + ((size_t) 1 << (bin_id - 1));
        table_mark(right_half_ptr, (size_t) 1 << (bin_id - 1), FREE);
        list_append((list_node_t *) right_half_ptr, bin_id - 1);
        assert(get_logsize(get_slot_metadata(get_slot_id(right_half_ptr))) ==
               bin_id - 1);
        assert(is_used(get_slot_metadata(get_slot_id(right_half_ptr))) == 0);
        bin_id--;
    }

    // mark as used and return
    table_mark(ptr, (size_t) 1 << bin_id, USED);
    list_remove((list_node_t *) ptr);
    //Update heap end
    heap_end = (char *) sbrk(0);
    return (void *) ptr;
}

/**
 * This seems right
 * @param ptr - Old ptr
 * @param size - New size
 * @return - Ptr corresponding to new size
 */
void *baggy_realloc(void *ptr, size_t size) {
    void *newptr;
    size_t copy_size;

    if (ptr == NULL) {
        return baggy_malloc(size);
    }

    newptr = baggy_malloc(size);
    if (newptr == NULL) {
        return NULL;
    }

    copy_size = (size_t) 1 << get_logsize(get_slot_metadata(get_slot_id(ptr)));
    if (size < copy_size)
        copy_size = size;

    memcpy(newptr, ptr, copy_size);
    //Update heap end
    heap_end = (char *) sbrk(0);

    baggy_free(ptr);
    return newptr;
}

void baggy_free(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    size_t size = (size_t) 1 << get_logsize(get_slot_metadata(get_slot_id(ptr)));
    unsigned int bin_id = get_log2(size);
    table_mark(ptr, size, FREE);
    list_append((list_node_t *) ptr, bin_id);

//    unsigned char try_coalescing = 1;
//    //TODO - Check this buddy allocator. Seems to be buggy
//    do {
//        long long int address = (long long) ptr;
//        unsigned int logsize = get_logsize(get_slot_metadata(get_slot_id(ptr)));
//        long long int buddy_address = ((address >> logsize) ^ 1) << logsize;
//        char *buddy_ptr = (char *) buddy_address;
//        if (get_logsize(get_slot_metadata(get_slot_id(buddy_ptr))) == logsize &&
//            !is_used(get_slot_metadata(get_slot_id(buddy_ptr)))) {
//            char *newptr;
//            if (address < buddy_address) {
//                newptr = (char *) address;
//            } else {
//                newptr = (char *) buddy_address;
//            }
//            list_remove((list_node_t *) ptr);
//            list_remove((list_node_t *) buddy_ptr);
//            bin_id++;
//            size *= 2;
//            table_mark(newptr, size, FREE);
//            list_append((list_node_t *) newptr, bin_id);
//            // TODO(aanastasov): do we need to update all slot entries for this ptr?
//            ptr = newptr;
//        } else {
//            try_coalescing = 0;
//        }
//    } while (try_coalescing);

    //Update heap end
    heap_end = (char *) sbrk(0);

}

void *baggy_calloc(size_t num, size_t size) {
    char *ptr = (char *) baggy_malloc((num * size));
    for (size_t i = 0; i < (size_t) (num * size); i++) {
        ptr[i] = 0;
    }
    //Update heap end
    heap_end = (char *) sbrk(0);
    return ptr;
}

