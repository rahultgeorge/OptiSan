#include "address_constants.h"
#include <assert.h>
#include <unistd.h>
#include "math.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Functions exposed which we can invoke when we instrument
 * Related to saving and retrieving bounds
 * The bounds check itself can be inlined so we inline
 * TODO- Check if should expose a function which does the entire process  (read table and check)
 */

extern char *baggy_bounds_table;
extern void *stack_bottom;
extern char *heap_start;
extern slot_id_type max_slot_id;
extern slot_id_type heap_first_legal_slot_id;

/**
 * No longer used.
 * Called for checks - using stack bottom based indexing scheme (Not original indexing scheme) only for stack objects
 * Other objects map to slot id 0 (always true)
 * @param ptr  - pointer
 * @return slot id
 */
/* slot_id_type get_slot_id(slot_id_type ptr)
{

    // In case we mark something as OOB (MSB set) and there is a subsequent check avoid de-referencing based on that
    if (ptr < 0)
        return 0;

    int ref = -1;
    // Essentially scaled the index down for both stack and heap.
    slot_id_type slot_id = 0;

    // STACK ONLY
    if (((slot_id_type)(&ref) > ptr))
        return slot_id;

    // For cmd line arguments
    if (ptr > (slot_id_type)stack_bottom)
        return slot_id;

    slot_id_type offset = (slot_id_type)stack_bottom - (slot_id_type)ptr;
    long double r = ceill((long double)(offset / (long double)SLOT_SIZE));
    // Probably not a stack address. (AVOID SUCH CHECKS)
    if (r > max_slot_id)
    {
        printf("Stack Ptr %p failed to find slot \n ", (void *)ptr);
        exit(0);
    }
    slot_id = max_slot_id - ((slot_id_type)r);
    if (slot_id > max_slot_id)
    {
        printf("Stack Ptr %p, slot id %llu, max slot id %llu \n ", (void *)ptr, slot_id, max_slot_id);
    }

    return slot_id;
}
 */

static inline unsigned int get_log2(size_t size)
{
    unsigned char res = 0;
    size--;
    while (size > 0)
    {
        size >>= 1;
        ++res;
    }
    return res;
}

/**
 *  Save bounds in table (used for stack objects and globals) (can be optimized TODO- check this)
 * @param loc  - address
 * @param allocation_size_lg  - log(allocation) (base 2)
 */
void baggy_save_in_table(slot_id_type loc, uint32_t allocation_size_lg)
{
    slot_id_type slot_id = ((slot_id_type)loc >> get_log2(SLOT_SIZE));
    if (slot_id > max_slot_id)
    {
        printf(" Ptr %p failed to find slot \n ", (void *)loc);
        exit(0);
    }

    size_t num_of_slots = (size_t)(1 << (allocation_size_lg)) / SLOT_SIZE;
    if (slot_id + num_of_slots > max_slot_id)
    {
        printf(" Ptr %p failed to find slot \n ", (void *)loc);
        exit(0);
    }

    //    memset(baggy_bounds_table[slot_id],allocation_size_lg,num_of_slots);

    for (size_t i = 0; i < num_of_slots; i++, slot_id++)
    {
        baggy_bounds_table[slot_id] = (unsigned char)allocation_size_lg;
    }
}

/** OLD Code - Different indexing
 *   slot_id_type offset = (slot_id_type) stack_bottom - ptr;
    long double r = ceill((long double) (offset / (long double) SLOT_SIZE));
    if (r > max_slot_id) {
        printf("Stack Ptr %p failed to find slot \n ", (void *) ptr);
        exit(0);
    }
    slot_id = max_slot_id - (slot_id_type) r;
    *isStackObject = 1;

    if (!HEAP_PROTECTION_OFF) {
        char *heap_end = sbrk(0);
        *isStackObject = 0;


        // Check if this object is on the stack
        if (ptr > (slot_id_type) heap_end) {
            offset = (slot_id_type) stack_bottom - ptr;
            long double r = ceill((long double) (offset / (long double) SLOT_SIZE));
            if (r > max_slot_id) {
                printf("Stack Ptr %p failed to find slot \n ", (void *) ptr);
                exit(0);
            }
            slot_id = max_slot_id - (slot_id_type) r;
            *
                    isStackObject = 1;
        }
            // For heap object get slot id (default indexing)
        else if (ptr >= (slot_id_type) heap_start) {
            slot_id_type offset = ((ptr) - (slot_id_type) heap_start);
            long double r = ceill((long double) (offset / (long double) SLOT_SIZE));
            slot_id = heap_first_legal_slot_id + ((slot_id_type) r);
        } else {
            slot_id_type offset = ((slot_id_type) heap_start - (ptr));
            long double r = ceill((long double) (offset / (long double) SLOT_SIZE));
            assert(r
                   <= heap_first_legal_slot_id && "Cannot be negative too many global objects change size");
            slot_id = heap_first_legal_slot_id - (slot_id_type) r;
            slot_id = slot_id == heap_first_legal_slot_id ? heap_first_legal_slot_id - 1 : slot_id;
        }
    }


    if (slot_id > max_slot_id) {
        printf("SAVING Ptr %p, slot id %llu, max slot id %llu \n ", (void *) ptr, slot_id, max_slot_id);
    }
    return slot_id;
 */
