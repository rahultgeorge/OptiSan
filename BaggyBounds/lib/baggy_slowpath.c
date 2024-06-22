#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "address_constants.h"

#define RED "\e[0;31m"

extern unsigned char *baggy_bounds_table;
extern void *stack_bottom;
extern slot_id_type max_slot_id;

/**
 *
 * @param base - base pointer
 * @param newPtr - resultant pointer
 * @return resultant pointer (MSB)
 */
void *baggy_slowpath(void *base, void *newPtr)
{
    void *oobPtr = NULL;
    // Similar to ASAN's halt on error (We print warning to stderr)
    if (SILENT_WARN_MODE)
    {
        // fprintf(stderr, RED "Potential overflow");
        return newPtr;
    }

    // We currently cannot deal with command line arguments
    if (((slot_id_type)base > (slot_id_type)stack_bottom))
        return newPtr;

    // Set the MSB on the newptr and return it
    oobPtr = (void *)((slot_id_type)newPtr | ((slot_id_type)1 << 63));
    // printf("Marked the MSB of %p, base %p\n", newPtr, base);

    uintptr_t orig = (uintptr_t)base;
    uintptr_t newptr = (uintptr_t)newPtr;
    uintptr_t msbAddr = (uintptr_t)((uintptr_t)1 << 63);
    // If base is already marked as OOB
    if ((orig & msbAddr) != 0)
    {
        orig &= (msbAddr - 1);
        newptr &= (msbAddr - 1);
        // Try restoring it (original design)
        if ((orig & (SLOT_SIZE >> 1)) == 0)
        {
            orig -= SLOT_SIZE; /* bottom half of slot */
        }
        else
        {
            orig += SLOT_SIZE; /* top half of slot */
        }

        /* get allocation size */
        slot_id_type slot_id = ((slot_id_type)orig >> 5);
        if (slot_id > max_slot_id)
            return oobPtr;
        size_t logSize = baggy_bounds_table[slot_id];
        logSize = logSize & 63;
        size_t alloc_size = ((size_t)1 << logSize);

        /* get start of allocation and calculate diff */
        orig = (orig >> logSize) << logSize;
        slot_id_type diff = newptr - orig;
        if (0 <= diff && diff < alloc_size)
        {
            return (void *)newptr;
        }
    }

    //    else if (diff < (alloc_size + (SLOT_SIZE >> 1)) && newptr >= (orig - (SLOT_SIZE >> 1))) {
    //        ret = (void *) (newptr | 0x80000000);
    //    } else {
    //        printf("Baggy segmentation fault\n");
    //        exit(EXIT_FAILURE);
    //    }

    /*Base ptr is in bounds and if derived pointer is more than 0.5*slot size out of bounds, we can't restore unless we use tagged pointers and track the offset.
     * Instead of full tagged pointer design let us use another bit to indicate we cannot restore it.
     * This way the false positives will drop but we do not compromise on detection and functionality because of false positives should not be affected much
     */
    else
    {
    }

    //    printf("Marked the MSB of %p to make it %p\n", newPtr, oobPtr);

    return oobPtr;
}
