#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <errno.h>
#include <string.h>
// This helps us print the stack trace when we catch a seg fault
#include <execinfo.h>
#include <limits.h>
#include "address_constants.h"

unsigned char *baggy_bounds_table;

// Bounds table size (1 GB) | with 32 bytes slot size we can maintain bounds of 32 GB of objects any given time
unsigned int bounds_table_size_log = 43;

// Space reserved for globals (4 MB) | with 16 bytes slot size we can maintain bounds of 64 MB of global objects at any time
#define GLOBAL_BOUNDS_TABLE_SIZE_LOG 22

unsigned int page_size;

// May not be actual stack bottom but close enough and constant wrt program execution (main onwards)
void *stack_bottom;

slot_id_type max_slot_id;

slot_id_type heap_first_legal_slot_id;

int is_initialized = 0;

void sigsegv_handler(int signal_number, siginfo_t *siginfo, void *context)
{

    void *array[30];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 30);
    printf("SIGSEGV segmentation fault\n");
    fprintf(stderr, "Error: signal %d:\n", signal_number);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

void buddy_allocator_init();

static inline void set_seg_fault_handler()
{

    struct sigaction act;
    act.sa_sigaction = sigsegv_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, NULL);
    // printf("Baggy seg fault");
}

void setup_table()
{
    page_size = (unsigned int)sysconf(_SC_PAGE_SIZE);

    size_t size = ((slot_id_type)1 << bounds_table_size_log);
    // Slot ids start from 0
    max_slot_id = ((slot_id_type)1 << bounds_table_size_log) - 1;
    void *va = (void *)mmap(NULL, size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (va == MAP_FAILED)
    {
        exit(EXIT_FAILURE);
    }
    unsigned int slot_size_reminder = SLOT_SIZE - (((unsigned long long)va) % SLOT_SIZE);
    if (slot_size_reminder < SLOT_SIZE)
    {
        va = va + slot_size_reminder;
    }
    baggy_bounds_table = (unsigned char *)va;
    // Only useful if we use the stack objects only approach
    baggy_bounds_table[0] = (unsigned char)UINT_MAX;
}

void baggy_set_stack_bottom(int *stackPtr)
{
    stack_bottom = (void *)(stackPtr);
}

void baggy_init()
{

    //    set_seg_fault_handler();
    if (is_initialized)
        return;
    is_initialized = 1;

    // Modified this to make the table placement more robust
    setup_table();

    if (!HEAP_PROTECTION_OFF)
        buddy_allocator_init();
}
