#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "address_constants.h"

extern char *baggy_bounds_table;
extern void *stack_bottom;
extern char *heap_start;
extern char *heap_end;
extern slot_id_type max_slot_id;
extern slot_id_type get_slot_id(long long ptr);

char *baggy_strcat(char *destination, const char *source) {
    size_t source_len, dest_len, alloc_size, log_size;
    intptr_t base_ptr, dest_ptr, offset;

    source_len = strlen(source);
    dest_len = strlen(destination);
    dest_ptr = (intptr_t) destination;
    slot_id_type slot_id = get_slot_id((long long) dest_ptr);
    log_size = (size_t) baggy_bounds_table[slot_id];
    alloc_size = 1 << log_size;
    //XOR
    base_ptr = (dest_ptr & (~0xf));
    offset = dest_ptr - base_ptr;

    if (dest_len + source_len + offset > alloc_size) {
        puts("Baggy libc segmentation fault: strcat");
        exit(EXIT_FAILURE);
    }

    return strcat(destination, source);
}

char *baggy_strcpy(char *destination, const char *source) {
    size_t source_len, alloc_size, log_size;
    intptr_t base_ptr, dest_ptr, offset;

    source_len = strlen(source);
    dest_ptr = (intptr_t) destination;

    slot_id_type slot_id = get_slot_id((long long) dest_ptr);

    log_size = baggy_bounds_table[slot_id];
    alloc_size = 1 << log_size;
    base_ptr = (dest_ptr & (~0xf));
    offset = dest_ptr - base_ptr;

    if (source_len + offset > alloc_size) {
        puts("Baggy libc segmentation fault:strcpy");
        exit(EXIT_FAILURE);
    }
    printf("Executing strcpy");

    return strcpy(destination, source);
}

int baggy_sprintf(char *str, const char *format, ...) {
    va_list argptr;
    size_t alloc_size, log_size;
    long long base_ptr, dest_ptr;
    int ret;
    int allowable_size;

    dest_ptr = (long long) str;

    slot_id_type slot_id = get_slot_id((long long) dest_ptr);

    log_size = baggy_bounds_table[slot_id];
    alloc_size = 1 << log_size;
    base_ptr = (dest_ptr & (~0xf));
    allowable_size = (intptr_t) base_ptr + alloc_size - dest_ptr;

    va_start(argptr, format);
    ret = vsnprintf(str, allowable_size, format, argptr);
    va_end(argptr);

    if (ret > allowable_size - 1) {
        puts("Baggy libc segmentation fault:sprintf");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int baggy_snprintf(char *str, size_t n, const char *format, ...) {
    va_list argptr;
    size_t alloc_size, log_size;
    intptr_t base_ptr, dest_ptr;
    int ret;
    int allowable_size;

    dest_ptr = (intptr_t) str;

    slot_id_type slot_id = get_slot_id((long long) dest_ptr);

    log_size = baggy_bounds_table[slot_id];
    alloc_size = 1 << log_size;
    base_ptr = (dest_ptr & (~0xf));
    allowable_size = (intptr_t) base_ptr + alloc_size - dest_ptr;

    va_start(argptr, format);
    ret = vsnprintf(str, allowable_size < n ? allowable_size : n, format, argptr);
    va_end(argptr);

    if (ret > allowable_size - 1 && n > allowable_size) {
        puts("Baggy libc segmentation fault:snprintf");
        exit(EXIT_FAILURE);
    }

    return ret;
}
