#ifndef BAGGY_CONSTANTS_H
#define BAGGY_CONSTANTS_H
#include <stddef.h>
// Must be a power of two and >16 
#define SLOT_SIZE 32  
// 0x7FFFFFFFFFFFFFFF is the same as 9223372036854775807
#define CLEAR_MSB_CONSTANT 0x7FFFFFFFFFFFFFFF
#define HEAP_PROTECTION_OFF 0
#define SILENT_WARN_MODE 0
#define PRECISE_STACK_MD_MODE 0
typedef size_t slot_id_type;
//Constants related to instrumentation
//Baggy cannot handle this function or should not instrument
#define BAGGY_SKIP_FUNCTION "baggySkip"
// Baggy instrinsic inst so do not modify (No sanitize common across sanitizers - LLVM)
#define BAGGY_INTRINSIC_INST "nosanitize"
#endif




