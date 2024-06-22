#ifndef UTIL_H
#define UTIL_H

#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/IRBuilder.h"
#include <stdint.h>
#include "address_constants.h"

uint64_t get_alignment(uint64_t sz);
uint32_t get_lg(uint64_t sz);
llvm::Instruction* get_save_in_table_instr(llvm::Module& m,
		llvm::Value* location, uint64_t allocation_size);

#endif


