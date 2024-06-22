#include "Util.h"

using namespace llvm;

// Given the size of an allocation, return the desired alignment.
// Finds the smallest power of 2 which is at least as large as sz
// but uses the SLOT_SIZE if that is too low.
uint64_t get_alignment(uint64_t sz) {
    while ((sz & (-sz)) != sz) {
        sz += sz & (-sz);
    }
//    printf("%u \n", sz);
    return sz < SLOT_SIZE ? SLOT_SIZE : sz;
}

// returns the log of a power of 2
uint32_t get_lg(uint64_t sz) {
    unsigned int c = 0;
    while (sz) {
        c++;
        sz >>= 1;
    }
    return c - 1;
}


/**
 *  Returns a call void baggy_save_in_table instruction (with arguments)
 * @param m - module
 * @param location - pointer
 * @param allocation_size -  allocation size
 * @return
 */
Instruction *get_save_in_table_instr(Module &m, Value *location, uint64_t allocation_size) {
    Function *func = m.getFunction("baggy_save_in_table");
    if (!func) {
        // auto-generated function type FuncTy_bsit (type of baggy_save_in_table function)
        std::vector < Type * > FuncTy_4_args;
        FuncTy_4_args.push_back(IntegerType::get(m.getContext(), 64));
        FuncTy_4_args.push_back(IntegerType::get(m.getContext(), 32));
        FunctionType *FuncTy_bsit = FunctionType::get(
                /*Result=*/Type::getVoidTy(m.getContext()),
                /*Params=*/FuncTy_4_args,
                /*isVarArg=*/false);

        func = Function::Create(FuncTy_bsit, GlobalValue::ExternalLinkage, "baggy_save_in_table", &m);
    }

    //Constant* loc_param = ConstantExpr::getCast(Instruction::PtrToInt, location, IntegerType::get(m.getContext(), 32));
    ConstantInt *sz_param = ConstantInt::get(m.getContext(), APInt(32, get_lg(allocation_size)));
    std::vector < Value * > params;
    params.push_back(location);
    params.push_back(sz_param);
    Instruction *inst = CallInst::Create(func, params);

    return inst;
}


