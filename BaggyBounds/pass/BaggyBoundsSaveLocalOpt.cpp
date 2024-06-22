#include <algorithm>
#include <llvm/Pass.h>

#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/IR/IRBuilder.h"

#include "EscapeTracking.h"

#include "Util.h"

using namespace llvm;
using std::max;

/*
 * Baggy Bounds
 * 1. Aligns all stack data objects as needed
 * 2. Save stack objects bound only if we find the ptr "escapes" (out of function or is stored into memory)
 * First pass
 */

namespace {
    struct BaggyBoundsSaveLocalOpt : public ModulePass {
        static char ID;

        BaggyBoundsSaveLocalOpt() : ModulePass(ID) {}

        DataLayout *DL;

        void handleInstruction(Module &M,
                               BasicBlock::InstListType &iList,
                               BasicBlock::InstListType::iterator iiter) {
            AllocaInst *inst = cast<AllocaInst>(iiter);
            unsigned int allocation_size = DL->getTypeAllocSize(inst->getType()->getElementType());
            unsigned int real_allocation_size = get_alignment(allocation_size);
            inst->setAlignment(MaybeAlign(max(inst->getAlignment(), real_allocation_size)));
            // Check if the pointer can "escape" the function.
            // Second and third arguments are if returning counts as escaping
            // and if storing counts as escaping, respectively. We say yes
            // to both. Of course, it is undefined behaviour to return a pointer
            // to this stack-allocated object, so that argument should be irrelevant.
            if (PointerMayLeave(inst, true, true)) {
                // Cast the pointer to an int and then add a save instruction.
                CastInst *intPtr = new PtrToIntInst(inst, IntegerType::get(M.getContext(), 64), "");
                Instruction *saveInst = get_save_in_table_instr(M, intPtr, real_allocation_size);
                iList.insertAfter(iiter, saveInst);
                iList.insertAfter(iiter, intPtr);
            }
        }

        virtual bool runOnModule(Module &M) {
            DL = const_cast<DataLayout *>(&(M.getDataLayout()));

            // Iterate through all functions, basic blocks, and instructions, looking for
            // alloca instructions. Call handleInstruction on all alloca instructions.
            for (Module::iterator miter = M.begin(); miter != M.end(); ++miter) {
                Function &F = *miter;
                for (Function::iterator bbiter = F.begin(); bbiter != F.end(); ++bbiter) {
                    BasicBlock &bb = *bbiter;
                    BasicBlock::InstListType &iList = bb.getInstList();
                    for (BasicBlock::InstListType::iterator iiter = iList.begin();
                         iiter != iList.end(); ++iiter) {
                        Value const *inst = dyn_cast<Value>(iiter);
                        if (isa<AllocaInst>(inst)) {
                            handleInstruction(M, iList, iiter);
                        }
                    }
                }
            }
        }

        virtual void getAnalysisUsage(AnalysisUsage &Info) const {
        }
    };
}

char BaggyBoundsSaveLocalOpt::ID = 0;
static RegisterPass<BaggyBoundsSaveLocalOpt>
        X("baggy-save-local-opt", "Baggy Bounds Locals Initialization Pass",
          true,
          false);
