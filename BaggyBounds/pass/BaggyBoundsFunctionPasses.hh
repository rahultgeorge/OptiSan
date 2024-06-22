//
//
//

#ifndef BAGGY_BOUNDS_FUNCTION_PASSES_HH
#define BAGGY_BOUNDS_FUNCTION_PASSES_HH

#include "llvm/Pass.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include <llvm/IR/InstIterator.h>
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

#include <algorithm>
#include <queue>
#include "Util.h"

using namespace llvm;
using std::max;

/*
 *  Aligns stack data objects and saves the bounds of the stack objects in the table
 *
 */

namespace BaggyBounds
{

    // Baggy Stack metadata
#define BAGGY_STACK_OBJECT "baggyStackObj"

    class BaggyBoundsSaveLocalsFunctionPass : public FunctionPass
    {
    public:
        static char ID;

        BaggyBoundsSaveLocalsFunctionPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F);

        StringRef getPassName() const override { return "BaggyBoundsSaveLocals"; }

        void getAnalysisUsage(AnalysisUsage &AU) const;

    private:
        Function *currFunc;

        FunctionCallee baggyMalloc;
        DataLayout *DL;
        Constant *baggyBoundsTable;

        bool isConstantSizeAlloca(const AllocaInst &AI);

        uint64_t getAllocaSizeInBytes(const AllocaInst &AI) const;

        void handleConstantSizeAlloca(Module &M,
                                      AllocaInst *);

        void handleConstantSizeAllocas(std::set<AllocaInst *>);

        void handleDynAlloca(Module &M,
                             BasicBlock::InstListType &iList,
                             BasicBlock::InstListType::iterator iiter);

        bool doInitialization(Module &M);

        bool isInterestingAlloca(const AllocaInst &AI);
    };

    class BaggyBoundsPointersFunctionPass : public llvm::FunctionPass
    {
    public:
        static char ID;

        BaggyBoundsPointersFunctionPass() : FunctionPass(ID) {}

        StringRef getPassName() const override { return "Baggy bounds pointers pass"; }

        void getAnalysisUsage(AnalysisUsage &Info) const;

        bool doInitialization(Module &M);

        bool runOnFunction(Function &F);

    private:
        Constant *baggyBoundsTable;
        Function *slowPathFunc;
        Function *getSlotIDFunc;
        Value *BaggyStrCpy;
        DataLayout *DL;
        // interior pointers should not be instrumented
        std::set<GetElementPtrInst *> whiteListGEPS;

        BasicBlock *instrumentMemset(BasicBlock *resumeBlock, MemSetInst *memSetInst, PHINode *phi);

        // TODO- Deal with GEPS which have vector indices
        BasicBlock *instrumentGEP(BasicBlock *orig, GetElementPtrInst *i, PHINode *phi);

        Value *castToIntAndClearTopBit(LLVMContext &ctxt,
                                       BasicBlock::InstListType &iList,
                                       BasicBlock::InstListType::iterator &i,
                                       Value *val);

        bool shouldInstrumentGEP(GetElementPtrInst *getElementPtrInst);

        bool shouldInstrumentPtrToInt(PtrToIntInst *ptrToIntInstruction);

        bool isCustomObject(Value *object);

        GetElementPtrInst *convertGEP(GEPOperator *CE, Instruction *InsertPt);
    };

}

#endif // BAGGY_BOUNDS_FUNCTION_PASSES_HH
