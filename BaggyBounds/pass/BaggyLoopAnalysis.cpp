#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/SimplifyIndVar.h"

using namespace llvm;

/*
 * Smart monitor - currently not being used
 * Loop optimization
 */

namespace {
    struct BaggyLoopAnalysis : public LoopPass {
        static char ID;

        BaggyLoopAnalysis() : LoopPass(ID) {}

        virtual bool doInitialization(Loop *L, LPPassManager &LPM);

        virtual bool runOnLoop(Loop *L, LPPassManager &LPM);

        virtual void getAnalysisUsage(AnalysisUsage &Info) const {
            Info.addRequired<LoopInfoWrapperPass>();
            // I Have no idea what these are
//            Info.addRequiredID(LoopSimplifyID);
//            Info.addRequiredID(LCSSAID);
            Info.addRequired<ScalarEvolutionWrapperPass>();
        }

    private:
        LoopInfo *LI;        // Current LoopInfo
        ScalarEvolution *SE; // Track the changes in a scalar value

        bool Changed;          // Set to true when we change anything.
        BasicBlock *Preheader; // The preheader block of the current loop...
        BasicBlock *Header;    // The header block of the current loop
        Loop *CurLoop;         // The current loop we are working on...

        /// getIfCanBePreChecked - Check if we can precheck inst in the preheader
        /// of the current loop.  If it can then return a GEP instruction that returns
        /// the largest value that inst can take.  Otherwise, return NULL
        ///
        GetElementPtrInst *getIfCanBePreChecked(GetElementPtrInst *inst);

        /// inSubLoop - Little predicate that returns true if the specified basic
        /// block is in a subloop of the current one, not the current one itself.
        ///
        bool inSubLoop(BasicBlock *BB) {
            assert(CurLoop->contains(BB) && "Only valid if BB is IN the loop");
            return LI->getLoopFor(BB) != CurLoop;
        }
    };
};

bool BaggyLoopAnalysis::doInitialization(Loop *L, LPPassManager &LPM) {}

bool BaggyLoopAnalysis::runOnLoop(Loop *L, LPPassManager &LPM) {
    if (!L->isLoopSimplifyForm()) {
        errs() << "Loop is not in simplified form\n";
        return false;
    }

    Changed = false;

    // Get our Loop and Alias Analysis information...
    LI = &getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
    SE = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();

    CurLoop = L;

    // Get the preheader block where the baggy check will go
    Preheader = L->getLoopPreheader();
    Header = L->getHeader();

    // Take out the ending branch
    Instruction *Term = Preheader->getTerminator();
    Term->removeFromParent();

    // go through the instructions in the loop
    for (Loop::block_iterator BB = L->block_begin(), BBE = L->block_end();
         (BB != BBE); ++BB) {
        // basic blocks in sub loops should already have been instrumented
        if (inSubLoop(*BB)) {
            continue;
        }
        for (BasicBlock::iterator I = (*BB)->begin(), E = (*BB)->end(); (I != E);
             ++I) {
            if (!isa<GetElementPtrInst>(I)) {
                continue;
            }

            GetElementPtrInst *inst = cast<GetElementPtrInst>(I);
            if (getIfCanBePreChecked(inst) != NULL) {
                Changed = true;
            }
        }
    }

    // Add the terminator instruction back
    Preheader->getInstList().push_back(Term);

    // Clean up for the next iteration
    Preheader = 0;
    Header = 0;
    CurLoop = 0;

    return Changed;
}

GetElementPtrInst *
BaggyLoopAnalysis::getIfCanBePreChecked(GetElementPtrInst *inst) {
    std::vector<Value *> args;

    // errs() << *inst;
    for (GetElementPtrInst::op_iterator OP = inst->idx_begin(),
                 OPE = inst->idx_end();
         OP != OPE; ++OP) {
        // errs() << " operand: " << **OP;
        const SCEV *S = SE->getSCEVAtScope(*OP, CurLoop);
        if (SE->isLoopInvariant(S, CurLoop)) {
            // errs() << " isLoopInvariant\n";
            args.push_back(*OP);
            continue;
        }
        if (!SE->hasComputableLoopEvolution(S, CurLoop)) {
            // errs() << " doesNotHaveComputableLoopEvolution\n";
            return NULL;
        }
        // errs() << "type: " << S->getSCEVType();
        if (const SCEVConstant *SConstant = dyn_cast<SCEVConstant>(S)) {
            // errs() << " isSCEVConstant\n";
            args.push_back(SConstant->getValue());
            continue;
        }
        if (const SCEVUnknown *SUnknown = dyn_cast<SCEVUnknown>(S)) {
            // errs() << " isSCEUnknown\n";
            args.push_back(SUnknown->getValue());
            continue;
        }
        if (const SCEVAddRecExpr *SAddRec = dyn_cast<SCEVAddRecExpr>(S)) {
            const SCEV *Iterations = SE->getBackedgeTakenCount(CurLoop);
            if (Iterations == SE->getCouldNotCompute()) {
                // errs() << " could not compute iterations\n";
                return NULL;
            }
            const SCEV *ValueAtIter = SAddRec->evaluateAtIteration(Iterations, *SE);
            if (const SCEVConstant *SValue = dyn_cast<SCEVConstant>(ValueAtIter)) {
                // errs() << " value: " << *(SValue->getValue()) << "\n";
                args.push_back(SValue->getValue());
                continue;
            }
            // errs() << " wat\n";
            return NULL;
        }

        return NULL;
    }

    // We have a GEP instruction that can be checked outside the loop
    GetElementPtrInst *CheckInst = GetElementPtrInst::Create(inst->getPointerOperand()->getType(),
                                                             inst->getPointerOperand(), args, "baggy.precheck",
                                                             Preheader);
    CheckInst->setIsInBounds(inst->isInBounds());

    return CheckInst;
}

char BaggyLoopAnalysis::ID = 0;
static RegisterPass<BaggyLoopAnalysis>
        X("baggy-loop-analysis",
          "Instrument pointer arithmetic outside loops when possible", true, false);
