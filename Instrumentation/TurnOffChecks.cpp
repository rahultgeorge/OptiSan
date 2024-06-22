#include "llvm/Pass.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/User.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"


using namespace llvm;

class TurnOffChecks : public llvm::FunctionPass {
private:
    // Using Candea's approach

    // Returns true if a given instruction is a call to an aborting, error reporting function
    bool isAbortingCall(const CallInst *CI) const;

    const CallInst *findSanityCheckCall(BasicBlock *BB) const;


public:
    static char ID; // Pass identification, replacement for typeid

    TurnOffChecks() : FunctionPass(ID) {}

    StringRef getPassName() const override { return "TurnOffChecks"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool runOnFunction(Function &F);


};

bool TurnOffChecks::isAbortingCall(const CallInst *CI) const {
    if (CI->getCalledFunction()) {
        StringRef name = CI->getCalledFunction()->getName();
        if (name.startswith("__asan_report_") || name.contains("baggy_slowpath")) {
            return true;
        }
    }
    return false;
}

const CallInst *TurnOffChecks::findSanityCheckCall(BasicBlock *BB) const {
    for (const Instruction &I: *BB) {
        if (const CallInst *CI = dyn_cast<CallInst>(&I)) {
            if (isAbortingCall(CI)) {
                return CI;
            }
        }
    }
    return nullptr;
}

bool TurnOffChecks::runOnFunction(Function &F) {
    if (F.isIntrinsic() || F.isDeclaration())
        return false;
    int numOfChecks=0;
  //  errs()<<"TCE:"<<F.getName()<<"\n";

    for (BasicBlock &BB: F) {

        if (findSanityCheckCall(&BB)) {


            // All branches to sanity check blocks are sanity check branches
            for (User *U: BB.users()) {

                BranchInst *BI = dyn_cast<BranchInst>(U);

                if (BI && BI->isConditional()) {
	        //errs()<<"\t:"<<*BI<<"\n";

                    for (unsigned int succ_no = 0; succ_no < BI->getNumSuccessors(); succ_no++) {
                        {
                            if (&BB == BI->getSuccessor(succ_no)) {
                                if (succ_no == 0)
                                    BI->setCondition(ConstantInt::getFalse(BI->getContext()));
                                else
                                    BI->setCondition(ConstantInt::getTrue(BI->getContext()));
                                ++numOfChecks;
                            }
                        }
                    }
                }
            }
        }

    }
   if(numOfChecks)
    errs()<<"# Checks turned off:"<<numOfChecks<<"\n";
   return true;
}

void TurnOffChecks::getAnalysisUsage(AnalysisUsage &AU) const {}

char TurnOffChecks::ID = 0;
static RegisterPass<TurnOffChecks>
        Y("tce", "Turn off checks", false, false);

