#ifndef FUNCTION_SCAN_PASS_HH
#define FUNCTION_SCAN_PASS_HH

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/IR/Dominators.h"

#include <string.h>
#include <set>

using namespace llvm;

class FunctionScanPass : public FunctionPass
{
private:
    Function *funcBeingAnalyzed = NULL;

    std::set<Function *> functionsProcessed;
    // Function dbg id to Function (even inlined functions)
    std::map<std::string, Function *> functionDbgIDMap;

    // To deal with cases where multiple instructions have same DI so use IR aka string :(
    // TODO - Figure out clean way to resolve this ambiguity - maybe column or something
    std::map<std::string, std::set<std::string>> functionDbgIDToIRMap;

    void processFunction(Function *);

public:
    static char ID; // Pass identification, replacement for typeid

    FunctionScanPass() : FunctionPass(ID)
    {
        // errs()<<"Function pass object created\n";
    }

    StringRef getPassName() const override { return "FunctionScanPass"; }

    void getAnalysisUsage(AnalysisUsage &AU) const override;

    //    bool doInitialization(Module &M);

    bool runOnFunction(Function &f) override;

    void processFunction();

    Function *findFunctionUsingDBGID(std::string dbgID)
    {

        // errs() << "\t DBG ID based:" << functionDbgIDMap[dbgID] << "\n";
        // errs() << "\t DBG ID based # IR matches:" << instructionDbgIDToIRMap[dbgID].size() << "\n";

        if (functionDbgIDMap.find(dbgID) != functionDbgIDMap.end())
            return functionDbgIDMap[dbgID];
        return nullptr;
    }

    std::set<std::string> findFunctionsUsingDBGID(std::string dbgID)
    {
        return functionDbgIDToIRMap[dbgID];
    }
};

#endif // FUNCTION_SCAN_PASS_HH
