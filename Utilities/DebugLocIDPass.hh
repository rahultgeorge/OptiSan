
#include "llvm/Pass.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/User.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/CommandLine.h"

#include "GraphConstants.h"
#include <neo4j-client.h>
#include <string.h>
#include <set>

using namespace llvm;

class DebugLocIDPass : public FunctionPass
{
private:
    Function *funcBeingAnalyzed = NULL;
    std::string programName;

    std::map<Instruction *, std::string> instructionDbgIDMap;

    void updateDB();

    void processFunction();

public:
    static char ID; // Pass identification, replacement for typeid

    DebugLocIDPass() : FunctionPass(ID) {}

    StringRef getPassName() const override { return "DebugLocIDPass"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool doInitialization(Module &M);

    bool runOnFunction(Function &f);
};

class DebugLocModulePass : public ModulePass
{

private:
    std::set<std::string> functionsToAnalyze;
    std::string programName;

    void findUnsafeFunctions();

    std::string
    findProgramInstructionInPDG(Instruction *instruction);

public:
    static char ID; // Pass identification, replacement for typeid

    DebugLocModulePass() : ModulePass(ID) {}

    StringRef getPassName() const override { return "DebugLocModulePass"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool runOnModule(Module &M);
};
