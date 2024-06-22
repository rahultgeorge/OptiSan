
#ifndef POINTER_EFFECTS_CONTROL_DEPENDENCY_GRAPH_HH
#define POINTER_EFFECTS_CONTROL_DEPENDENCY_GRAPH_HH

#include "Graph.hh"
#include "ReachabilityGraph.hh"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "PTAWrapper.hh"
#include "llvm/ADT/SCCIterator.h"
#include <vector>

class IntraTargetAnalysisPass : public llvm::ModulePass
{
public:
    static char ID;

    llvm::Function *currentFunc;

    IntraTargetAnalysisPass() : llvm::ModulePass(ID){};

    bool runOnModule(llvm::Module &M) override;

    void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

    llvm::StringRef getPassName() const override { return "Intra stack data reachability analysis"; };

    ReachabilityGraph *getCFG(llvm::Function &func);

    void reduceUnsafePoints(llvm::Function *);

private:
    ReachabilityGraph *_cfg;
    llvm::PostDominatorTree *_PDT;
    InstructionSet allStackObjects;
    std::map<llvm::Instruction *, InstructionSet> stackObjectsToKills;

    // Cache to computed results i.e analyze functions
    std::map<llvm::Function *, ReachabilityGraph *> functionGraphCache;

    bool runOnFunction(llvm::Function &F);

    void identifyStackDataConservatively();

    void computeKills();

    void computeCFG(llvm::Function *);

    void collectMayAliasUses();
};

#endif // POINTER_EFFECTS_CONTROL_DEPENDENCY_GRAPH_HH
