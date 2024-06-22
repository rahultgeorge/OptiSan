
#ifndef POINTER_EFFECTS_GRAPH_HH
#define POINTER_EFFECTS_GRAPH_HH

#include <set>
#include <map>
#include <queue>
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/ADT/GraphTraits.h"
#include "llvm/Support/CommandLine.h"

// Can improve DS if needed. KISS

typedef std::set<llvm::Instruction *> InstructionSet;

class ReachabilityGraph
{

private:
    // Basic blocks
    std::set<llvm::BasicBlock *> nodes;
    std::map<llvm::BasicBlock *, std::set<llvm::BasicBlock *>> edges;
    InstructionSet allStackObjects;
    InstructionSet unsafePoints;
    std::map<llvm::Instruction *, InstructionSet> stackObjectsToKills;
    std::map<llvm::Instruction *, InstructionSet> stackObjectsToMayAliasUses;
    // Reachability cache (per function/per graph)
    std::map<llvm::Instruction *, InstructionSet> instructionToUsableTargets;

public:
    ReachabilityGraph(){};

    void addNode(llvm::BasicBlock *);

    void addEdge(llvm::BasicBlock *, llvm::BasicBlock *);

    bool canReach(llvm::BasicBlock *source, llvm::BasicBlock *dest);

    bool canReach(llvm::Instruction *source, llvm::Instruction *dest);

    bool canReach(llvm::Instruction *source, llvm::Instruction *dest, std::set<llvm::BasicBlock *> ignoreList);

    void removeBlock(llvm::BasicBlock *);

    void setAllTargets(InstructionSet &);

    void getAllTargets(InstructionSet &);

    InstructionSet getAllTargets() { return allStackObjects; };

    void setKills(llvm::Instruction *, InstructionSet);

    void identifyUsableTargets(llvm::Instruction *, InstructionSet &);

    void identifyUsableTargetsForUnsafePoints(InstructionSet &);

    void addUnsafePoint(llvm::Instruction *);

    InstructionSet getUnsafePoints();

    void setUnsafePoints(InstructionSet &);

    void clearUnsafePoints();

    void addMayAliasUseForStackObject(llvm::Instruction *, llvm::Instruction *);
};

#endif // POINTER_EFFECTS_GRAPH_HH
