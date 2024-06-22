#ifndef __TARGET_ANALYSIS_H__
#define __TARGET_ANALYSIS_H__

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/LazyCallGraph.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

#include <string.h>
#include <assert.h>
#include <vector>
#include <set>
#include <queue>
#include <neo4j-client.h>
#include <errno.h>

#include "GraphConstants.h"
#include "IntraTargetAnalysisPass.hh"
#include "MemorySafetyResults.hh"
#include "FunctionScanPass.hh"
#include "ProgramDependencyGraph.hh"

using namespace llvm;

#define TRANSACTION_SIZE 100

enum UPAType
{
    UPAStackWrite,
    UPAStackRead,
    UPANonStackWrite,
    UPANonStackRead,
    UPAPropagationStack,
    UPAPropagationNonStack,
    None
};

typedef std::set<Value *> ValueSet;
typedef std::set<Instruction *> InstructionSet;
typedef std::set<Function *> FunctionSet;
typedef std::pair<Function *, Instruction *> FunctionInstPairTy;

#define FIND_ALL_UPAS 1

class UsableTargetsAnalysis : public ModulePass
{
private:
    Module *_module;
    MemorySafetyResults *_results;
    int scenario = 1;
    std::string programName;
    uint64_t totalTargets = 0;
    llvm::CallGraph *_callGraph;
    IntraTargetAnalysisPass *intraTargetAnalysisPass;

    typedef std::map<Instruction *, std::string> InstructionStringMap;
    typedef std::map<UPAType, InstructionStringMap> OperationTypeInstructionStringMap;
    typedef std::pair<Function *, Instruction *> FunctionReachabilityPointPairTy;

    InstructionSet unsafeMemoryOperationsThatCanUnderflow;

    // Cache node id to IR Instruction
    std::map<std::string, Instruction *> cache;
    // Maps operation type to instruction and action ID
    OperationTypeInstructionStringMap upaActions;
    // Maps unsafe operation (ag id?) to the unsafe object(s) (which may not be in the same function)
    std::map<std::string, std::set<Instruction *>> unsafeOperationIDToUnsafeObjects;
    // Cache of  usable targets for all possible stack frames ending with function f (doesn't include f)
    std::map<Function *, InstructionSet> allStackFramesWithLastFunctionUsableTargetsCache;

    std::map<Function *, InstructionSet> functionFormalArgumentsMap;
    // Only for OOB reads and OOB writes to speed up computation
    // TODO - CLEAN UP LATER
    std::map<Instruction *, std::string> instToImpactedStatesCreated;

    // Map from function to call sites to a specific function (direct, indirect or through a call chain)
    std::map<std::pair<Function *, Function *>, InstructionSet> sourceSinkPairToRelevantCallSitesInSource;

    std::map<std::pair<Function *, Function *>, FunctionSet> sourceSinkPairToIntermediateFunctions;

    FunctionSet intermediateFunctions;

    // Cache for the inter procedural analysis i.e from the source (reachable use of an impacted stack object) to any reachable system calls
    std::map<llvm::Instruction *, std::set<std::string>> interProceduralDataFlowAliasResultsCache;

    void computeUsableTargets(Instruction *, UPAType);

    void computeUsableTargetsThroughUnderflow(Instruction *, UPAType, std::set<std::pair<Function *, Instruction *>> &, std::set<Function *> &);

    void computeUsableTargetsHelper(UPAType unsafeOperationType, std::set<Function *> &candidateTargetFunctions, InstructionSet &usableTargetsInFunc);

    InstructionSet findRelevantCallSitesInSourceToSink(Function *caller, Function *callee);

    void findAllFunctionsAlongPath(Function *caller, Function *callee, std::set<FunctionReachabilityPointPairTy> &visitedNodes);

    void findAllFunctionsAlongPathHelper(CallInst *, Function *callee, std::vector<CallInst *> currentPath, std::set<Function *> &visitedNodes, std::set<FunctionReachabilityPointPairTy> &functionReachabilityPointPairsSet);

    /* Helper functions either db or caching */

    void analyzeUsableTargets(const InstructionSet &, std::set<std::string> &);

    bool fetchUnsafeMemoryOperationsFromDB();

    std::set<Instruction *> findAllPossiblePreviousCallers(Function *, int numLevels = 1);

    void computeInterProceduralDataFlowDBSingleQuery(std::string actionID, InstructionSet sources);

    void fetchUnsafeMemoryOperations();

    bool cacheFunction(Function *function);

    std::string findProgramInstructionInPDG(Instruction *instruction);

    std::string createAttackState(std::string attackStateType, std::string pdgLabel);

    bool connectActionAndState(std::string actionID, std::string stateID, std::string customLabel = "");

    bool connectActionAndStateTransactionBased(std::string actionID, std::set<std::string> stateIDs,
                                               std::string customLabel = "");

    inline UPAType isInterestingUPAType(std::string upaType);

    InstructionSet analyzeCallSiteAndActualArg(CallInst *callSite, Instruction *formalArg);

    Instruction *findInstructionInFunctionUsingDebugInfo(std::string dbgID, unsigned int opcode,
                                                         std::string instructionString,
                                                         Function *function);

public:
    static char ID;

    bool runOnModule(Module &M) override;

    void getAnalysisUsage(AnalysisUsage &AU) const override;

    UsableTargetsAnalysis();

    void analyzeFunctionsParametersForSystemCalls();
};

#endif
