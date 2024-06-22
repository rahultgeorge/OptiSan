#ifndef SPATIAL_MEMORY_SAFETY_ANALYSIS_HH
#define SPATIAL_MEMORY_SAFETY_ANALYSIS_HH

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/IR/Dominators.h"
#include <string.h>
#include <vector>
#include <neo4j-client.h>
#include <string>
#include <queue>
#include <unordered_map>

#include "GraphConstants.h"
// #include "FunctionSpatialMemorySafetyAnalysis.hh"
#include "MemorySafetyResults.hh"
// #include "TargetAnalysis.h"
#include "FunctionScanPass.hh"

using namespace llvm;

#define OP errs()

#define dbgs \
    if (0)   \
    OP

// #define USE_VR

/* enum UPAType
{
    UPAStackWrite,
    UPAStackRead
}; */

#define USE_VR_RES_FROM_DB

class SpatialMemorySafetyAnalysisWrapper : public ModulePass
{
private:
    Module *_module;
    std::string programName;

    MemorySafetyResults *_results;

    std::set<Instruction *> unsafeStackMemoryAccesses;

    std::set<Instruction *> taintedOperands;

    typedef std::map<Instruction *, std::string> InstructionStringMap;
    // Caches the instruction using the instruction string and function name
    std::map<std::string, Instruction *> cache;
    // Instruction to state id maps
    InstructionStringMap unsafePointerArithmeticInstructionsToDBIDMap;
    InstructionStringMap unsafeNonStackPointerStates;
    InstructionStringMap impactedStackPointerStates;
    InstructionStringMap impactedStackDataObjectStates;
    InstructionStringMap oobReads;
    std::set<Instruction *> allPropagationActionsSeen;
    std::map<std::string, std::set<std::string>> oobReadIDToStackDataWhichCanBeLeaked;
    // For now we are not fetching these derived unsafe pointer
    InstructionStringMap derivedUnsafeStackPointerStates;

    std::map<std::string, Instruction *> irToInstructionCache;

    std::set<Instruction *> findStackDataSource(GetElementPtrInst *oobGEP);

    void computeUsesOfImpactedObjectsWhichCanBeLeaked();

    // TODO - Implement systematic method later
    void propagateUnsafeAddress(std::set<Instruction *>, std::map<Instruction *, std::string>);

    void findPotentialUnsafeMemoryAccesses();

    void analyzeUnsafePointerArithmeticInstructions();

    void computePossibleStackUnsafeMemoryAccessesUsingVR();

    // Simple check instead of querying PDG or reconstructing function CFG
    bool isReachable(Instruction *source, Instruction *dest);

    // Common method to compute subsequent operations uses for both unsafe pointers and impacted pointers using def use chains.
    // For impacted pointers the unsafe instruction passed to this method must be reachable wrt the unsafe operation (or at least 1 of them)
    void
    computeUsesOfAddress(Instruction *unsafeAddress,
                         bool checkForTaintedOperands, bool isUnsafePtr);

    std::set<Instruction *> findFormalArgAndUses(Function *, Argument *arg);

    std::set<std::string> findAllPossiblePreviousCallers(Function *, int numLevels = 1);

    std::set<Instruction *> findCallSites(Function *caller, Function *sinkFunc);

    std::string stripVersionTag(std::string str);

    bool isTypeEqual(Type &t1, Type &t2);

    bool isFuncSignatureMatch(CallInst &ci, llvm::Function &f);

    std::set<Function *> getIndirectCallCandidates(CallInst &ci);

    Instruction *findDominatingInstruction(std::vector<Instruction *>);

    Instruction *findInstructionInFunctionUsingIR(std::string instructionString, Function *function, std::string pdgLabel);

    bool cacheFunction(Function *function);

    std::string
    findProgramInstructionInPDG(Instruction *instruction);

    std::string createAttackAction(std::string pdgNodeLabel,
                                   std::string actionType,
                                   std::string actionLabel = "");

    void connectStateAndAction(std::string stateID,
                               std::string actionID);

public:
    static char ID;

    void getAnalysisUsage(AnalysisUsage &AU) const;

    SpatialMemorySafetyAnalysisWrapper();

    bool runOnModule(Module &M);
};

std::set<std::string> sensitiveSystemCalls = {"open", "openat", "openat2", "open64", "fopen", "creat", "fopen64",
                                              "scanf", "__isoc99_scanf",
                                              "getenv", "gets", "fgets", "fscanf", "sscanf", "__isoc99_fscanf",
                                              "__isoc99_sscanf",
                                              "socket", "socketpair",
                                              "read", "fread",
                                              "write", "fwrite",
                                              "link", "symlink", "unlink",
                                              "chmod", "fchmod", "fchmodat", "chown", "fchown",
                                              "recv", "recvfrom", "recvmsg",
                                              "send", "sendto", "sendmsg",
                                              "mprotect",
                                              "mmap", "munmap",
                                              "malloc", "free",
                                              "setenv", "setuid", "setgid",
                                              "execv", "execve", "fork", "clone"};

// Certain libc library calls  such as sprintf write to strings (aka buffers) and these might be UPAS
// TODO - Include summaries of micro lib c in our analysis

std::set<std::string> libraryUPACalls = {"strcat", "strncat", "strcpy", "sprintf", "snprintf"};

// Include https://releases.llvm.org/1.5/docs/LangRef.html#intrinsics - memcpy,memset,memmove
std::set<std::string> llvmIntrinsicLibraryCalls = {
    "memmove", "memset",
    "memcpy"};

#endif // SPATIAL_MEMORY_SAFETY_ANALYSIS_HH
