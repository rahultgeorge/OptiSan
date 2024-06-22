#ifndef ESTIMATION_PASS_HH

#define ESTIMATION_PASS_HH

// Base header with all common LLVM and C++ DS headers
#include "llvm/Pass.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
// This header includes LoopSimplifyID as an extern
#include "llvm/Transforms/Utils.h"
#include "llvm/Support/CommandLine.h"

#include "CoverageUtilities.hh"
#include "FunctionScanPass.hh"
#include <fstream>
#include <iostream>
#include <neo4j-client.h>
#include <string.h>
#include <set>
#include <vector>
#include <deque>

using namespace llvm;
// The different monitors
enum MonitorType
{
    ASAN,
    BaggyBounds,
    ESAN,
    // This is just Baggy + ASAN for cost estimation
    BaggyBoundsASAN,
    NoMonitor
};

enum OperationType
{
    MetadataOperations,
    CheckOperations,
};

const MonitorType monitors[] = {MonitorType::ASAN, MonitorType::BaggyBounds};

#define CURRENT_MONITOR MonitorType::ASAN

#define COMPUTE_PER_CHECK_COST 1

#define COMPUTE_METADATA_COST 1

// #define IDENTIFY_INDIVIDUAL_STACK_MD_OPERATIONS

#define BAGGY_SKIP_FUNCTION "baggySkip"

/*
 * This pass should run on the instrumented code
 * Output - should be the cost estimate for various operations associated with this monitor
 */
class CostEstimationPass : public ModulePass
{
private:
    Module *_module;

    FunctionScanPass *scanPass;

    // Monitoring points in order so that we can correlate coverage information
    std::deque<Instruction *> monitoringPoints;

    // MP IDs
    std::deque<std::string> monitoringPointIDs;

    // Caches the instruction using the instruction string and function name (index string)
    std::map<std::string, Instruction *> cache;

    std::map<std::string, uint64_t> stackObjInstrumentedPerFunctionMap;

    std::string programName;

    inline std::string monitorTypeToString(MonitorType type)
    {
        switch (type)
        {
        case MonitorType::ASAN:
            return "ASAN";
        case MonitorType::BaggyBounds:
            return "BaggyBounds";
        case MonitorType::BaggyBoundsASAN:
            return "BaggyASAN";
        default:
            return "Unknown type";
        }
    }

    inline std::string operationTypeToString(OperationType type)
    {
        switch (type)
        {
        case OperationType::MetadataOperations:
            return "MetadataOperations";
        case OperationType::CheckOperations:
            return "CheckOperations";
        default:
            return "Unknown type";
        }
    }

    inline void dumpCostEstimateInfo(std::map<OperationType, uint64_t> monitorOperationTypeToCount)
    {
        std::ofstream outputFile;
        outputFile.open(programName + "_" + monitorTypeToString(CURRENT_MONITOR) + "_cost_estimate.txt",
                        std::ios::out | std::ios::trunc);
        for (auto const &it : monitorOperationTypeToCount)
        {
            outputFile << operationTypeToString(it.first) << ":" << it.second << "\n";
        }
        outputFile.close();
    }

    bool isConstantSizeAlloca(const AllocaInst &AI);

    void updateFrequencyInfoInDB(std::map<std::string, uint64_t>);

    void updateObjCountInDB();

    void generateCoverageData();

    bool cacheFunction(Function *function);

    /**
     * Find the write/store UPAs
     * @return
     */
    bool findRelevantMonitoringPoints(std::map<std::string, uint64_t> &);

    bool findAllMonitoringPoints(std::map<std::string, uint64_t> &);

    Instruction *
    findInstructionInFunctionUsingDebugInfo(std::string dbgID, unsigned int opcode, std::string instructionString,
                                            std::string functionName);

    std::set<std::string> findAllMetadataFunctions();

    uint64_t identifyObjectMetadataOperations(Function *func);

    uint64_t getAllocaSizeInBytes(const AllocaInst &AI);

    bool isInterestingAlloca(const AllocaInst &AI);

    uint64_t estimateNetObjects(Function *func);

    uint64_t getNumOfStackObjects(Function *func);

    std::string getFunctionDebugInfo(std::string functionName);

    void searchForInlinedFunctions();

    Function *findFunctionUsingNameAndMD(std::string functionName, bool &multiple, std::set<std::string> &);

public:
    static char ID; // Pass identification, replacement for typeid

    CostEstimationPass() : ModulePass(ID) {}

    StringRef getPassName() const override { return "CostEstimationPass"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool runOnModule(Module &M);
};

class CostEstimationFunctionPass : public llvm::FunctionPass
{
private:
    // Using Candea's approach

    // Types used to store sanity check blocks / instructions
    typedef llvm::DenseSet<llvm::BasicBlock *> BlockSet;
    typedef llvm::DenseSet<llvm::Instruction *> InstructionSet;
    typedef std::list<llvm::Instruction *> InstructionVec;
    // All blocks that abort due to sanity checks
    std::map<llvm::Function *, BlockSet> SanityCheckBlocks;

    // All instructions that belong to sanity checks
    std::map<llvm::Function *, InstructionSet> SanityCheckInstructions;
    // A map from instructions to the checks that use them.
    std::map<llvm::Instruction *, InstructionSet> ChecksByInstruction;

    // A map of all instructions required by a given sanity check branch.
    // Note that instructions can belong to multiple sanity check branches.
    std::map<llvm::Instruction *, InstructionSet> InstructionsBySanityCheck;

    // All sanity checks themselves (branch instructions that could lead to an abort)
    std::map<llvm::Function *, InstructionVec> SCBranches;

    std::map<llvm::Function *, InstructionVec> UCBranches;

    // Returns true if a given instruction is a call to an aborting, error reporting function
    bool isAbortingCall(const CallInst *CI, MonitorType monitorType) const
    {
        if (CI->getCalledFunction())
        {
            StringRef name = CI->getCalledFunction()->getName();
            if (monitorType == MonitorType::NoMonitor)
            {
                if (name.startswith("__asan_report_") || name.contains("baggy_slowpath"))
                    return true;
            }
            else if (monitorType == MonitorType::ASAN && name.startswith("__asan_report_"))
            {
                return true;
            }
            else if (monitorType == MonitorType::BaggyBounds && name.contains("baggy_slowpath"))
                return true;
        }
        return false;
    }

    void findInstructions();

    const CallInst *findSanityCheckCall(BasicBlock *BB, MonitorType monitorType = NoMonitor) const;

    bool onlyUsedInSanityChecks(Value *V);

    Function *funcBeingAnalyzed;

    // Keep track of monitored operations or operations where we expect metadata or checking operations to occur
    std::map<OperationType, std::set<Instruction *>> monitorOperationTypeToInstruction;

    // Data structures to keep track of points of interest in a function
    InstructionSet stackObjectAllocationsThroughAlloca;
    // Might include CMA (stack and heap) also monitor functions
    InstructionSet callInstructions;
    // Loads and stores
    InstructionSet memoryDereferences;
    // Considering only gep for now
    InstructionSet pointerManipulationInstructions;

    // Simpler cost per monitored operation approach
    InstructionSet monitoredMemoryOperations;

    void processFunction();

public:
    static char ID; // Pass identification, replacement for typeid

    CostEstimationFunctionPass() : FunctionPass(ID) {}

    StringRef getPassName() const override { return "CostEstimationFunctionPass"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool runOnFunction(Function &M);

    const InstructionSet getMonitoredMemoryOperations()
    {
        //        findInstructions();
        findMonitoredMemoryInstructions();
        if (CURRENT_MONITOR == MonitorType::ASAN)
            errs() << "ASAN:";
        else if (CURRENT_MONITOR == MonitorType::BaggyBounds)
            errs() << "Baggy:";
        else if (CURRENT_MONITOR == MonitorType::BaggyBoundsASAN)
            errs() << "Baggy+ASAN:";
        errs() << monitoredMemoryOperations.size() << " monitored operations found in:" << funcBeingAnalyzed->getName()
               << "\n";
        return monitoredMemoryOperations;
    }

    void findMonitoredMemoryInstructions();
};

inline std::ofstream createFileWriter(std::string fileName)
{
    std::ofstream outputFile;
    outputFile.open(fileName, std::ios::out | std::ios::trunc);
    return outputFile;
}

#endif // ESTIMATION_PASS_HH
