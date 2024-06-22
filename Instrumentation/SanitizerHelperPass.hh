#ifndef SANITZATION_HELPER_PASS_HH
#define SANITZATION_HELPER_PASS_HH

// Base header with all common LLVM and C++ DS headers
#include "llvm/Pass.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/User.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/CFG.h"

#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "llvm/Transforms/Utils/PromoteMemToReg.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/SwapByteOrder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <system_error>

#include <queue>
#include <cstdlib>
#include <string.h>
#include <vector>
#include <set>
#include <regex>
#include <map>
#include <neo4j-client.h>
#include "GraphConstants.h"
#include "FunctionScanPass.hh"
#include <chrono>

#if __has_include(<filesystem>)

#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
error "Missing the <filesystem> header."
#endif

// #define DEBUG 0
// This is for opt baseline for cost estimation (to deal with inline attr)
#define OPTIMIZATION_BASELINE_MODE 0

#define OPTIMIZATION_PIPELINE_MODE
// In this mode just run monitors sequentially - Do not guide sanitization.  cost estimation  mode for opt binary for ASan
#define TEST_MODE 0
// Metadata we use to annotate (Switch to attr for functions - cheaper)
#define BAGGY_SKIP_FUNCTION "baggySkip"
// ASAN Attribute
#define ASAN_SKIP_FUNCTION "no_sanitize"
// Metadata to annotate instructions
#define ASAN_MONITORING_POINT "asanMP"
#define BAGGY_MONITORING_POINT "baggyMP"
// ASAN Stack metadata
#define ASAN_STACK_OBJECT "asanStackObj"
// Baggy Stack metadata
#define BAGGY_STACK_OBJECT "baggyStackObj"

using namespace llvm;

// The different monitors
enum MonitorType
{
    ASAN,
    BaggyBounds,
    ESAN,
    UNKNOWN
};

namespace asan_minus
{
// ASAN-- Scalable Value
#define RZ_SIZE 16
#define CHECK_RANGE 64
#define CHECK_RANGE_LOOP 32
#define MAX_STEP_SIZE 8
    enum addrType
    {
        IBIO,
        VBIO,
        IBVO,
        VBVO,
        UNKNOWN
    };

    enum SCEVType
    {
        SEIncrease,
        SEDecrease,
        SEConstant,
        SELoopInvariant,
        SEUnknown
    };

    /// This struct defines the shadow mapping using the rule:
    ///   shadow = (mem >> Scale) ADD-or-OR Offset.
    struct ShadowMapping
    {
        int Scale;
        uint64_t Offset;
        bool OrShadowOffset;
    };
    static const uint64_t kDefaultShadowScale = 3;
    static const uint64_t kDefaultShadowOffset32 = 1ULL << 29;
    static const uint64_t kDefaultShadowOffset64 = 1ULL << 44;
    static const uint64_t kDynamicShadowSentinel = ~(uint64_t)0;
    static const uint64_t kIOSShadowOffset32 = 1ULL << 30;
    static const uint64_t kIOSSimShadowOffset32 = 1ULL << 30;
    static const uint64_t kIOSSimShadowOffset64 = kDefaultShadowOffset64;
    static const uint64_t kSmallX86_64ShadowOffset = 0x7FFF8000; // < 2G.
    static const uint64_t kLinuxKasan_ShadowOffset64 = 0xdffffc0000000000;
    static const uint64_t kPPC64_ShadowOffset64 = 1ULL << 41;
    static const uint64_t kSystemZ_ShadowOffset64 = 1ULL << 52;
    static const uint64_t kMIPS32_ShadowOffset32 = 0x0aaa0000;
    static const uint64_t kMIPS64_ShadowOffset64 = 1ULL << 37;
    static const uint64_t kAArch64_ShadowOffset64 = 1ULL << 36;
    static const uint64_t kFreeBSD_ShadowOffset32 = 1ULL << 30;
    static const uint64_t kFreeBSD_ShadowOffset64 = 1ULL << 46;
    static const uint64_t kWindowsShadowOffset32 = 3ULL << 28;
    // The shadow memory space is dynamically allocated.
    static const uint64_t kWindowsShadowOffset64 = kDynamicShadowSentinel;

    static const size_t kMinStackMallocSize = 1 << 6;  // 64B
    static const size_t kMaxStackMallocSize = 1 << 16; // 64K
    static const uintptr_t kCurrentStackFrameMagic = 0x41B58AB3;
    static const uintptr_t kRetiredStackFrameMagic = 0x45E0360E;

    static const char *const kAsanModuleCtorName = "asan.module_ctor";
    static const char *const kAsanModuleDtorName = "asan.module_dtor";
    static const uint64_t kAsanCtorAndDtorPriority = 1;
    static const char *const kAsanReportErrorTemplate = "__asan_report_";
    static const char *const kAsanRegisterGlobalsName = "__asan_register_globals";
    static const char *const kAsanUnregisterGlobalsName =
        "__asan_unregister_globals";
    static const char *const kAsanRegisterImageGlobalsName =
        "__asan_register_image_globals";
    static const char *const kAsanUnregisterImageGlobalsName =
        "__asan_unregister_image_globals";
    static const char *const kAsanPoisonGlobalsName = "__asan_before_dynamic_init";
    static const char *const kAsanUnpoisonGlobalsName = "__asan_after_dynamic_init";
    static const char *const kAsanInitName = "__asan_init";
    static const char *const kAsanVersionCheckName =
        "__asan_version_mismatch_check_v8";
    static const char *const kAsanPtrCmp = "__sanitizer_ptr_cmp";
    static const char *const kAsanPtrSub = "__sanitizer_ptr_sub";
    static const char *const kAsanHandleNoReturnName = "__asan_handle_no_return";
    static const int kMaxAsanStackMallocSizeClass = 10;
    static const char *const kAsanStackMallocNameTemplate = "__asan_stack_malloc_";
    static const char *const kAsanStackFreeNameTemplate = "__asan_stack_free_";
    static const char *const kAsanGenPrefix = "__asan_gen_";
    static const char *const kODRGenPrefix = "__odr_asan_gen_";
    static const char *const kSanCovGenPrefix = "__sancov_gen_";
    static const char *const kAsanSetShadowPrefix = "__asan_set_shadow_";
    static const char *const kAsanPoisonStackMemoryName =
        "__asan_poison_stack_memory";
    static const char *const kAsanUnpoisonStackMemoryName =
        "__asan_unpoison_stack_memory";
    static const char *const kAsanGlobalsRegisteredFlagName =
        "__asan_globals_registered";

    static const char *const kAsanOptionDetectUseAfterReturn =
        "__asan_option_detect_stack_use_after_return";

    static const char *const kAsanShadowMemoryDynamicAddress =
        "__asan_shadow_memory_dynamic_address";

    static const char *const kAsanAllocaPoison = "__asan_alloca_poison";
    static const char *const kAsanAllocasUnpoison = "__asan_allocas_unpoison";

    // Accesses sizes are powers of two: 1, 2, 4, 8, 16.
    static const size_t kNumberOfAccessSizes = 5;

    static const unsigned kAllocaRzSize = 32;
}

const MonitorType monitors[] = {MonitorType::ASAN, MonitorType::BaggyBounds};

// An unsafe operation should map to this - Monitor type and where will it place this check (which instruction)
class MonitorInfo
{

public:
    MonitorType monitorType;
    Instruction *monitoringPoint;

    MonitorInfo() {}

    MonitorInfo(MonitorType type, Instruction *instruction)
    {
        this->monitorType = type;
        this->monitoringPoint = instruction;
    }
};

class PreSanitizationHelper : public ModulePass
{
private:
    Module *module = NULL;
    std::string programName;

    std::chrono::_V2::system_clock::time_point start;
    std::chrono::_V2::system_clock::time_point stop;
    std::chrono::milliseconds duration;

    std::map<MonitorType, std::set<Function *>> monitorTypeToFunctions;

    std::set<std::string> functionsWhiteList;

    std::set<Function *> functionsToBeSanitizedInModule;

    std::map<std::string, Function *> moduleFunctionDIToFunctionMap;

    std::map<std::string, std::string> dbFunctionNameToModuleFunctionDI;

    bool isCurrentModuleRelevant();

    void fetchFunctionsToBeSanitized();

    void findAllWhiteListedFunctions();

    void fetchAllFunctionsToBeSanitized();

    void fetchAndAnnotateOperationsToBeMonitored();

    Function *findFunctionUsingDebugInfo(std::string functionName);

    Instruction *
    findInstructionInFunctionUsingDebugInfo(std::string dbgID, unsigned int opcode, std::string instructionString,
                                            Function *function, FunctionScanPass *);

    void analyzeInstruction(Instruction *);

    bool findDataSource(GetElementPtrInst *);

public:
    static char ID; // Pass identification, replacement for typeid

    PreSanitizationHelper() : ModulePass(ID) {}

    StringRef getPassName() const override { return "PreSanitizationHelper"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool runOnModule(Module &m);
};

class PostSanitizationHelperPass : public ModulePass
{
private:
    Module *_module;

    // ASAN--
    Type *IntptrTy;
    LLVMContext *C;
    Triple TargetTriple;

    int LongSize;
    bool Recover;

    asan_minus::ShadowMapping Mapping;
    void initializeCallbacks(Module &M);
    bool UseAfterScope;
    DominatorTree *DT;
    Function *AsanCtorFunction = nullptr;
    Function *AsanInitFunction = nullptr;
    Function *AsanHandleNoReturnFunc;
    Function *AsanPtrCmpFunction, *AsanPtrSubFunction;
    // This array is indexed by AccessIsWrite, Experiment and log2(AccessSize).
    Function *AsanErrorCallback[2][2][asan_minus::kNumberOfAccessSizes];
    Function *AsanMemoryAccessCallback[2][2][asan_minus::kNumberOfAccessSizes];
    // This array is indexed by AccessIsWrite and Experiment.
    Function *AsanErrorCallbackSized[2][2];
    Function *AsanMemoryAccessCallbackSized[2][2];
    Function *AsanMemmove, *AsanMemcpy, *AsanMemset;
    InlineAsm *EmptyAsm;
    Value *LocalDynamicShadow;
    // GlobalsMetadata GlobalsMD;

    std::string programName;

    std::map<Instruction *, MonitorType> monitoringPointToMonitorType;

    std::map<Function *, SmallVector<Instruction *, 16>> functionToASANChecks;

    // Track these functions to do some clean up (Remove unnecessary metadata)
    std::set<Function *> unsafeFunctionsMonitored;

    std::map<MonitorType, DenseSet<Instruction *>> abortingCalls;

    DenseMap<const AllocaInst *, bool> ProcessedAllocas;

    // DenseSet<Instruction *> gepInstructions;

    // DenseSet<Instruction *> memoryDereferenceInstructions;

    void isAbortingCall(CallInst *);

    bool turnOffHeapMetadata();

    void analyzeFunctionsAndFindChecks();

    void placeChecksAsRequired();

    void findSanityCheckCallAndTurnOffCheck(BranchInst *BI, MonitorType monitorType);

    void findSanityCheckCallAndTurnOnCheck(BranchInst *BI, MonitorType monitorType);

    // ASAN-- Optimizations

    void ASAN_Optimizations(Function &F, SmallVector<Instruction *, 16> &ToInstrument, bool &foundRedundantChecks);

    void sequentialExecuteOptimizationPostDom(Function &F, SmallVector<Instruction *, 16> &ToInstrument);

    void sequentialExecuteOptimizationBoost(Function &F, SmallVector<Instruction *, 16> &ToInstrument);

    void loopOptimization(Function &F, SmallVector<Instruction *, 16> &ToInstrument);

    // ASAN-- Helper Functions

    bool isSafeAccess(ObjectSizeOffsetVisitor &ObjSizeVis, Value *Addr,
                      uint64_t TypeSize) const;
    bool isSafeAccessBoost(ObjectSizeOffsetVisitor &ObjSizeVis, Instruction *IndexInst, Value *Addr, Function *F) const;

    Value *isInterestingMemoryAccess(Instruction *I,
                                     bool *IsWrite,
                                     uint64_t *TypeSize,
                                     unsigned *Alignment,
                                     Value **MaybeMask = nullptr);

    bool isInterestingAlloca(const AllocaInst &AI);

public:
    static char ID; // Pass identification, replacement for typeid

    PostSanitizationHelperPass() : ModulePass(ID) {}

    StringRef getPassName() const override { return "MonitorPlacementPass"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool runOnModule(Module &M);
};

static std::string monitorTypeToString(MonitorType monitorType)
{
    if (monitorType == BaggyBounds)
        return "BBC";
    else if (monitorType == ASAN)
        return "ASAN";
    return "";
}

#endif
