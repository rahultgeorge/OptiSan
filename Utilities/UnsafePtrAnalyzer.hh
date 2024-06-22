#include "FunctionScanPass.hh"
#include "GraphConstants.h"
#include <queue>
#include <neo4j-client.h>
#include "PTAWrapper.hh"
using namespace llvm;

#define PRUNE_MAY_POINT_TO_STACK_OOBS 1

/**
 * This is a utility pass to deal with cases where there was no points to info available
 * Also, to confirm other cases i.e. recompute points to one for ones which were confirmed as may point to stack (at least 1 stack object found)
 */
class UnsafePtrAnalyzer : public ModulePass
{
private:
    Module *module = NULL;
    std::string programName;

    std::set<Function *> functionsToMonitor;
    // If we do analyze formal args for a function then we cache it
    std::map<Function *, std::set<Value *>> functionToArgCache;
    std::map<Value *, std::set<Instruction *>> valueToStackObjects;

    // TODO - Replace this also we may switch to debug id
    std::map<std::string, Instruction *> irToInstructionCache;

    void fetchOOBStatesAndAnalyze();

    void fetchPotentialStackOOBStatesAndAnalyze();

    Instruction *findInstructionInFunctionUsingIR(std::string instructionString, Function *function);

    Instruction *findInstructionInFunctionUsingDebugInfo(std::string dbgID, unsigned int opcode,
                                                         std::string instructionString,
                                                         Function *function);

    std::set<Instruction *> findStackDataSource(GetElementPtrInst *oobGEP);

    Argument *findArgument(Value *argOrGV);

    void identifyFormalArguments(Function *function);

    std::string findProgramInstructionInPDG(Instruction *instruction);

    std::string findLogicalNodeInDBForUnsafeObject(std::string);

    std::string getFunctionDebugInfo(std::string functionName);

    std::string getFunctionUsingDebugInfo(std::string debugInfo);

public:
    static char ID; // Pass identification, replacement for typeid

    UnsafePtrAnalyzer() : ModulePass(ID) {}

    StringRef getPassName() const override { return "UnsafePtrAnalyzer"; }

    void getAnalysisUsage(AnalysisUsage &AU) const;

    bool runOnModule(Module &m);
};
