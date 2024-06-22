
#ifndef MEMORY_SAFETY_RESULTS_HH
#define MEMORY_SAFETY_RESULTS_HH

#include <set>
#include <map>
#include <queue>
#include <unordered_map>

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

typedef std::set<llvm::Instruction *> InstructionSet;

class MemorySafetyResults
{

private:
    static MemorySafetyResults *_results;

    std::set<llvm::Instruction *> unsafePointerArithemticInstructions;

    std::set<llvm::Instruction *> unsafeStackMemoryAccesses;

    std::unordered_multimap<llvm::Instruction *, llvm::Instruction *> unsafeMemoryAccessToUnsafePointerArithmetic;

    std::unordered_multimap<llvm::Instruction *, llvm::Instruction *> unsafePointerArithmeticToMemoryObject;

    std::unordered_multimap<llvm::Instruction *, llvm::Instruction *> unsafeMemoryAccessToMemoryObject;

    MemorySafetyResults(){};

    ~MemorySafetyResults(){};

public:
    static MemorySafetyResults *getInstance()
    {
        if (_results == nullptr)
        {
            _results = new MemorySafetyResults();
        }
        return _results;
    };

    void addUnsafeMemoryAccess(llvm::Instruction *instruction);

    std::set<llvm::Instruction *> getUnsafeMemoryAcceses() { return unsafeStackMemoryAccesses; };

    std::set<llvm::Instruction *> getUnsafeObjectsForAccess(llvm::Instruction *memoryAccess) { return unsafeStackMemoryAccesses; };

    void addUnsafePtrArithmeticForUnsafeMemoryAccess(llvm::Instruction *, llvm::Instruction *);

    void addStackObjectForUnsafePointerArithmetic(llvm::Instruction *, llvm::Instruction *);

    void addStackObjectForUnsafeMemoryAccess(llvm::Instruction *, llvm::Instruction *);

    void removeUnsafeMemoryAccess(llvm::Instruction *instruction);

    // using unsafeStackMemoryAccesses.begin() as unsafe_memory_it_begin;
};

#endif // MEMORY_SAFETY_RESULTS_HH
