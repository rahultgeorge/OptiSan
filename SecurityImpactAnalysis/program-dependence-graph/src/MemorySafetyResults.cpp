#include "MemorySafetyResults.hh"

MemorySafetyResults *MemorySafetyResults::_results = nullptr;

void MemorySafetyResults::addUnsafeMemoryAccess(llvm::Instruction *instruction) { unsafeStackMemoryAccesses.insert(instruction); };

void MemorySafetyResults::removeUnsafeMemoryAccess(llvm::Instruction *instruction)
{
    unsafeStackMemoryAccesses.erase(instruction);
};

void MemorySafetyResults::addUnsafePtrArithmeticForUnsafeMemoryAccess(llvm::Instruction *unsafeMemoryAccess, llvm::Instruction *unsafePointerArithmetic)
{
    unsafeMemoryAccessToUnsafePointerArithmetic.insert(std::pair<llvm::Instruction *, llvm::Instruction *>(unsafeMemoryAccess, unsafePointerArithmetic));
}


void MemorySafetyResults::addStackObjectForUnsafePointerArithmetic(llvm::Instruction *pointerArithmetic, llvm::Instruction *memoryObject)
{
    unsafePointerArithmeticToMemoryObject.insert(std::pair<llvm::Instruction *, llvm::Instruction *>(pointerArithmetic, memoryObject));
}


void MemorySafetyResults::addStackObjectForUnsafeMemoryAccess(llvm::Instruction *unsafeMemoryAccess, llvm::Instruction *memoryObject)
{
    unsafeMemoryAccessToMemoryObject.insert(std::pair<llvm::Instruction *, llvm::Instruction *>(unsafeMemoryAccess, memoryObject));
}