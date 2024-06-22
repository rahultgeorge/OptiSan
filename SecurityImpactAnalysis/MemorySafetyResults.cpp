#include "MemorySafetyResults.hh"

MemorySafetyResults *MemorySafetyResults::_results = nullptr;

void MemorySafetyResults::addUnsafeMemoryAccess(llvm::Instruction *instruction) { unsafeStackMemoryAccesses.insert(instruction); };

void MemorySafetyResults::addUnsafePointerArithmetic(llvm::Instruction *instruction)
{
    unsafePointerArithemticInstructions.insert(instruction);
}

void MemorySafetyResults::addMayPointToStackPtr(llvm::Value *ptr)
{
    mayPointToStackUnsafePtr.insert(ptr);
}

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

std::set<llvm::Instruction *> MemorySafetyResults::getUnsafeObjectsForAccess(llvm::Instruction *memoryAccess)
{

    std::set<llvm::Instruction *> unsafeStackObjects;

    if (!memoryAccess)
        return unsafeStackObjects;

    auto itr = unsafeMemoryAccessToMemoryObject.equal_range(memoryAccess);

    for (auto it = itr.first; it != itr.second; it++)
    {
        unsafeStackObjects.insert(it->second);
    }
    return unsafeStackObjects;
}

std::set<llvm::Instruction *> MemorySafetyResults::getUnsafeObjectsForPointerArithmetic(llvm::Instruction *pointerArithmetic)
{
    std::set<llvm::Instruction *> unsafeStackObjects;

    if (!pointerArithmetic)
        return unsafeStackObjects;

    auto itr = unsafePointerArithmeticToMemoryObject.equal_range(pointerArithmetic);

    for (auto it = itr.first; it != itr.second; it++)
    {
        unsafeStackObjects.insert(it->second);
    }
    return unsafeStackObjects;
}
