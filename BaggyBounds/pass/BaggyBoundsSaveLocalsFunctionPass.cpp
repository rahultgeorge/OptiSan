#include "BaggyBoundsFunctionPasses.hh"

/*
 *  Aligns stack data objects and saves everything (stack objects) to the table
 *  Baggy by design cannot handle dyn alloca. Should move such objects to the heap
 *  For now we skip such functions
 */
using namespace BaggyBounds;

// Utility functions taken from ASAN

inline bool BaggyBoundsSaveLocalsFunctionPass::isConstantSizeAlloca(const AllocaInst &AI)
{
    if (AI.isArrayAllocation())
    {
        const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
        if (!CI)
            return false;
    }
    Type *Ty = AI.getAllocatedType();
    return Ty->isSized();
}

uint64_t BaggyBoundsSaveLocalsFunctionPass::getAllocaSizeInBytes(const AllocaInst &AI) const
{
    uint64_t ArraySize = 1;
    if (AI.isArrayAllocation())
    {
        const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
        assert(CI && "non-constant array size");
        ArraySize = CI->getZExtValue();
    }
    Type *Ty = AI.getAllocatedType();
    uint64_t SizeInBytes =
        AI.getModule()->getDataLayout().getTypeAllocSize(Ty);
    return SizeInBytes * ArraySize;
}

bool BaggyBoundsSaveLocalsFunctionPass::isInterestingAlloca(const AllocaInst &AI)
{

    // All stack objects must be aligned to slot size for this instrumentation (just alignment)to work or alternatively modify the size of the allocation as well
    //    return true;
    // Precise mode, add flag later
    if (PRECISE_STACK_MD_MODE)
    {
        if (!AI.hasMetadata(BAGGY_STACK_OBJECT))
            return false;
    }

    bool IsInteresting =
        ((!AI.getAllocatedType()->isPointerTy()) && AI.getAllocatedType()->isSized() &&
         // alloca() may be called with 0 size, ignore it.
         ((!AI.isStaticAlloca()) || getAllocaSizeInBytes(AI) > 0) &&
         // We are only interested in allocas not promotable to registers.
         // Promotable allocas are common under -O0.
         (!isAllocaPromotable(&AI)) &&
         // inalloca allocas are not treated as static, and we don't want
         // dynamic alloca instrumentation for them as well.
         !AI.isUsedWithInAlloca() &&
         // swifterror allocas are register promoted by ISel
         !AI.isSwiftError());

    return IsInteresting;
}

void BaggyBoundsSaveLocalsFunctionPass::handleConstantSizeAlloca(Module &M, AllocaInst *originalAlloca)
{

    uint64_t objectSize = getAllocaSizeInBytes(*originalAlloca);
    // Allocation bounds and desired alignment are the same
    uint64_t desired_alignment = get_alignment(objectSize);
    MDNode *MD = MDNode::get(currFunc->getContext(), {});

    AllocaInst *newAlloca = new AllocaInst(IntegerType::getInt8Ty(M.getContext()), 0, ConstantInt::get(IntegerType::get(M.getContext(), 64), desired_alignment), originalAlloca->hasName() ? originalAlloca->getName() : "baggyAlloca");
    newAlloca->setAlignment(Align(desired_alignment));

    Instruction *ptrToInt = new PtrToIntInst(newAlloca, IntegerType::getInt64Ty(M.getContext()));
    Instruction *intToPtr = new IntToPtrInst(ptrToInt, originalAlloca->getType());

    newAlloca->insertAfter(originalAlloca);
    ptrToInt->insertAfter(newAlloca);
    intToPtr->insertAfter(ptrToInt);
    originalAlloca->replaceAllUsesWith(intToPtr);

    /*     if (originalAlloca->getFunction()->getName().equals("WM_operator_properties_sanitize"))
        {
            errs() << "Original alloca inst" << *originalAlloca << "\n";
            errs() << "\t Alignment:" << originalAlloca->getAlignment() << "\n";
            errs() << "\t Object size:" << objectSize << "\n";
            errs() << "New alloca inst" << *newAlloca << "\n";
            errs() << "\t Size :" << getAllocaSizeInBytes(*newAlloca) << "\n";
            errs() << "\t Alignment :" << newAlloca->getAlignment() << "\n";
        } */

    // Cast the pointer to an int and then add a save instruction.
    //    Instruction *objAddr = new PtrToIntInst(intToPtr, IntegerType::get(M.getContext(), 64));
    //    objAddr->setMetadata(BAGGY_INTRINSIC_INST, MD);

    //    objAddr->insertAfter(intToPtr);

    Instruction *saveInst = get_save_in_table_instr(M, ptrToInt, desired_alignment);

    saveInst->insertAfter(intToPtr);
    //    errs()<<"TRYING TO ERASE NOW\n";
    originalAlloca->eraseFromParent();
}

void BaggyBoundsSaveLocalsFunctionPass::handleConstantSizeAllocas(std::set<AllocaInst *> allocasToInstrument)
{

    uint64_t allocation_size;
    uint64_t desired_alignment;
    uint64_t curr_alignment;

    IRBuilder<> builder(&currFunc->getEntryBlock().front());

    Value *baggyBoundsTablePtr = builder.CreateLoad(baggyBoundsTable, "boundsTable");
    AllocaInst *newAlloca = NULL;

    GetElementPtrInst *boundsTableGEP = NULL;
    MDNode *MD = MDNode::get(currFunc->getContext(), {});

    // Step 1 - Rewrite allocas and metadata operations in a separate BB
    for (auto alloca_it : allocasToInstrument)
    {
        IRBuilder<> builder(alloca_it);

        if (alloca_it->isArrayAllocation())
            newAlloca = builder.CreateAlloca(alloca_it->getAllocatedType(), alloca_it->getArraySize());
        else
            newAlloca = builder.CreateAlloca(alloca_it->getAllocatedType());

        if (getAllocaSizeInBytes(*alloca_it) != getAllocaSizeInBytes(*newAlloca))
        {
            errs() << "Failed to create correct new alloca\n";
            continue;
        }
        allocation_size = getAllocaSizeInBytes(*newAlloca);
        desired_alignment = get_alignment(allocation_size);
        curr_alignment = newAlloca->getAlignment();

        newAlloca->setAlignment(MaybeAlign(max(curr_alignment, desired_alignment)));

        // Inline the saving
        Value *BaseInt = builder.CreatePtrToInt(newAlloca, IntegerType::get(currFunc->getContext(), 64));

        if (dyn_cast<PtrToIntInst>(BaseInt))
            dyn_cast<PtrToIntInst>(BaseInt)->setMetadata(BAGGY_INTRINSIC_INST, MD);

        Value *slotID = builder.CreateLShr(BaseInt, get_lg(SLOT_SIZE), "slotID");

        //        ConstantExpr::getGetElementPtr(baggyBoundsTablePtr->getType(),)
        Value *boundsTableObjEntry = builder.CreateInBoundsGEP(baggyBoundsTablePtr, slotID);

        boundsTableGEP = dyn_cast<GetElementPtrInst>(boundsTableObjEntry);
        if (boundsTableGEP)
        {
            boundsTableGEP->setMetadata(BAGGY_INTRINSIC_INST, MD);
        }

        // Create a value corresponding to the required  (log) allocation size(char)* number of slots
        auto num_slots = desired_alignment / SLOT_SIZE;
        std::vector<Constant *> metadataValue;

        auto log_of_size = get_lg(desired_alignment);
        for (auto i = 0; i < num_slots; i++)
        {
            metadataValue.push_back(ConstantInt::get(Type::getInt8Ty(currFunc->getContext()), log_of_size));
        }
        ArrayType *objMetadataType = ArrayType::get(Type::getInt8Ty(currFunc->getContext()), num_slots);

        //        errs() << "New alloca:" << *newAlloca << "\n";
        //        errs() << "\t Object size (log):" << log_of_size << "\n";
        //        errs() << "\t Desired alignment:" << desired_alignment << "| # slots:" << num_slots << "\n";

        GlobalVariable *objSizeMetadata = new GlobalVariable(*currFunc->getParent(), objMetadataType, true,
                                                             GlobalVariable::InternalLinkage,
                                                             ConstantArray::get(objMetadataType, metadataValue),
                                                             "baggy_stack_gen" + std::to_string(num_slots));

        Value *castedObjSizeMetadata = builder.CreatePtrToInt(objSizeMetadata,
                                                              Type::getInt8Ty(currFunc->getContext()));

        if (dyn_cast<PtrToIntInst>(castedObjSizeMetadata))
            dyn_cast<PtrToIntInst>(castedObjSizeMetadata)->setMetadata(BAGGY_INTRINSIC_INST, MD);

        builder.CreateStore(castedObjSizeMetadata,
                            boundsTableObjEntry);
        alloca_it->replaceAllUsesWith(newAlloca);
    }

    // Step 3 - Delete old allocas (?)
    /*    for (auto alloca_it: allocasToInstrument) {
            alloca_it->eraseFromParent();
        }*/
}

// TODO - Think of a way we can handle dyn alloca? Move to heap can't think of anything else as of now

bool BaggyBoundsSaveLocalsFunctionPass::doInitialization(Module &M)
{
    DL = const_cast<DataLayout *>(&(M.getDataLayout()));
    baggyBoundsTable = M.getOrInsertGlobal("baggy_bounds_table",
                                           Type::getInt8PtrTy(M.getContext()));

    if (!baggyMalloc)
    {
        std::vector<Type *> baggyMallocArgs;
        baggyMallocArgs.push_back(Type::getInt64Ty(M.getContext()));

        FunctionType *baggyMallocFuncType = FunctionType::get(Type::getInt8PtrTy(M.getContext()),
                                                              baggyMallocArgs, false);

        baggyMalloc =
            M.getOrInsertFunction("baggy_malloc", baggyMallocFuncType);
    }

    return true;
}

bool BaggyBoundsSaveLocalsFunctionPass::runOnFunction(Function &F)
{

    if (F.hasMetadata(BAGGY_SKIP_FUNCTION))
        return false;

    // errs() << "Running on func:" << F.getName() << "\n";

    currFunc = &F;
    bool cannotHandleFunc = false;
    AllocaInst *localVarForArg = nullptr;
    MDNode *MD = MDNode::get(F.getContext(), {});
    std::set<AllocaInst *> interestingAllocas;
    // Find alloca instructions and handle as needed
    AllocaInst *allocaInst = nullptr;
    CallInst *stackObjectMovedToHeap = nullptr;
    BitCastInst *castedPtrToDynAlloca = nullptr;

    // To deal with dynamically sized stack allocations
    BinaryOperator *objectSize = nullptr;
    Value *arraySize = nullptr;
    uint64_t SizeInBytes = 0;
    Type *allocatedType = nullptr;
    std::vector<Value *> mallocParams;

    for (auto &arg : F.args())
    {

        auto &entryBlockInstList = F.getEntryBlock().getInstList();

        // If this is passed byval then we need to save the bounds (as this is a new object deep copy)
        if (arg.hasByValAttr())
        {

            //            errs() << "\t By value arg:" << arg << "\n";
            Type *argType = arg.getParamByValType();

            if (argType)
            {

                if (argType->isArrayTy())
                {
                    // errs() << "Skipping by val arg type:" << arg << "\n";
                    continue;
                }

                // Insert this new local var in entry BB
                localVarForArg = new AllocaInst(argType, 0, nullptr,
                                                (arg.hasName() ? arg.getName() : "arg" + Twine(arg.getArgNo())) +
                                                    ".byval");
                entryBlockInstList.push_front(localVarForArg);
                arg.replaceAllUsesWith(localVarForArg);

                // Insert immediately after because there might be uses of the arg in the entry BB
                LoadInst *argValue = new LoadInst(argType, &arg, "");
                argValue->setMetadata(BAGGY_INTRINSIC_INST, MD);
                argValue->insertAfter(localVarForArg);

                StoreInst *storeArgToLocalVar = new StoreInst(argValue, localVarForArg, false);
                storeArgToLocalVar->setMetadata(BAGGY_INTRINSIC_INST, MD);
                storeArgToLocalVar->insertAfter(argValue);
            }
            // TODO - WHat about inalloca? (Apparently 32 bit MS ABI so should not be a problem)
        }
        else if (arg.hasStructRetAttr())
        {
            //            errs() << "\t Struct ret arg:" << arg << "\n";
            Type *argType = arg.getType()->getPointerElementType();
            if (argType)
            {
                if (argType->isArrayTy())
                {
                    errs() << "Skipping sret arg type:" << arg << "\n";
                    continue;
                }

                // Insert this new local var in entry BB

                localVarForArg = new AllocaInst(argType, 0, nullptr,
                                                (arg.hasName() ? arg.getName() : "arg" + Twine(arg.getArgNo())) +
                                                    ".sret");
                entryBlockInstList.push_front(localVarForArg);

                arg.replaceAllUsesWith(localVarForArg);

                // Insert immediately after because there might be uses of the arg in the entry BB
                LoadInst *argValue = new LoadInst(argType, &arg, "");
                argValue->setMetadata(BAGGY_INTRINSIC_INST, MD);
                argValue->insertAfter(localVarForArg);

                StoreInst *storeArgToLocalVar = new StoreInst(argValue, localVarForArg, false);
                storeArgToLocalVar->setMetadata(BAGGY_INTRINSIC_INST, MD);
                storeArgToLocalVar->insertAfter(argValue);

                // For sret arg need to put back local arg value in the arg before exiting
                for (auto &bb : F.getBasicBlockList())
                {
                    if (ReturnInst *returnInst = dyn_cast<ReturnInst>(bb.getTerminator()))
                    {
                        // Exit BB so put val back

                        // Read local var (corresponding to arg) value
                        LoadInst *localVarValue = new LoadInst(argType, localVarForArg, "");
                        localVarValue->setMetadata(BAGGY_INTRINSIC_INST, MD);

                        localVarValue->insertBefore(returnInst);

                        StoreInst *storeLocalVarToArg = new StoreInst(localVarValue, &arg, false);
                        storeLocalVarToArg->setMetadata(BAGGY_INTRINSIC_INST, MD);
                        storeLocalVarToArg->insertAfter(localVarValue);
                    }
                }
            }
        }

        // Vaarg instruction is not supported by most backends and va_list type is not well-defined so using hacky string approach for x86_64 backend
        // TODO - Think of a robust way to deal with this later
        if (arg.getType())
        {
            Type *argType = arg.getType();
            while (argType->isPointerTy() || argType->isArrayTy())
            {
                if (argType->isPointerTy())
                    argType = cast<PointerType>(argType)->getElementType();
                else
                    argType = cast<ArrayType>(argType)->getElementType();
            }
            if (argType->isStructTy())
            {
                StructType *structType = cast<StructType>(argType);
                if (structType->isLiteral())
                    continue;
                StringRef structTypeName = argType->getStructName();
                if (structTypeName.contains("__va_list_tag"))
                {
                    //                    errs() << "Vaarg type(DEBUG):" << *argType << ":"  << "\n";
                    //                    errs() << "\t" << "Struct type name:" << structTypeName << "\n";
                    if (!PRECISE_STACK_MD_MODE)
                        errs() << "Cannot instrument function (VA_ARG) as arg:" << F.getName() << "\n";
                    cannotHandleFunc = true;
                }
            }
        }
    }

    for (Function::iterator bbiter = F.begin(); bbiter != F.end(); ++bbiter)
    {
        BasicBlock &bb = *bbiter;
        BasicBlock::InstListType &iList = bb.getInstList();
        for (BasicBlock::InstListType::iterator iiter = iList.begin();
             iiter != iList.end(); ++iiter)
        {
            if (isa<AllocaInst>(iiter))
            {
                allocaInst = dyn_cast<AllocaInst>(iiter);

                if (isInterestingAlloca(*allocaInst))
                {
                    if (isConstantSizeAlloca(*allocaInst))
                    {
                        interestingAllocas.insert(allocaInst);
                    }
                    else
                    {
                        if (HEAP_PROTECTION_OFF)
                            continue;
                        // errs() << "Cannot instrument dyn alloca in function:" << F.getName() << "\n";
                        // errs() << "Dyn Alloca:" << *allocaInst << "\n";

                        if (!baggyMalloc)
                        {
                            errs() << "Failed to create baggy malloc\n";
                            continue;
                        }

                        // Step 1 - Figure out actual object size
                        allocatedType = allocaInst->getAllocatedType();
                        mallocParams.clear();
                        if (allocaInst->isArrayAllocation())
                        {
                            arraySize = allocaInst->getArraySize();
                            SizeInBytes =
                                allocaInst->getModule()->getDataLayout().getTypeAllocSize(allocatedType);

                            if (SizeInBytes > 1)
                            {
                                // errs() << "Size >1:" << *arraySize << " * " << SizeInBytes << "\n";
                                objectSize = BinaryOperator::Create(Instruction::Mul, arraySize,
                                                                    ConstantInt::get(
                                                                        IntegerType::get(
                                                                            F.getParent()->getContext(),
                                                                            64),
                                                                        SizeInBytes));

                                mallocParams.push_back(objectSize);
                                stackObjectMovedToHeap = CallInst::Create(baggyMalloc,
                                                                          mallocParams);
                                stackObjectMovedToHeap->insertBefore(allocaInst);
                                objectSize->insertBefore(stackObjectMovedToHeap);

                                // errs() << "\t Object size inst:" << *objectSize << "\n";
                            }
                            else
                            {
                                // errs() << "\t Array size:" << *arraySize << "\n";
                                mallocParams.push_back(arraySize);

                                stackObjectMovedToHeap = CallInst::Create(baggyMalloc,
                                                                          mallocParams);
                                //                                errs() << "\t Baggy malloc inst:" << *stackObjectMovedToHeap << "\n";

                                stackObjectMovedToHeap->insertBefore(allocaInst);
                            }

                            castedPtrToDynAlloca = new BitCastInst(stackObjectMovedToHeap, allocaInst->getType(), "newPtr");
                            castedPtrToDynAlloca->insertAfter(stackObjectMovedToHeap);
                            allocaInst->replaceAllUsesWith(castedPtrToDynAlloca);
                            // errs() << "\t Baggy malloc inst:" << *stackObjectMovedToHeap << "\n";
                            // errs() << "\t Ptr to heap obj:" << *castedPtrToDynAlloca << "\n";
                        }
                        else
                        {
                            // Type is not sized so cannot do anything (this should be rare)
                            cannotHandleFunc = true;
                            if (!PRECISE_STACK_MD_MODE)
                                errs() << "Cannot instrument function:" << F.getName() << "\n";
                        }
                    }
                }
            }

            //                //Check for va_arg inst, (Va_start,va_copy and va_end are intrinsic functions). Not well supported
            //            else if (isa<VAArgInst>(iiter)) {
            //                cannotHandleFunc = true;
            //            }
        }
    }

    // Deal with function arguments (formal arguments)
    if (F.isVarArg())
        cannotHandleFunc = true;

    if (cannotHandleFunc && (!PRECISE_STACK_MD_MODE))
    {
        MDNode *MD = MDNode::get(F.getContext(), {});
        F.setMetadata(BAGGY_SKIP_FUNCTION, MD);
        return true;
    }

    for (auto it : interestingAllocas)
    {
        handleConstantSizeAlloca(*currFunc->getParent(), it);
    }

    return true;
}

void BaggyBoundsSaveLocalsFunctionPass::getAnalysisUsage(AnalysisUsage &AU) const
{
}

char BaggyBoundsSaveLocalsFunctionPass::ID = 0;

static RegisterPass<BaggyBoundsSaveLocalsFunctionPass>
    Y("baggy-save-local", "Baggy Bounds Locals Initialization Pass",
      false,
      false);
