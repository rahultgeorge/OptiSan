#include "BaggyBoundsFunctionPasses.hh"

/*
 *
 * Instruments GEP and memset makes them "SAFE"
 *
 */
using namespace BaggyBounds;

BasicBlock *
BaggyBoundsPointersFunctionPass::instrumentMemset(BasicBlock *resumeBlock, MemSetInst *memSetInst, PHINode *phi)
{
    BasicBlock *baggyCheckBlock = BasicBlock::Create(resumeBlock->getContext(), "baggy.check",
                                                     resumeBlock->getParent(), resumeBlock);
    IRBuilder<> builder(baggyCheckBlock);

    Value *Base = memSetInst->getOperand(0);
    Value *Length = memSetInst->getLength();
    Value *LengthSized;
    if (Length->getType()->getPrimitiveSizeInBits() > 64)
    {
        LengthSized = builder.CreateTrunc(Length, Type::getInt64Ty(baggyCheckBlock->getContext()));
    }
    else
    {
        LengthSized = builder.CreateZExtOrBitCast(Length, Type::getInt64Ty(baggyCheckBlock->getContext()));
    }

    Value *BaseInt = builder.CreatePtrToInt(Base, Type::getInt64Ty(baggyCheckBlock->getContext()));
    Value *EndInt = builder.CreateAdd(BaseInt, LengthSized);

    Value *slotID = builder.CreateLShr(BaseInt, 5, "baggy.offset");

    //    Value *slotID = builder.CreateCall(getSlotIDFunc->getFunctionType(), getSlotIDFunc,
    //                                       ArrayRef<Value *>(BaseInt), "slotID");

    LoadInst *BaggyBoundsTablePtr = builder.CreateLoad(baggyBoundsTable, "baggy.table");
    Value *TableAddr = builder.CreateInBoundsGEP(BaggyBoundsTablePtr, slotID);
    LoadInst *Size = builder.CreateLoad(TableAddr, "alloc.size");
    Value *MaskedSize = builder.CreateZExtOrBitCast(Size, Type::getInt64Ty(baggyCheckBlock->getContext()));
    // This add limits the max object 1F limits it to 2^31 so 3F to limit it 2^63
    Value *SizeInt = builder.CreateAnd(MaskedSize, 0x3F);
    Value *Xor = builder.CreateXor(BaseInt, EndInt);
    Value *Result = builder.CreateAShr(Xor, SizeInt);

    // Create the slow path block
    BasicBlock *slowPathBlock = BasicBlock::Create(baggyCheckBlock->getContext(), "baggy.slowPath",
                                                   baggyCheckBlock->getParent(), resumeBlock);
    IRBuilder<> slowPathBuilder(slowPathBlock);
    Value *bufcast, *pcast, *retptr;

    bufcast = slowPathBuilder.CreatePointerCast(Base, Type::getInt64PtrTy(baggyCheckBlock->getContext()));
    pcast = slowPathBuilder.CreateIntToPtr(EndInt, Type::getInt64PtrTy(baggyCheckBlock->getContext()));
    std::vector<llvm::Value *> slowPathFuncArgs;
    slowPathFuncArgs.push_back(bufcast);
    slowPathFuncArgs.push_back(pcast);
    retptr = slowPathBuilder.CreateCall(slowPathFunc, slowPathFuncArgs);
    Value *slowPathPtr = slowPathBuilder.CreatePointerCast(retptr, memSetInst->getOperand(0)->getType());
    slowPathBuilder.CreateBr(resumeBlock);

    // Branch to slowpath if necessary
    MDBuilder weightBuilder(baggyCheckBlock->getContext());
    MDNode *branchWeights;
    Value *baggyCheck;
    baggyCheck = builder.CreateICmpEQ(Result,
                                      ConstantInt::get(IntegerType::get(baggyCheckBlock->getContext(), 64), 0));
    branchWeights = weightBuilder.createBranchWeights(99, 1);
    builder.CreateCondBr(baggyCheck, resumeBlock, slowPathBlock, branchWeights);

    // Add both branches to phi node
    phi->addIncoming(memSetInst->getOperand(0), baggyCheckBlock);
    phi->addIncoming(slowPathPtr, slowPathBlock);

    return baggyCheckBlock;
}

BasicBlock *
BaggyBoundsPointersFunctionPass::instrumentGEP(BasicBlock *orig, GetElementPtrInst *originalGep, PHINode *phi)
{
    BasicBlock *baggyBlock = BasicBlock::Create(orig->getContext(), "baggy.check",
                                                orig->getParent(), orig);
    IRBuilder<> builder(baggyBlock);
    Value *base, *baseint, *tableaddr, *sizeint, *tmpsize;
    LoadInst *size, *baggyBoundsTablePtr;
    MDNode *MD = MDNode::get(originalGep->getContext(), {});

    // Baggy lookup
    // Get the original pointer  (base)
    base = builder.CreateConstInBoundsGEP1_64(originalGep->getOperand(0)->getType()->getPointerElementType(),
                                              originalGep->getOperand(0), 0, "baggy.base");

    // Convert ptr to int
    baseint = builder.CreatePtrToInt(base, IntegerType::get(baggyBlock->getContext(), 64));

    // Clear MSB if set i.e already marked as OOB
    Value *processedIntAddr = builder.CreateBinOp(Instruction::And, baseint, ConstantInt::get(IntegerType::get(baggyBlock->getContext(), 64), CLEAR_MSB_CONSTANT));

    // Find the slot id (table index)

    Value *slotID = builder.CreateLShr(processedIntAddr, get_lg(SLOT_SIZE), "baggy.offset");

    //    Value *slotID = builder.CreateCall(getSlotIDFunc->getFunctionType(), getSlotIDFunc,
    //                                       ArrayRef<Value *>(baseint), "slotID");
    // sizeTableAddr = builder.CreateConstInBoundsGEP1_32(sizeTable, 0);

    // Inlined fetch bounds
    baggyBoundsTablePtr = builder.CreateLoad(baggyBoundsTable, "baggy.table");
    baggyBoundsTablePtr->setMetadata(BAGGY_INTRINSIC_INST, MD);
    // Fetch the bounds
    tableaddr = builder.CreateInBoundsGEP(baggyBoundsTablePtr, slotID);
    size = builder.CreateLoad(tableaddr, "alloc.size");
    size->setMetadata(BAGGY_INTRINSIC_INST, MD);
    tmpsize = builder.CreateZExtOrBitCast(size, IntegerType::get(baggyBlock->getContext(), 64));
    sizeint = builder.CreateAnd(tmpsize, 0x3F);

    // insert arithmetic (GEP instruction)
    baggyBlock->getInstList().push_back(originalGep);

    // baggy check
    Value *combine, *instint, *result;
    // errs() << "Org GEP inst ret type:" << *i->getType() << "\n";

    instint = builder.CreatePtrToInt(originalGep, IntegerType::get(baggyBlock->getContext(), 64));
    // Clear MSB if set i.e already marked as OOB.
    Value *processedNewPtr = builder.CreateBinOp(Instruction::And, instint, ConstantInt::get(IntegerType::get(baggyBlock->getContext(), 64), CLEAR_MSB_CONSTANT));

    // Using base ptr (MSB could be marked) with cleared new ptr (This will ensure this always leads to slow path func if MSB is set)
    combine = builder.CreateXor(baseint, processedNewPtr);
    result = builder.CreateAShr(combine, sizeint, "baggy.result");

    // Create the slowpath block
    BasicBlock *slowPathBlock = BasicBlock::Create(baggyBlock->getContext(), "baggy.slowPath",
                                                   baggyBlock->getParent(), orig);
    IRBuilder<> slowPathBuilder(slowPathBlock);
    Value *slowPathPtr, *bufcast, *pcast, *retptr;

    bufcast = slowPathBuilder.CreatePointerCast(base, Type::getInt64PtrTy(baggyBlock->getContext()));
    pcast = slowPathBuilder.CreatePointerCast(originalGep, Type::getInt64PtrTy(baggyBlock->getContext()));
    std::vector<llvm::Value *> slowPathFuncArgs;
    slowPathFuncArgs.push_back(bufcast);
    slowPathFuncArgs.push_back(pcast);
    retptr = slowPathBuilder.CreateCall(slowPathFunc, slowPathFuncArgs);
    slowPathPtr = slowPathBuilder.CreatePointerCast(retptr, originalGep->getType());
    slowPathBuilder.CreateBr(orig);

    // Branch to slowpath if necessary
    MDBuilder weightBuilder(baggyBlock->getContext());
    MDNode *branchWeights;
    Value *baggyCheck;
    baggyCheck = builder.CreateICmpEQ(result,
                                      ConstantInt::get(IntegerType::get(baggyBlock->getContext(), 64), 0));
    branchWeights = weightBuilder.createBranchWeights(99, 1);
    builder.CreateCondBr(baggyCheck, orig, slowPathBlock, branchWeights);

    // Add both branches to phi node
    phi->addIncoming(originalGep, baggyBlock);
    phi->addIncoming(slowPathPtr, slowPathBlock);
    /*     if (baggyBoundsTablePtr->getFunction() && baggyBoundsTablePtr->getFunction()->getName().equals("mesh_uv_reset_mface"))
        {
            errs() << " Ptr arithmetic " << *originalGep << "\n\t :" << *originalGep->getType() << "\n";
            errs() << " Has all zero indices:" << originalGep->hasAllZeroIndices() << "\n";
            errs() << "Base:" << *base << "\n";
            errs() << "Base to int :" << *baseint << "\n";
            errs() << "Base to int* :" << *bufcast << "\n";
            errs() << "Ptr arithmetic to int*  :" << *pcast << "\n";
            errs() << "Return int * to original type :" << *slowPathPtr << "\n\n";
        } */

    return baggyBlock;
}

Value *BaggyBoundsPointersFunctionPass::castToIntAndClearTopBit(LLVMContext &ctxt,
                                                                BasicBlock::InstListType &iList,
                                                                BasicBlock::InstListType::iterator &i,
                                                                Value *val)
{
    Instruction *toIntInst = new PtrToIntInst(val, IntegerType::get(ctxt, 64));
    // 0x7FFFFFFFFFFFFFFF is the same as 9223372036854775807
    Instruction *zeroBitInst = BinaryOperator::Create(Instruction::And, toIntInst,
                                                      ConstantInt::get(IntegerType::get(ctxt, 64),
                                                                       CLEAR_MSB_CONSTANT));
    iList.insert(i, toIntInst);
    iList.insert(i, zeroBitInst);
    return zeroBitInst;
}

bool BaggyBoundsPointersFunctionPass::doInitialization(Module &M)
{
    baggyBoundsTable = M.getOrInsertGlobal("baggy_bounds_table",
                                           Type::getInt8PtrTy(M.getContext()));
    slowPathFunc = M.getFunction("baggy_slowpath");

    DL = const_cast<DataLayout *>(&M.getDataLayout());

    if (!slowPathFunc)
    {
        std::vector<Type *> slowPathFuncArgs;
        slowPathFuncArgs.push_back(Type::getInt64PtrTy(M.getContext()));
        slowPathFuncArgs.push_back(Type::getInt64PtrTy(M.getContext()));

        FunctionType *slowPathFuncType = FunctionType::get(Type::getInt64PtrTy(M.getContext()),
                                                           slowPathFuncArgs, false);

        slowPathFunc = dyn_cast<Function>(
            M.getOrInsertFunction("baggy_slowpath", slowPathFuncType).getCallee());
    }

    /*
    // Get the get_slot_id function

        Function *StrCpy = M.getFunction("strcpy");
    if (StrCpy != NULL)
    {
        BaggyStrCpy = M.getOrInsertFunction("baggy_strcpy",
                                            StrCpy->getFunctionType())
                          .getCallee();
    }
       errs()<<*StrCpy->getType()<<"=="<<*BaggyStrCpy->getType()<<"\n";

     getSlotIDFunc = M.getFunction("get_slot_id");
        if (!getSlotIDFunc) {
            std::vector<Type *> getSlotIDArgs;
            getSlotIDArgs.push_back(IntegerType::get(M.getContext(), 64));
            FunctionType *getSlotIDFunctionType = FunctionType::get(
                    Result=Type::getInt128Ty(M.getContext()),
                    Params=getSlotIDArgs,
                    isVarArg=false);

            getSlotIDFunc = Function::Create(getSlotIDFunctionType, GlobalValue::ExternalLinkage, "get_slot_id",
                                             M);
        }*/

    return true;
}

bool BaggyBoundsPointersFunctionPass::runOnFunction(Function &F)
{

    if (F.hasMetadata(BAGGY_SKIP_FUNCTION))
        return false;

    // To deal with OOB pointers (MSB set) appropriately for ptr to int and inequality comparisons
    for (Function::iterator bb = F.begin(), bbend = F.end(); bb != bbend; ++bb)
    {
        BasicBlock *block = &(*bb);
        BasicBlock::InstListType &iList = block->getInstList();
        for (BasicBlock::InstListType::iterator i = iList.begin(); i != iList.end(); ++i)
        {

            if (isa<PtrToIntInst>(*i))
            {
                PtrToIntInst *ptii = cast<PtrToIntInst>(i);
                // errs()<<"#Size in bits:"<<ptii->getDestTy()->getPrimitiveSizeInBits()<<"\n";

                if (shouldInstrumentPtrToInt(ptii))
                {
                    // AND out the most significant bit of newly created int
                    PtrToIntInst *inst1 = cast<PtrToIntInst>(ptii->clone());
                    BinaryOperator *inst2 = BinaryOperator::Create(Instruction::And, inst1, ConstantInt::get(IntegerType::get(block->getContext(), 64), CLEAR_MSB_CONSTANT));
                    iList.insert(i, inst1);
                    ReplaceInstWithInst(i->getParent()->getInstList(), i, inst2);
                }
            }
            else if (isa<ICmpInst>(*i))
            {
                ICmpInst *ici = cast<ICmpInst>(i);
                if (!ici->isEquality())
                {
                    Value *operand2 = ici->getOperand(1);
                    if (operand2->getType()->isVectorTy())
                        continue;
                    ICmpInst *new_ici = cast<ICmpInst>(ici->clone());
                    for (int op_num = 0; op_num < 2; op_num++)
                    {
                        Value *operand = ici->getOperand(op_num);
                        if (operand->getType()->isPointerTy())
                        {
                            new_ici->setOperand(op_num, castToIntAndClearTopBit(block->getContext(), iList, i,
                                                                                operand));
                        }
                    }
                    ReplaceInstWithInst(i->getParent()->getInstList(), i, new_ici);
                }
            }
        }
    }

    GetElementPtrInst *gepInst = NULL;
    // To deal with constant GEP expressions inlined
    MemSetInst *memSetInst = NULL;
    BasicBlock *baggyCheckBlock = NULL;
    BasicBlock *resumeBlock = NULL;
    PHINode *phi = NULL;

    //    errs() << "\t Function:" << F.getName() << "\n";
    // Find GEPS and memsets that need to be instrumented
    for (Function::iterator bb = F.begin(), bbend = F.end(); bb != bbend; ++bb)
    {
        BasicBlock *block = &(*bb);
        for (BasicBlock::iterator i = block->begin(), e = block->end(); i != e; ++i)
        {

            if (gepInst = dyn_cast<GetElementPtrInst>(i))
            {

                if (!shouldInstrumentGEP(gepInst))
                    continue;

                resumeBlock = block->splitBasicBlock(i, "baggy.resume");

                GetElementPtrInst *inst = cast<GetElementPtrInst>(i->clone());

                // Remove the getelementptrinst from the old block
                // i->removeFromParent();
                phi = PHINode::Create(gepInst->getType(), 2);
                ReplaceInstWithInst(gepInst->getParent()->getInstList(), i, phi);

                // Create the instrumentation block
                baggyCheckBlock = instrumentGEP(resumeBlock, inst, phi);

                // Have control flow through the instrumentation/check block
                Instruction *term = block->getTerminator();
                if (term == NULL)
                {
                    block->getInstList().push_back(BranchInst::Create(baggyCheckBlock));
                }
                else
                {
                    term->setSuccessor(0, baggyCheckBlock);
                }

                // Skip the newly created instrumentation basicblock
                ++bb;

                // We're done with this block
                break;
            }
            else if (isa<MemSetInst>(*i))
            {
                continue;
                // TODO - Fix this such that if OOB we set MSB (The github implementation did not do this)
                //                memSetInst = cast<MemSetInst>(i);
                //                Value *dstPtr = memSetInst->getOperand(0);
                //                Instruction *dstPtrInst = dyn_cast<Instruction>(dstPtr);
                //                if (!dstPtrInst) {
                //                    //Check if gepoperator/gep constant expression then do what is necessary :)
                //                    GEPOperator *gepOperator = dyn_cast<GEPOperator>(dstPtr);
                //                    if (!gepOperator)
                //                        continue;
                //                    dstPtrInst = convertGEP(gepOperator, memSetInst);
                //                }
                //
                //                // In case dest ptr is a constant expression using -- to split at previous instruction
                //                resumeBlock = block->splitBasicBlock(dstPtrInst, "baggy.resume");
                //
                //                phi = PHINode::Create(dstPtrInst->getType(), 2);
                //                ReplaceInstWithInst(dstPtrInst, phi);
                //
                //                // Create the instrumentation block
                //                baggyCheckBlock = instrumentMemset(resumeBlock, memSetInst, phi);
                //
                //                // Have control flow through the instrumentation block
                //                Instruction *term = block->getTerminator();
                //                if (term == NULL) {
                //                    block->getInstList().push_back(BranchInst::Create(baggyCheckBlock));
                //                }
                //                else {
                //                    term->setSuccessor(0, baggyCheckBlock);
                //                }
                //
                //                // Skip the newly created instrumentation basicblock
                //                ++bb;
                //
                //                // We're done with this block
                //                break;
            }
        }
    }

    return true;
}

bool BaggyBoundsPointersFunctionPass::shouldInstrumentPtrToInt(PtrToIntInst *ptrToIntInstruction)
{
    bool shouldInstrument = false;
    bool shouldPrint = false;
    // return false;

    // TODO - deal with vector indices
    if (ptrToIntInstruction->getSrcTy()->isVectorTy())
        return false;

    if (ptrToIntInstruction->getDestTy()->getPrimitiveSizeInBits() >= 64)
    {
        shouldInstrument = true;
        if (shouldPrint)
        {
            errs() << "PtrToInt: " << *ptrToIntInstruction << "\n";
        }
        /* C/C++ allows usage of (void*)-1 to represent an invalid pointer i.e. MSB of address may be set in such cases we need not mask it
         * Very basic check/heuristic checking if it is being cast to this ptr==(void*)-1 */
        for (auto &use_it : ptrToIntInstruction->uses())
        {
            if (shouldPrint && use_it.getUser())
                errs() << "\t Use:" << *use_it.getUser() << "\n";
            if (CmpInst *cmpInst = dyn_cast<CmpInst>(use_it.getUser()))
            {
                if (cmpInst->isEquality())
                {
                    for (unsigned index = 0; index < cmpInst->getNumOperands(); ++index)
                    {
                        auto operand = cmpInst->getOperand(index);
                        if (operand)
                        {
                            if (ConstantInt *CI = dyn_cast<ConstantInt>(operand))
                                shouldInstrument = !(CI->isMinusOne());
                        }
                    }
                }
            }
            else if (SwitchInst *switchInst = dyn_cast<SwitchInst>(use_it.getUser()))
            {

                if (switchInst->getCondition() == ptrToIntInstruction)
                {
                    auto caseIt = switchInst->findCaseValue(ConstantInt::get(IntegerType::get(switchInst->getContext(), 64), -1));
                    if (caseIt != switchInst->case_default())
                    {
                        errs() << "\t\t will not instrument because of  (-1): " << *switchInst << "\n";

                        shouldInstrument = false;
                        break;
                    }
                }
            }
        }
    }
    return shouldInstrument;
}

bool BaggyBoundsPointersFunctionPass::shouldInstrumentGEP(GetElementPtrInst *getElementPtrInst)
{

    if (getElementPtrInst->hasMetadata(BAGGY_INTRINSIC_INST))
        return false;

    bool isScalarFieldType = false;
    bool shouldInstrument = true;

    // TODO- Handle vector indices later (including base operand i.e. it may be a vector of ptrs)
    for (unsigned index = 0; index < getElementPtrInst->getNumOperands(); ++index)
    {
        if (getElementPtrInst->getOperand(index)->getType()->isVectorTy())
            return false;
    }

    Type *pointerOperandType = getElementPtrInst->getPointerOperandType()->getPointerElementType();

    // Add checks, will remove as per computed placement
    if (!PRECISE_STACK_MD_MODE)
    {
        if (getElementPtrInst->hasAllZeroIndices() || (!pointerOperandType))
            return false;

        if (whiteListGEPS.find(getElementPtrInst) != whiteListGEPS.end())
            return false;

        // Original design - Not supposed to instrument accesses to scalar fields of structs
        if (pointerOperandType->isStructTy())
        {
            uint num_indices = getElementPtrInst->getNumIndices();
            StructType *structType = dyn_cast<StructType>(pointerOperandType);

            uint indexToCheck = 2;

            if (num_indices > 1)
            {
                indexToCheck = 2;
                auto field_type = structType->getTypeAtIndex(getElementPtrInst->getOperand(indexToCheck));
                if (!(field_type->isVectorTy() || field_type->isArrayTy()))
                {
                    ++indexToCheck;
                    // If accessing another struct which may contain a vector field
                    while (field_type->isStructTy() && num_indices >= indexToCheck)
                    {
                        structType = dyn_cast<StructType>(field_type);
                        field_type = structType->getTypeAtIndex(getElementPtrInst->getOperand(indexToCheck));
                        if (field_type->isVectorTy() || field_type->isArrayTy())
                            return shouldInstrument;
                        indexToCheck++;
                    }
                    // Not a vector/array field
                    isScalarFieldType = true;
                    shouldInstrument = false;
                }
                else
                {
                    //                errs() << "GEP:" << *getElementPtrInst << "\n";
                    //                errs() << "\t Struct type:" << *structType << "\n";
                    //                errs() << "\t\t Num of indices:" << num_indices << "\n";
                    //                errs() << "\t\t\t Field type:" << *field_type << "\n";
                    //                errs() << "\t\t\t\t Vector/array type\n";
                    return shouldInstrument;
                }
            }
            else
            {
                // First index means array of structs so
                indexToCheck = 1;
            }
        }

        if (isScalarFieldType)
        {

            // Track subsequent geps which use a scalar field as the pointer operand
            std::queue<Value *> workList;
            std::set<Value *> seenInst;
            workList.push(getElementPtrInst);
            while (!workList.empty())
            {
                auto currValue = workList.front();
                if (seenInst.find(currValue) == seenInst.end())
                {
                    for (auto &use_it : currValue->uses())
                    {
                        if (LoadInst *loadInst = dyn_cast<LoadInst>(use_it.getUser()))
                        {
                            if (loadInst->getType()->isPointerTy())
                                workList.push(loadInst);
                        }
                        else if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(use_it.getUser()))
                        {
                            if (gep->getPointerOperand() == currValue)
                            {
                                workList.push(gep);
                                // errs() << "\t Ignore GEP:" << *gep << "\n";
                                whiteListGEPS.insert(gep);
                            }
                        }
                    }
                }
                workList.pop();
            }

            return shouldInstrument;
        }

        // CMA - Do not check (Very crude check for CMA right now)
        if (isCustomObject(getElementPtrInst->getPointerOperand()))
            return false;
    }

    return shouldInstrument;
}

// Custom memory allocators and ctype functions (the latter being unexpected and more common)
bool BaggyBoundsPointersFunctionPass::isCustomObject(Value *object)
{
    if (isa<GlobalVariable>(object))
        return false;

    Instruction *inst = dyn_cast<Instruction>(object);
    if (!inst)
        return false;
    //    errs() << "\t Checking if custom:" << *object << "\n";
    std::queue<Value *> workList;
    std::set<Value *> seenInst;
    workList.push(inst);
    Value *curr = NULL;
    while (!workList.empty())
    {
        curr = workList.front();
        if (seenInst.find(curr) == seenInst.end())
        {
            if (LoadInst *loadInst = dyn_cast<LoadInst>(curr))
            {
                workList.push(loadInst->getPointerOperand());
                //            errs() << "\t Checking if custom:" << *loadInst << "\n";
            }
            else if (GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(curr))
            {
                workList.push(gepInst->getPointerOperand());
                //            errs() << "\t Checking if custom:" << *gepInst << "\n";
            }
            else if (PHINode *phiNode = dyn_cast<PHINode>(curr))
            {
                //            errs() << "\t Checking if custom:" << *phiNode << "\n";
                for (auto &val : phiNode->incoming_values())
                {
                    workList.push(val.get());
                }
            }
            else if (CallInst *callInst = dyn_cast<CallInst>(curr))
            {
                Function *func = callInst->getCalledFunction();
                //            errs() << "\t Checking if custom:" << *callInst << "\n";
                if (!func)
                    return true;
                if (func->isDeclaration() && func->getName().contains("ctype"))
                    return true;
            }
            seenInst.insert(curr);
        }
        workList.pop();
    }

    return false;
}

GetElementPtrInst *BaggyBoundsPointersFunctionPass::convertGEP(GEPOperator *CE, Instruction *InsertPt)
{

    //
    // Create iterators to the indices of the constant expression.
    //
    std::vector<Value *> Indices;
    for (unsigned index = 1; index < CE->getNumOperands(); ++index)
    {
        Indices.push_back(CE->getOperand(index));
    }

    //
    // Make the new GEP instruction.
    //
    return (GetElementPtrInst::Create(CE->getPointerOperandType()->getPointerElementType(), CE->getPointerOperand(),
                                      Indices,
                                      CE->getName(),
                                      InsertPt));
}

void BaggyBoundsPointersFunctionPass::getAnalysisUsage(AnalysisUsage &AU) const
{
}

char BaggyBoundsPointersFunctionPass::ID = 0;
static RegisterPass<BaggyBoundsPointersFunctionPass>
    X("baggy-pointers",
      "Baggy Bounds Pointer Instrumentation Pass",
      false,
      false);
