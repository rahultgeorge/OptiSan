#include "BaggyBoundsPass.hh"

/* Module pass
 * 1.Adds a new main which initializes baggy bounds  (including stack bottom currently only used to deal with command line args)
 * 2.Saves all globals bounds info
 * 3.Save all heap objects info - replaces malloc,heap etc
 * 4.Replace lib c calls (Needs to be checked)
 */

static cl::opt<bool> ClGlobals(
    "baggy-globals", cl::desc("Save global object bounds"),
    cl::Hidden, cl::init(true));

void BaggyBounds::BaggyBoundsPass::initializeBaggyBoundsAndHandleMain()
{
    Function *originalMain = currentModule->getFunction("main");
    if (!originalMain)
        return;
    // This is supposed to rename and update all uses appropriately
    originalMain->setName("main_original");

    // Create a new main function
    Function *newMain = Function::Create(originalMain->getFunctionType(), originalMain->getLinkage(), "main",
                                         currentModule);

    newMain->copyAttributesFrom(originalMain);

    BasicBlock *entry = BasicBlock::Create(currentModule->getContext(), "entry", newMain);
    IRBuilder<> builder(entry);

    // Create a var which is aligned
    ArrayType *arrayType = ArrayType::get(IntegerType::getInt32Ty(currentModule->getContext()), SLOT_SIZE / 4);

    Value *stackBaseVariable = builder.CreateAlloca(arrayType,
                                                    Constant::getIntegerValue(
                                                        IntegerType::getInt32Ty(
                                                            currentModule->getContext()),
                                                        APInt(32, SLOT_SIZE / 4)),
                                                    "stackBaseVariable");

    Value *stackBottomValue = builder.CreateBitCast(stackBaseVariable, Type::getInt32PtrTy(currentModule->getContext()),
                                                    "stackBaseAddress");

    // Set stack bottom
    Value *baggyStackBottomCallee = (currentModule->getOrInsertFunction("baggy_set_stack_bottom",
                                                                        Type::
                                                                            getVoidTy(
                                                                                currentModule->getContext()), // return type
                                                                        Type::getInt32PtrTy(
                                                                            currentModule->getContext()))
                                         .getCallee());

    builder.CreateCall(dyn_cast<Function>(baggyStackBottomCallee),
                       *(new ArrayRef<Value *>(stackBottomValue)));

    // Call the actual main with args if any
    std::vector<Value *> originalMainFormalArgs;
    // Send whatever arguments received
    for (Function::arg_iterator formalNewMainArg = newMain->arg_begin();
         formalNewMainArg != newMain->arg_end(); ++formalNewMainArg)
    {

        originalMainFormalArgs.push_back(&(*formalNewMainArg));
    }

    Value *originalMainRetValue = builder.CreateCall(dyn_cast<Function>(originalMain)->getFunctionType(),
                                                     originalMain, originalMainFormalArgs);

    // end the basic block with a ret statement
    builder.CreateRet(originalMainRetValue);

    MDNode *MD = MDNode::get(newMain->getContext(), {});
    newMain->setMetadata(BAGGY_SKIP_FUNCTION, MD);

    // Create baggy ctor which does one thing - call baggy init
    Function *baggyCtor = dyn_cast<Function>(currentModule->getOrInsertFunction(BAGGY_CTOR_NAME,
                                                                                Type::getVoidTy(
                                                                                    currentModule->getContext()),
                                                                                NULL)
                                                 .getCallee());
    baggyCtor->addFnAttr(Attribute::NoUnwind);
    if (baggyCtor->empty())
    {

        BasicBlock *entry = BasicBlock::Create(currentModule->getContext(), "entry", baggyCtor);
        IRBuilder<> IRB(entry);
        Function *baggyInit = dyn_cast<Function>(currentModule->getOrInsertFunction("baggy_init",
                                                                                    Type::
                                                                                        getVoidTy(
                                                                                            currentModule->getContext()),
                                                                                    NULL)
                                                     .getCallee());

        IRB.CreateCall(dyn_cast<Function>(baggyInit), None);

        IRB.CreateRetVoid();
        appendToUsed(*currentModule, {baggyCtor});
        appendToGlobalCtors(*currentModule, baggyCtor, 101);
    }
}

void BaggyBounds::BaggyBoundsPass::replaceAllLibraryCalls()
{
    Function *StrCpy = currentModule->getFunction("strcpy");
    if (StrCpy != NULL)
    {
        Value *BaggyStrCpy = currentModule->getOrInsertFunction("baggy_strcpy",
                                                                StrCpy->getFunctionType())
                                 .getCallee();
        StrCpy->replaceAllUsesWith(BaggyStrCpy);
    }

    Function *StrCat = currentModule->getFunction("strcat");
    if (StrCat != NULL)
    {
        Value *BaggyStrCat = currentModule->getOrInsertFunction("baggy_strcat",
                                                                StrCat->getFunctionType())
                                 .getCallee();
        StrCat->replaceAllUsesWith(BaggyStrCat);
    }

    Function *Sprintf = currentModule->getFunction("sprintf");
    if (Sprintf != NULL)
    {
        Value *BaggySprintf = currentModule->getOrInsertFunction("baggy_sprintf",
                                                                 Sprintf->getFunctionType())
                                  .getCallee();
        Sprintf->replaceAllUsesWith(BaggySprintf);
    }

    Function *Snprintf = currentModule->getFunction("snprintf");
    if (Snprintf != NULL)
    {
        Value *BaggySnprintf = currentModule->getOrInsertFunction("baggy_snprintf",
                                                                  Snprintf->getFunctionType())
                                   .getCallee();
        Snprintf->replaceAllUsesWith(BaggySnprintf);
    }
}

void BaggyBounds::BaggyBoundsPass::replaceAllHeapAllocationFunctionCalls()
{
    // Replace all heap related functions like malloc, free, calloc and realloc
    Function *mallocFunc = currentModule->getFunction("malloc");
    if (mallocFunc != NULL)
    {
        Value *baggyMalloc = currentModule->getOrInsertFunction("baggy_malloc",
                                                                mallocFunc->getFunctionType())
                                 .getCallee();
        mallocFunc->replaceAllUsesWith(baggyMalloc);
    }

    Function *freeFunc = currentModule->getFunction("free");
    if (freeFunc != NULL)
    {
        Value *baggyFree = currentModule->getOrInsertFunction("baggy_free",
                                                              freeFunc->getFunctionType())
                               .getCallee();
        freeFunc->replaceAllUsesWith(baggyFree);
    }

    Function *callocFunc = currentModule->getFunction("calloc");
    if (callocFunc != NULL)
    {
        Value *baggyCalloc = currentModule->getOrInsertFunction("baggy_calloc",
                                                                callocFunc->getFunctionType())
                                 .getCallee();
        callocFunc->replaceAllUsesWith(baggyCalloc);
    }

    Function *reallocFunc = currentModule->getFunction("realloc");
    if (reallocFunc != NULL)
    {
        Value *baggyRealloc = currentModule->getOrInsertFunction("baggy_realloc",
                                                                 reallocFunc->getFunctionType())
                                  .getCallee();
        reallocFunc->replaceAllUsesWith(baggyRealloc);
    }

    // Ad hoc way of dealing with new operator, new [] operator (which does not always translate to malloc)
    //  A mature implementation of baggy should leverage interception like ASAN
    //  https://github.com/seahorn/llvm-dsa/blob/master/lib/DSA/AllocatorIdentification.cpp
    Function *newOperator1 = currentModule->getFunction("_Znwm");
    if (newOperator1 != NULL)
    {
        Value *baggyMalloc = currentModule->getOrInsertFunction("baggy_malloc",
                                                                newOperator1->getFunctionType())
                                 .getCallee();
        newOperator1->replaceAllUsesWith(baggyMalloc);
    }

    Function *newOperator2 = currentModule->getFunction("_Znam");
    if (newOperator2 != NULL)
    {
        Value *baggyMalloc = currentModule->getOrInsertFunction("baggy_malloc",
                                                                newOperator2->getFunctionType())
                                 .getCallee();
        newOperator2->replaceAllUsesWith(baggyMalloc);
    }

    Function *freeOperator1 = currentModule->getFunction("_ZdlPv");
    if (freeOperator1 != NULL)
    {
        Value *baggyFree = currentModule->getOrInsertFunction("baggy_free",
                                                              freeOperator1->getFunctionType())
                               .getCallee();
        freeOperator1->replaceAllUsesWith(baggyFree);
    }

    Function *freeOperator2 = currentModule->getFunction("_ZdaPv");
    if (freeOperator2 != NULL)
    {
        Value *baggyFree = currentModule->getOrInsertFunction("baggy_free",
                                                              freeOperator2->getFunctionType())
                               .getCallee();
        freeOperator2->replaceAllUsesWith(baggyFree);
    }
}

void BaggyBounds::BaggyBoundsPass::saveGlobalObjectsBounds()
{

    GlobalVariable *globalVariable = NULL;
    bool areThereGlobalObjectsWhoseBoundsNeedToBeSaved = false;

    for (Module::global_iterator iter = currentModule->global_begin();
         iter != currentModule->global_end(); ++iter)
    {
        globalVariable = &*iter;

        if (globalVariable->hasInitializer())
        {
            // TODO- Add a better check
            if (iter->hasName() && (iter->getName().contains("llvm") || iter->getName().contains("gcov")))
                continue;
            areThereGlobalObjectsWhoseBoundsNeedToBeSaved = true;
            break;
        }
    }

    if (!areThereGlobalObjectsWhoseBoundsNeedToBeSaved)
        return;

    Function *baggyGlobalsCtor = dyn_cast<Function>(currentModule->getOrInsertFunction(BAGGY_GLOBALS_CTOR_NAME,
                                                                                       Type::getVoidTy(
                                                                                           currentModule->getContext()),
                                                                                       NULL)
                                                        .getCallee());
    baggyGlobalsCtor->setLinkage(GlobalValue::InternalLinkage);
    // Check why is this done
    baggyGlobalsCtor->addFnAttr(Attribute::NoUnwind);
    BasicBlock *CtorBB = BasicBlock::Create(currentModule->getContext(), "", baggyGlobalsCtor);
    ReturnInst::Create(currentModule->getContext(), CtorBB);
    //    // Ensure Ctor cannot be discarded, even if in a comdat. (NS - How this works)
    appendToUsed(*currentModule, {baggyGlobalsCtor});

    // Create baggy globals ctor which  saves global objects bounds
    if (baggyGlobalsCtor)
    {
        BasicBlock *entry = BasicBlock::Create(currentModule->getContext(), "entry", baggyGlobalsCtor);
        IRBuilder<> IRB(entry);
        Function *baggyInit = dyn_cast<Function>(currentModule->getOrInsertFunction("baggy_init",
                                                                                    Type::
                                                                                        getVoidTy(
                                                                                            currentModule->getContext()),
                                                                                    NULL)
                                                     .getCallee());

        IRB.CreateCall(dyn_cast<Function>(baggyInit), None);

        // IRBuilder<> IRB(baggyGlobalsCtor->getEntryBlock().getTerminator());

        //  Loop through global variables
        for (Module::global_iterator iter = currentModule->global_begin();
             iter != currentModule->global_end(); ++iter)
        {
            globalVariable = &*iter;

            if (globalVariable->hasInitializer())
            {
                // TODO- Add a better check
                if (iter->hasName() && (iter->getName().contains("llvm") || iter->getName().contains("gcov")))
                    continue;
                unsigned int allocation_size = DL->getTypeAllocSize(globalVariable->getValueType());
                // Set the alignment on the global variable
                unsigned int real_allocation_size = get_alignment(allocation_size);
                iter->setAlignment(MaybeAlign(max(iter->getAlignment(), real_allocation_size)));

                // Add an instruction to update the size_table with the global variable's size
                Constant *location = ConstantExpr::getCast(Instruction::PtrToInt, dyn_cast<Constant>(iter),
                                                           IntegerType::get(currentModule->getContext(), 64));
                IRB.Insert(get_save_in_table_instr(*currentModule, location, real_allocation_size));
            }
        }
        IRB.CreateRetVoid();

        appendToGlobalCtors(*currentModule, baggyGlobalsCtor, 102);
    }
}

void BaggyBounds::BaggyBoundsPass::getAnalysisUsage(AnalysisUsage &AU)
{
}

bool BaggyBounds::BaggyBoundsPass::runOnModule(Module &m)
{
    DL = const_cast<DataLayout *>(&(m.getDataLayout()));
    currentModule = &m;

    initializeBaggyBoundsAndHandleMain();

    if (ClGlobals)
        saveGlobalObjectsBounds();

    if (!HEAP_PROTECTION_OFF)
    {
        // TODO - Check if these wrappers are correct
        //        replaceAllLibraryCalls();
        replaceAllHeapAllocationFunctionCalls();
    }

    return true;
}

char BaggyBounds::BaggyBoundsPass::ID = 0;
static RegisterPass<BaggyBounds::BaggyBoundsPass>
    X("baggy-bounds", "Baggy Bounds initialization pass",
      false /* Only looks at CFG */,
      false /* Analysis Pass */);
