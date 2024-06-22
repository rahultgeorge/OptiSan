
#include "SanitizerHelperPass.hh"

/**
 * @brief
 * Key points about placement
 * 1. Heap obviously off
 *     Baggy would actually uses
 *     ASAN uses interception by replacing the hooks
 *          Also
 * 2. Stack object metadata (taken care of by the respective sanitizer passes)
 *
 * 3. Removing checks
 */

using namespace asan_minus;

inline void PostSanitizationHelperPass::isAbortingCall(CallInst *callInstruction)
{
    if (callInstruction->getCalledFunction())
    {
        StringRef name = callInstruction->getCalledFunction()->getName();
        if ((name.startswith("__asan_report_")))
        {
            abortingCalls[MonitorType::ASAN].insert(callInstruction);
        }
        else if (name.contains("baggy_slowpath"))
        {
            abortingCalls[MonitorType::BaggyBounds].insert(callInstruction);
        }
    }
}

inline uint64_t getAllocaSizeInBytes(const AllocaInst &AI)
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

void PostSanitizationHelperPass::findSanityCheckCallAndTurnOffCheck(BranchInst *BI, MonitorType monitorType)
{
    // assert(BI->isConditional());
    if ((monitorType == ASAN) && (BI->hasMetadata(ASAN_MONITORING_POINT)))
        return;
    if ((monitorType == BaggyBounds) && (BI->hasMetadata(BAGGY_MONITORING_POINT)))
        return;

    bool foundAbortingCall = false;
    for (unsigned int succ_no = 0; succ_no < BI->getNumSuccessors(); succ_no++)
    {
        for (const Instruction &I : *BI->getSuccessor(succ_no))
        {
            if (const CallInst *CI = dyn_cast<CallInst>(&I))
            {
                if (CI->getCalledFunction())
                {
                    StringRef name = CI->getCalledFunction()->getName();
                    if ((monitorType == ASAN) && (name.startswith("__asan_report_")))
                    {
                        foundAbortingCall = true;
                        break;
                    }
                    else if ((monitorType == BaggyBounds) && name.contains("baggy_slowpath"))
                    {
                        foundAbortingCall = true;
                        break;
                    }
                }
            }
        }
        if (foundAbortingCall)
        {
            if (succ_no == 0)
                BI->setCondition(ConstantInt::getFalse(BI->getContext()));
            else
                BI->setCondition(ConstantInt::getTrue(BI->getContext()));
            // errs() << "\t Turning off BI:" << *BI << ":" << BI->getFunction()->getName() << "\n";
            break;
        }
    }
    return;
}

void PostSanitizationHelperPass::findSanityCheckCallAndTurnOnCheck(BranchInst *BI, MonitorType monitorType)
{
    // assert(BI->isConditional());
    bool foundAbortingCall = false;
    for (unsigned int succ_no = 0; succ_no < BI->getNumSuccessors(); succ_no++)
    {
        for (const Instruction &I : *BI->getSuccessor(succ_no))
        {
            if (const CallInst *CI = dyn_cast<CallInst>(&I))
            {
                if (CI->getCalledFunction())
                {
                    StringRef name = CI->getCalledFunction()->getName();
                    if ((monitorType == ASAN) && (name.startswith("__asan_report_")))
                    {
                        foundAbortingCall = true;
                        break;
                    }
                    else if ((monitorType == BaggyBounds) && name.contains("baggy_slowpath"))
                    {
                        foundAbortingCall = true;
                        break;
                    }
                }
            }
        }
        if (foundAbortingCall)
        {
            MDNode *MD = MDNode::get(_module->getContext(), {});
            if (monitorType == ASAN)
                BI->setMetadata(ASAN_MONITORING_POINT, MD);
            else if (monitorType == BaggyBounds)
                BI->setMetadata(BAGGY_MONITORING_POINT, MD);
            break;
        }
    }
    return;
}

void PostSanitizationHelperPass::analyzeFunctionsAndFindChecks()
{
    std::string instructionString;
    std::string indexString;
    Instruction *inst;
    raw_string_ostream rso(instructionString);
    uint32_t functionsFound = 0;
    for (auto &func : _module->functions())
    {
        if (func.empty() || func.isIntrinsic() || func.isDeclaration())
            continue;
        if (func.hasMetadata(BAGGY_SKIP_FUNCTION) && func.hasFnAttribute(ASAN_SKIP_FUNCTION))
            continue;
        functionsFound++;
        for (auto bb_iter = func.begin(); bb_iter != func.end(); bb_iter++)
        {
            for (auto inst_it = bb_iter->begin(); inst_it != bb_iter->end(); inst_it++)
            {
                inst = &*inst_it;
                if (inst->hasMetadata(ASAN_MONITORING_POINT))
                {
                    monitoringPointToMonitorType[inst] = ASAN;
                    unsafeFunctionsMonitored.insert(inst->getFunction());
                }

                else if (inst->hasMetadata(BAGGY_MONITORING_POINT))
                {
                    monitoringPointToMonitorType[inst] = BaggyBounds;
                    unsafeFunctionsMonitored.insert(inst->getFunction());
                }
                if (CallInst *callInst = dyn_cast<CallInst>(inst))
                {
                    isAbortingCall(callInst);
                }

                // if (isa<LoadInst>(inst))
                //     memoryDereferenceInstructions.insert(inst);
                // else if (isa<StoreInst>(inst))
                //     memoryDereferenceInstructions.insert(inst);
                // else if (isa<GetElementPtrInst>(inst))
                //     gepInstructions.insert(inst);
            }
        }
    }
    // errs() << "# functions found:" << functionsFound << "\n";
}

/*
 *   ASAN check structure
 *                          A (First check)
 *                        /   \
 *        B(Second check)      \
 *         |             \      \
 *     D (asan_report)   C (Mem instruction block)
 *
 */
void PostSanitizationHelperPass::placeChecksAsRequired()
{
    BasicBlock *monitoredInstructionBasicBlock = nullptr;
    BasicBlock *checkBasicBlock = nullptr;
    BranchInst *terminatorInst = nullptr;
    // Deal with loops
    std::set<BasicBlock *> basicBlocksSeen;

    if (!monitoringPointToMonitorType.empty())
    {
        errs() << "# operations to monitor:" << monitoringPointToMonitorType.size() << "\n";
    }

    // Identify the desired checks of required monitor types as is
    for (auto const &operationToMonitorTuple : monitoringPointToMonitorType)
    {
        monitoredInstructionBasicBlock = operationToMonitorTuple.first->getParent();
        if (operationToMonitorTuple.second == ASAN)
        {
            // This handles the N byte check (N<8) (two predecessors)
            for (auto pred_it = pred_begin(monitoredInstructionBasicBlock);
                 pred_it != pred_end(monitoredInstructionBasicBlock); pred_it++)
            {
                checkBasicBlock = *pred_it;
                terminatorInst = dyn_cast<BranchInst>(checkBasicBlock->getTerminator());
                if (!terminatorInst || !terminatorInst->isConditional())
                {
                    // errs() << "\t Failed to find check corresponding to annotated unsafe operation:" << *operationToMonitorTuple.first << "\n";
                    continue;
                }
                findSanityCheckCallAndTurnOnCheck(terminatorInst, ASAN);
            }
        }

        else if (operationToMonitorTuple.second == BaggyBounds)
        {
            terminatorInst = dyn_cast<BranchInst>(
                monitoredInstructionBasicBlock->getTerminator());
            if (!terminatorInst || !terminatorInst->isConditional())
                continue;
            findSanityCheckCallAndTurnOnCheck(terminatorInst, BaggyBounds);
        }
    }

    // Turn off the unnecessary checks (Using metadata)
    for (auto current_monitor : monitors)
    {
        for (auto &inst : abortingCalls[current_monitor])
        {
            monitoredInstructionBasicBlock = inst->getParent();

            if (basicBlocksSeen.find(monitoredInstructionBasicBlock) != basicBlocksSeen.end())
                continue;

            // This handles the N byte check (N<8) (two predecessors)
            for (auto pred_it = pred_begin(monitoredInstructionBasicBlock);
                 pred_it != pred_end(monitoredInstructionBasicBlock); pred_it++)
            {
                checkBasicBlock = *pred_it;
                terminatorInst = dyn_cast<BranchInst>(checkBasicBlock->getTerminator());
                if (!terminatorInst)
                    continue;
                //                    errs() << "Potential ASAN Terminator:" << *terminatorInst << "\n";
                findSanityCheckCallAndTurnOffCheck(terminatorInst, current_monitor);
            }

            basicBlocksSeen.insert(monitoredInstructionBasicBlock);
        }

        basicBlocksSeen.clear();
    }

    //     Clean up code (Enable this once we're sure everything is correct for all programs)
    // for (auto const &operationToMonitorTuple: monitoringPointToMonitorType) {
    //     if (operationToMonitorTuple.first->hasMetadata(ASAN_MONITORING_POINT))
    //         operationToMonitorTuple.first->setMetadata(ASAN_MONITORING_POINT, NULL);
    //     else if (operationToMonitorTuple.first->hasMetadata(BAGGY_MONITORING_POINT))
    //         operationToMonitorTuple.first->setMetadata(BAGGY_MONITORING_POINT, NULL);
    // }
}

bool PostSanitizationHelperPass::turnOffHeapMetadata()
{
    // Step 1  - Turn off heap baggy protection (Baggy metadata)
    Function *baggyMallocFunc = _module->getFunction("baggy_malloc");
    if (baggyMallocFunc != NULL)
    {
        Value *mallocFunc = _module->getOrInsertFunction("malloc",
                                                         baggyMallocFunc->getFunctionType())
                                .getCallee();
        baggyMallocFunc->replaceAllUsesWith(mallocFunc);
    }

    Function *baggyFreeFunc = _module->getFunction("baggy_free");
    if (baggyFreeFunc != NULL)
    {
        Value *freeFunc = _module->getOrInsertFunction("free",
                                                       baggyFreeFunc->getFunctionType())
                              .getCallee();
        baggyFreeFunc->replaceAllUsesWith(freeFunc);
    }

    Function *baggyCallocFunc = _module->getFunction("baggy_calloc");
    if (baggyCallocFunc != NULL)
    {
        Value *callocFunc = _module->getOrInsertFunction("calloc",
                                                         baggyCallocFunc->getFunctionType())
                                .getCallee();
        baggyCallocFunc->replaceAllUsesWith(callocFunc);
    }

    Function *baggyRealloc = _module->getFunction("baggy_realloc");
    if (baggyRealloc != NULL)
    {
        Value *reallocFunc = _module->getOrInsertFunction("realloc",
                                                          baggyRealloc->getFunctionType())
                                 .getCallee();
        baggyRealloc->replaceAllUsesWith(reallocFunc);
    }

    return true;
}

/**
 *
 * @param M
 * @return
 */
bool PostSanitizationHelperPass::runOnModule(Module &M)
{
    _module = &M;

    if (TEST_MODE)
        return false;

    turnOffHeapMetadata();

    // Step 1 - Fetch the unsafe operations we want to monitor (annotated by previous pass)
    analyzeFunctionsAndFindChecks();

    // Step 2 - Remove unnecessary checks while leaving desired checks
    placeChecksAsRequired();

#ifdef OPTIMIZATION_PIPELINE_MODE

    for (auto &func : M.functions())
    {

        // if (func.isDeclaration() || func.isIntrinsic() || func.empty())
        //     continue;
        if (func.hasFnAttribute(Attribute::OptimizeNone))
            func.removeFnAttr(Attribute::OptimizeNone);
        if (func.hasFnAttribute(Attribute::NoInline))
            func.removeFnAttr(Attribute::NoInline);
        // if (unsafeFunctionsMonitored.find(&func) == unsafeFunctionsMonitored.end())
        // {
        //     if (func.hasFnAttribute(Attribute::NoInline))
        //         func.removeFnAttr(Attribute::NoInline);
        // }
    }

#endif

    return true;
}

void PostSanitizationHelperPass::getAnalysisUsage(AnalysisUsage &AU) const
{
}

char PostSanitizationHelperPass::ID = 0;

static RegisterPass<PostSanitizationHelperPass>
    X("post-sanitize", "Refine sanitization as computed", false, false);
