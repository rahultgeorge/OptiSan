#include "EstimationPass.hh"

/*
 * Simple heuristic
 * Monitor instruments, we identify points of interest and check for instrumentation
 * This checking for instrumentation is not as robust as we would like
 * We do the same like Candea "string based"
 */

// TODO - Look at inst visitor
void CostEstimationFunctionPass::processFunction()
{
    /* DISubprogram *subprogram = funcBeingAnalyzed->getSubprogram();
    std::string currFuncName = "";
    if (subprogram)
    {
        currFuncName = subprogram->getFilename().str();
        errs() << "func name:" << currFuncName << "\n";
    } */
    for (auto bb_it = funcBeingAnalyzed->begin(); bb_it != funcBeingAnalyzed->end(); bb_it++)
    {
        for (auto inst_it = bb_it->begin(); inst_it != bb_it->end(); inst_it++)
        {

            /* Instruction *instruction = dyn_cast<Instruction>(inst_it);
            DILocation *loc = instruction->getDebugLoc();
            if (loc)
            {
                auto funcName = loc->getFilename();
                if (currFuncName.compare(funcName))
                    errs() << " May be inlined:" << currFuncName << " " << funcName << "\n";

                auto inlinedDILoc = loc->getInlinedAt();
                if (inlinedDILoc)
                    errs() << "\t" << *inlinedDILoc << "\n";
            } */

            if (CallInst *callInst = dyn_cast<CallInst>(inst_it))
            {
                if (callInst->getCalledFunction())
                {
                    callInstructions.insert(callInst);
                }
            }
            else if (AllocaInst *allocaInst = dyn_cast<AllocaInst>(inst_it))
            {
                stackObjectAllocationsThroughAlloca.insert(allocaInst);
            }
            // For now ignoring add and sub with respect ptr cast to int
            else if (GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(inst_it))
            {
                pointerManipulationInstructions.insert(gepInst);
            }
            // Memory dereferences
            else if (LoadInst *loadInst = dyn_cast<LoadInst>(inst_it))
            {
                memoryDereferences.insert(loadInst);
            }
            else if (StoreInst *storeInst = dyn_cast<StoreInst>(inst_it))
            {
                memoryDereferences.insert(storeInst);
            }
        }
    }
}

/**
 * This is a simpler algo but ends up overapproximating frequency (loops)
 * This is because we try to find the memory references/GEPS purely based on CFG match so there are c
 */
void CostEstimationFunctionPass::findMonitoredMemoryInstructions()
{
    BasicBlock *monitoredInstructionBasicBlock = NULL;
    BasicBlock *checkBasicBlock = NULL;
    BranchInst *terminatorInst;
    std::set<BasicBlock *> basicBlocksSeen;
    if (CURRENT_MONITOR == MonitorType::ASAN)
    {
        // The sibling basic block should contain a sanity call
        for (auto &inst : memoryDereferences)
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
                if (!terminatorInst || (!terminatorInst->isConditional()))
                    continue;
                // errs() << "Terminator:" << *terminatorInst << "\n";
                for (uint32_t i = 0; i < terminatorInst->getNumSuccessors(); i++)
                {
                    if (findSanityCheckCall(terminatorInst->getSuccessor(i)) != NULL &&
                        terminatorInst->getSuccessor(i) != monitoredInstructionBasicBlock)
                    {
                        // We know that is monitored
                        monitoredMemoryOperations.insert(inst);
                        // errs() << "Monitored BB:" << *monitoredInstructionBasicBlock << "\n";
                        break;
                    }
                }
            }
            basicBlocksSeen.insert(monitoredInstructionBasicBlock);
        }
    }

    // Baggy bounds- Similar approach (except check struct is different )
    else if (CURRENT_MONITOR == MonitorType::BaggyBounds)
    {
        // The basic block
        for (auto &inst : pointerManipulationInstructions)
        {
            monitoredInstructionBasicBlock = inst->getParent();
            if (basicBlocksSeen.find(monitoredInstructionBasicBlock) != basicBlocksSeen.end())
                continue;
            for (auto succ_it = succ_begin(monitoredInstructionBasicBlock);
                 succ_it != succ_end(monitoredInstructionBasicBlock); succ_it++)
            {
                checkBasicBlock = *succ_it;
                //                errs() << "\t\t" << *checkBasicBlock << "\n\n";
                for (auto inst_it = checkBasicBlock->begin(); inst_it != checkBasicBlock->end(); inst_it++)
                {
                    if (CallInst *callInst = dyn_cast<CallInst>(inst_it))
                    {
                        if (callInst->getCalledFunction())
                        {
                            if (callInst->getCalledFunction()->getName().contains("baggy_slowpath"))
                            // We know that it is monitored
                            {
                                // errs() << "Monitored BB:" << *monitoredInstructionBasicBlock << "\n";
                                monitoredMemoryOperations.insert(inst);
                                break;
                            }
                        }
                    }
                }
            }

            basicBlocksSeen.insert(monitoredInstructionBasicBlock);
        }
    }

    else if (CURRENT_MONITOR == MonitorType::BaggyBoundsASAN)
    {

        // ASAN
        for (auto &inst : memoryDereferences)
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
                if (!terminatorInst || (!terminatorInst->isConditional()))
                    continue;
                // errs() << "Terminator:" << *terminatorInst << "\n";
                for (uint32_t i = 0; i < terminatorInst->getNumSuccessors(); i++)
                {
                    if (findSanityCheckCall(terminatorInst->getSuccessor(i), MonitorType::ASAN) != NULL &&
                        terminatorInst->getSuccessor(i) != monitoredInstructionBasicBlock)
                    {
                        // We know that is monitored
                        monitoredMemoryOperations.insert(inst);
                        break;
                    }
                }
            }
            basicBlocksSeen.insert(monitoredInstructionBasicBlock);
        }

        basicBlocksSeen.clear();

        // The basic block
        for (auto &inst : pointerManipulationInstructions)
        {
            monitoredInstructionBasicBlock = inst->getParent();
            if (basicBlocksSeen.find(monitoredInstructionBasicBlock) != basicBlocksSeen.end())
                continue;
            for (auto succ_it = succ_begin(monitoredInstructionBasicBlock);
                 succ_it != succ_end(monitoredInstructionBasicBlock); succ_it++)
            {
                checkBasicBlock = *succ_it;
                //                errs() << "\t\t" << *checkBasicBlock << "\n\n";
                for (auto inst_it = checkBasicBlock->begin(); inst_it != checkBasicBlock->end(); inst_it++)
                {
                    if (CallInst *callInst = dyn_cast<CallInst>(inst_it))
                    {
                        if (callInst->getCalledFunction())
                        {
                            if (callInst->getCalledFunction()->getName().contains("baggy_slowpath"))
                            // We know that it is monitored
                            {
                                // errs() << "Monitored BB:" << *monitoredInstructionBasicBlock << "\n";
                                monitoredMemoryOperations.insert(inst);
                                break;
                            }
                        }
                    }
                }
            }

            basicBlocksSeen.insert(monitoredInstructionBasicBlock);
        }
    }
}

bool CostEstimationFunctionPass::runOnFunction(Function &F)
{

    // errs() << "Pre processing function:" << F.getName().str() << "\n";
    funcBeingAnalyzed = &F;

    InstructionsBySanityCheck.clear();
    monitorOperationTypeToInstruction.clear();
    monitoredMemoryOperations.clear();
    stackObjectAllocationsThroughAlloca.clear();
    callInstructions.clear();
    memoryDereferences.clear();
    pointerManipulationInstructions.clear();
    processFunction();

    monitoredMemoryOperations.clear();
    SanityCheckBlocks[&F] = BlockSet();
    SanityCheckInstructions[&F] = InstructionSet();
    SCBranches[&F] = InstructionVec();
    UCBranches[&F] = InstructionVec();

    return false;
}

void CostEstimationFunctionPass::findInstructions()
{

    Function *F = funcBeingAnalyzed;
    // A list of instructions that are used by sanity checks. They become sanity
    // check instructions if it turns out they're not used by anything else.
    std::set<Instruction *> Worklist;

    // A list of basic blocks that contain sanity check instructions. They
    // become sanity check blocks if it turns out they don't contain anything
    // else.
    std::set<BasicBlock *> BlockWorklist;

    for (BasicBlock &BB : *F)
    {

        if (findSanityCheckCall(&BB))
        {
            SanityCheckBlocks[F].insert(&BB);

            // All instructions inside sanity check blocks are sanity check instructions
            for (Instruction &I : BB)
            {
                Worklist.insert(&I);
            }

            // All branches to sanity check blocks are sanity check branches
            for (User *U : BB.users())
            {
                if (Instruction *Inst = dyn_cast<Instruction>(U))
                {
                    Worklist.insert(Inst);
                }
                BranchInst *BI = dyn_cast<BranchInst>(U);
                if (BI && BI->isConditional())
                {
                    SCBranches[F].push_back(BI);
                    monitoredMemoryOperations.insert(BI);
                    // fprintf(ff, "%s ", F->getName());
                    // for (Instruction &I: *BI->getParent()){
                    //     fprintf(ff, ":%s",I.getOpcodeName());
                    // }
                    // fprintf(ff, "\n");
                    UCBranches[F].remove(dyn_cast<Instruction>(U));
                    ChecksByInstruction[BI].insert(BI);
                }
            }
        }
    }

    while (!Worklist.empty())
    {
        // Alternate between emptying the worklist...
        while (!Worklist.empty())
        {
            Instruction *Inst = *Worklist.begin();
            Worklist.erase(Inst);
            if (onlyUsedInSanityChecks(Inst))
            {
                if (SanityCheckInstructions[F].insert(Inst).second)
                {
                    UCBranches[F].remove(Inst);
                    for (Use &U : Inst->operands())
                    {
                        if (Instruction *Op = dyn_cast<Instruction>(U.get()))
                        {
                            Worklist.insert(Op);

                            // Copy ChecksByInstruction from Inst to Op
                            auto CBI = ChecksByInstruction.find(Inst);
                            if (CBI != ChecksByInstruction.end())
                            {
                                ChecksByInstruction[Op].insert(CBI->second.begin(), CBI->second.end());
                            }
                        }
                    }

                    BlockWorklist.insert(Inst->getParent());

                    // Fill InstructionsBySanityCheck from the inverse ChecksByInstruction
                    auto CBI = ChecksByInstruction.find(Inst);
                    if (CBI != ChecksByInstruction.end())
                    {
                        for (Instruction *CI : CBI->second)
                        {
                            InstructionsBySanityCheck[CI].insert(Inst);
                        }
                    }
                }
            }
        }

        // ... and checking whether this causes basic blocks to contain only
        // sanity checks. This would in turn cause terminators to be added to
        // the worklist.
        while (!BlockWorklist.empty())
        {
            BasicBlock *BB = *BlockWorklist.begin();
            BlockWorklist.erase(BB);

            bool allInstructionsAreSanityChecks = true;
            for (Instruction &I : *BB)
            {
                if (!SanityCheckInstructions.at(BB->getParent()).count(&I))
                {
                    allInstructionsAreSanityChecks = false;
                    break;
                }
            }

            if (allInstructionsAreSanityChecks)
            {
                for (User *U : BB->users())
                {
                    if (Instruction *Inst = dyn_cast<Instruction>(U))
                    {
                        Worklist.insert(Inst);
                        BranchInst *BI = dyn_cast<BranchInst>(Inst);
                        if (BI && BI->isConditional())
                        {
                            for (Instruction &I : *BB)
                            {
                                auto CBI = ChecksByInstruction.find(&I);
                                if (CBI != ChecksByInstruction.end() &&
                                    ChecksByInstruction.find(BI) == ChecksByInstruction.end())
                                {
                                    ChecksByInstruction[BI].insert(CBI->second.begin(), CBI->second.end());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

const CallInst *CostEstimationFunctionPass::findSanityCheckCall(BasicBlock *BB, MonitorType monitorType) const
{
    for (const Instruction &I : *BB)
    {
        if (const CallInst *CI = dyn_cast<CallInst>(&I))
        {
            if (isAbortingCall(CI, monitorType))
            {
                return CI;
            }
        }
    }
    return 0;
}

bool CostEstimationFunctionPass::onlyUsedInSanityChecks(Value *V)
{
    for (User *U : V->users())
    {
        Instruction *Inst = dyn_cast<Instruction>(U);
        if (!Inst)
            return false;

        Function *F = Inst->getParent()->getParent();
        if (!(SanityCheckInstructions[F].count(Inst)))
        {
            return false;
        }
    }
    return true;
}

void CostEstimationFunctionPass::getAnalysisUsage(AnalysisUsage &AU) const { AU.setPreservesAll(); }

char CostEstimationFunctionPass::ID = 0;
static RegisterPass<CostEstimationFunctionPass>
    Y("fcost", "Cost estimation function pass", false, true);
