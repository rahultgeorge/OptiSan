#include "IntraTargetAnalysisPass.hh"

using namespace llvm;

void IntraTargetAnalysisPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const
{
    AU.addRequired<PostDominatorTreeWrapperPass>();
    AU.setPreservesAll();
}

void IntraTargetAnalysisPass::identifyStackDataConservatively()
{

    if (currentFunc->hasOptNone())
    {
        for (auto &arg_it : currentFunc->args())
        {
            for (auto user_it : arg_it.users())
            {
                if (StoreInst *storeInst = dyn_cast<StoreInst>(user_it))
                {
                    if (AllocaInst *allocaInst = dyn_cast<AllocaInst>(storeInst->getPointerOperand()))
                        allStackObjects.insert(allocaInst);
                }
            }
        }
    }

    for (inst_iterator inst_it = inst_begin(currentFunc), E = inst_end(currentFunc); inst_it != E; ++inst_it)
    {
        if (AllocaInst *allocaInst = dyn_cast<AllocaInst>(&*inst_it))
        {
            allStackObjects.insert(allocaInst);
        }
    }
    // errs() << "\t\t\t Stack objects found:" << allStackObjects.size() << "\n";
    _cfg->setAllTargets(allStackObjects);
    // Include args overapproximating (irrespective of calling convention)
}

void IntraTargetAnalysisPass::computeKills()
{
    // TODO - make this more robust i.e intra proc dfa (?)

    for (auto stackObj : allStackObjects)
    {
        // errs() << "Obj:" << *stackObj << "\n";
        InstructionSet killUses;
        for (auto user_it : stackObj->users())
        {
            if (StoreInst *storeInst = dyn_cast<StoreInst>(user_it))
            {
                if (storeInst->getPointerOperand() == stackObj)
                {
                    // errs() << "\t KILL:" << *storeInst << "\n";
                    killUses.insert(storeInst);
                }
            }
        }
        stackObjectsToKills[stackObj] = killUses;
        if (!killUses.empty())
            _cfg->setKills(stackObj, killUses);
    }
}

bool IntraTargetAnalysisPass::runOnFunction(llvm::Function &F)
{
    currentFunc = &F;
    if (functionGraphCache.find(currentFunc) == functionGraphCache.end())
    {
        // errs() << "\t\t Identifying stack data and computing cfg:" << currentFunc->getName() << "\n";
        _PDT = &getAnalysis<PostDominatorTreeWrapperPass>(F).getPostDomTree();
        _cfg = new ReachabilityGraph();
        allStackObjects.clear();
        stackObjectsToKills.clear();
        computeCFG(&F);
        identifyStackDataConservatively();
        pdg::ProgramGraph &pdg = pdg::ProgramGraph::getInstance();
        if (pdg.isBuild())
        {
            collectMayAliasUses();
        }
        computeKills();
        functionGraphCache[currentFunc] = _cfg;
    }
    else
        _cfg = functionGraphCache[currentFunc];

    return false;
}

bool IntraTargetAnalysisPass::runOnModule(llvm::Module &M)
{
    return false;
}

void IntraTargetAnalysisPass::computeCFG(Function *func)
{
    BasicBlock *succ_bb;
    for (auto &bb : *func)
    {
        for (auto succ_it = succ_begin(&bb); succ_it != succ_end(&bb); succ_it++)
        {
            succ_bb = *succ_it;
            if (&bb == succ_bb || !_PDT->dominates(succ_bb, &bb))
            {
                // get terminator and connect with the dependent block
                // Any valid terminator. Terminators like ret will not be a problem
                Instruction *terminator = bb.getTerminator();

                BasicBlock *nearestCommonDominator = _PDT->findNearestCommonDominator(&bb, succ_bb);
                if (nearestCommonDominator == &bb)
                    _cfg->addEdge(&bb, succ_bb);

                for (auto *cur = _PDT->getNode(succ_bb);
                     cur != _PDT->getNode(nearestCommonDominator); cur = cur->getIDom())
                {
                    _cfg->addEdge(&bb, cur->getBlock());
                }
            }
            /**
             *
             * This missing condition in the PDG code seems incorrect.
             * Use this PDT example from here- https://llvm.org/devmtg/2017-10/slides/Kuderski-Dominator_Trees.pdf.
             * It seems like
             **/
            else
                _cfg->addEdge(&bb, succ_bb);
        }
    }
}

void IntraTargetAnalysisPass::collectMayAliasUses()
{
    pdg::ProgramGraph &pdg = pdg::ProgramGraph::getInstance();

    auto addessTakenStackObjects = pdg.getAddressTakenStackObjects();

    if (addessTakenStackObjects.empty())
        return;
    InstructionSet loadsAndCalls;
    for (inst_iterator inst_it = inst_begin(currentFunc), E = inst_end(currentFunc); inst_it != E; ++inst_it)
    {
        if (isa<LoadInst>(&*inst_it) || isa<CallBase>(&*inst_it))
            loadsAndCalls.insert(&*inst_it);
    }

    for (auto stackObj : addessTakenStackObjects)
    {
        if (stackObj->getFunction() != currentFunc)
            continue;
        for (auto loadOrCallUse : loadsAndCalls)
        {
            // Filter out direct uses
            if (LoadInst *loadInst = dyn_cast<LoadInst>(loadOrCallUse))
            {
                if (loadInst->getPointerOperand() == stackObj)
                    continue;
            }

            pdg::Node *src = pdg.getNode(*stackObj);
            pdg::Node *dst = pdg.getNode(*loadOrCallUse);
            if (!src || !dst)
                continue;
            if (pdg.canReach(*src, *dst))
                _cfg->addMayAliasUseForStackObject(stackObj, loadOrCallUse);
        }
    }
}

ReachabilityGraph *IntraTargetAnalysisPass::getCFG(Function &func)
{
    runOnFunction(func);
    return _cfg;
}

void IntraTargetAnalysisPass::reduceUnsafePoints(Function *func)
{

    auto cfg = getCFG(*func);
    std::set<Instruction *> initialUnsafePoints = cfg->getUnsafePoints();
    std::map<BasicBlock *, Instruction *> basicBlockToUnsafePoint;
    InstructionSet finalUnsafePoints;
    std::vector<BasicBlock *> topologicalSortSCC;
    std::vector<BasicBlock *> topologicalSortSCCFixed;

    std::map<BasicBlock *, bool> reachableFromAPoint;

    for (auto &basicBlock : *func)
    {
        basicBlockToUnsafePoint[&basicBlock] = nullptr;
        reachableFromAPoint[&basicBlock] = false;
    }

    for (auto point : initialUnsafePoints)
    {
        basicBlockToUnsafePoint[point->getParent()] = point;
    }

    // errs() << "# Initial unsafe points:" << initialUnsafePoints.size() << "\n";
    // errs() << "# Initial unsafe BBs:" << basicBlockToUnsafePoint.size() << "\n";

    bool hasUnsafeOp;
    Instruction *unsafeOPinSCC = nullptr;
    for (scc_iterator<Function *> SCCI = scc_begin(func); !SCCI.isAtEnd(); ++SCCI)
    {
        const std::vector<BasicBlock *> &nextSCC = *SCCI;
        hasUnsafeOp = false;
        unsafeOPinSCC = nullptr;
        for (std::vector<BasicBlock *>::const_iterator I = nextSCC.begin(),
                                                       E = nextSCC.end();
             I != E; ++I)
        {
            // errs() << (*I)->getName() << ", ";
            if (basicBlockToUnsafePoint[*I])
            {
                hasUnsafeOp = true;
                unsafeOPinSCC = basicBlockToUnsafePoint[*I];
                topologicalSortSCC.push_back(*I);
                topologicalSortSCCFixed.push_back(*I);
                break;
            }
        }
        /*  for (std::vector<BasicBlock *>::const_iterator I = nextSCC.begin(),
                                                        E = nextSCC.end();
              I != E; ++I)
         {
             // errs() << (*I)->getName() << ", ";
             if (!hasUnsafeOp)
                 break;
             topologicalSortSCC.push_back(*I);
             basicBlockToUnsafePoint[*I] = unsafeOPinSCC;
         } */
    }

    // errs() << "Reducing using top sort: " << topologicalSortSCC.size() << "\n";

    while (!topologicalSortSCC.empty())
    {
        auto sourceBB = topologicalSortSCC.back();
        topologicalSortSCC.pop_back();
        if (basicBlockToUnsafePoint[sourceBB])
        {
            if (reachableFromAPoint[sourceBB])
                continue;
            for (auto destBB : topologicalSortSCCFixed)
            {
                if (reachableFromAPoint[destBB])
                    continue;
                if (sourceBB != destBB && basicBlockToUnsafePoint[destBB])
                {
                    if (cfg->canReach(sourceBB, destBB))
                    {
                        reachableFromAPoint[destBB] = true;
                    }
                }
            }
            finalUnsafePoints.insert(basicBlockToUnsafePoint[sourceBB]);
        }
    }
    // errs() << "# Final unsafe points:" << finalUnsafePoints.size() << "\n";
    if (!finalUnsafePoints.empty() && finalUnsafePoints.size() < initialUnsafePoints.size())
    {
        cfg->setUnsafePoints(finalUnsafePoints);
    }
}

char IntraTargetAnalysisPass::ID = 0;

static RegisterPass<IntraTargetAnalysisPass>
    LCDG("lcdg", "Lite Control Dependency Graph Construction", false, true);