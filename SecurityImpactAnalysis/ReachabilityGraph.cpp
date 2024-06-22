#include "ReachabilityGraph.hh"

using namespace llvm;

void ReachabilityGraph::addUnsafePoint(Instruction *unsafePoint)
{
    unsafePoints.insert(unsafePoint);
}

void ReachabilityGraph::clearUnsafePoints()
{
    unsafePoints.clear();
}

InstructionSet ReachabilityGraph::getUnsafePoints()
{
    return unsafePoints;
}

void ReachabilityGraph::setUnsafePoints(InstructionSet &unsafePointsSpecified)
{
    unsafePoints.clear();
    for (auto point : unsafePointsSpecified)
        unsafePoints.insert(point);
}

void ReachabilityGraph::addNode(BasicBlock *node)
{
    this->nodes.insert(node);
}

void ReachabilityGraph::addEdge(BasicBlock *source, BasicBlock *dest)
{
    if (this->edges.count(source) > 0)
    {
        this->edges[source].insert(dest);
    }
    else
    {
        std::set<BasicBlock *> outGoingEdges;
        outGoingEdges.insert(dest);
        this->edges[source] = outGoingEdges;
    }
}

bool ReachabilityGraph::canReach(llvm::BasicBlock *source_bb, llvm::BasicBlock *dest_bb)
{
    if (source_bb == nullptr || dest_bb == nullptr)
    {
        errs() << "Invalid src,dst  - Source :" << source_bb << ". Dest:" << dest_bb << "\n";
        return false;
    }

    std::map<BasicBlock *, bool> visited;
    std::queue<BasicBlock *> workList;

    if (&source_bb->getParent()->getEntryBlock() == source_bb)
        return true;

    for (auto &basicBlock : *source_bb->getParent())
    {
        visited[&basicBlock] = false;
    }

    workList.push(source_bb);

    // BFS search from source node
    while (!workList.empty())
    {
        auto curr_node = workList.front();

        if (visited[curr_node])
        {
            workList.pop();
            continue;
        }

        if (curr_node == dest_bb)
            return true;

        for (auto succ_bb : edges[curr_node])
        {
            workList.push(succ_bb);
        }

        visited[curr_node] = true;
        workList.pop();
    }

    return false;
}

bool ReachabilityGraph::canReach(llvm::Instruction *source, llvm::Instruction *dest)
{
    if (source == nullptr || dest == nullptr)
    {
        errs() << "Invalid src,dst  - Source :" << source << ". Dest:" << dest << "\n";
        return false;
    }
    BasicBlock *source_bb = source->getParent();
    BasicBlock *dest_bb = dest->getParent();
    return canReach(source_bb, dest_bb);
}

bool ReachabilityGraph::canReach(llvm::Instruction *source, llvm::Instruction *dest, std::set<llvm::BasicBlock *> ignoreList)
{
    if (source == NULL || dest == NULL)
    {
        errs() << "Source:" << source << ". Dest:" << dest << "\n";
        return false;
    }
    BasicBlock *source_bb = source->getParent();
    BasicBlock *dest_bb = dest->getParent();
    std::map<BasicBlock *, bool> visited;
    std::queue<BasicBlock *> workList;

    if (source_bb == dest_bb)
        return true;

    if (ignoreList.empty())
    {
        // errs() << "\t No kills \n";
        return canReach(source_bb, dest_bb);
    }

    for (auto &basicBlock : *source_bb->getParent())
    {
        visited[&basicBlock] = false;
    }

    workList.push(source_bb);

    // BFS search from source node
    while (!workList.empty())
    {
        auto curr_node = workList.front();

        if (ignoreList.find(curr_node) != ignoreList.end())
        {
            visited[curr_node] = true;
            workList.pop();
            continue;
        }

        if (visited[curr_node])
        {
            workList.pop();
            continue;
        }

        if (curr_node == dest_bb)
            return true;

        for (auto succ_bb : edges[curr_node])
        {
            workList.push(succ_bb);
        }

        visited[curr_node] = true;
        workList.pop();
    }

    return false;
}

void ReachabilityGraph::identifyUsableTargets(Instruction *unsafeOperationPoint, InstructionSet &usableTargets)
{
    if (!unsafeOperationPoint)
        return;
    if (instructionToUsableTargets.find(unsafeOperationPoint) != instructionToUsableTargets.end())
    {
        // errs() << "\t Cache hit:" << unsafeOperationPoint << " in func:" << unsafeOperationPoint->getFunction()->getName() << "\n";
        for (auto usableTarget : instructionToUsableTargets[unsafeOperationPoint])
            usableTargets.insert(usableTarget);
        return;
    }

    std::set<BasicBlock *> cutBlocks;
    InstructionSet usableTargetsInFunc;
    bool isUsable;
    for (auto stackObj : allStackObjects)
    {
        if (usableTargets.find(stackObj) != usableTargets.end())
        {
            continue;
        }
        cutBlocks.clear();
        isUsable = false;
        // errs() << "Obj:" << *stackObj << "\n";
        if (stackObjectsToKills.find(stackObj) != stackObjectsToKills.end())
        {
            // errs() << "\t Kills found:" << stackObjectsToKills[stackObj].size() << "\n";
            for (auto kill : stackObjectsToKills[stackObj])
                cutBlocks.insert(kill->getParent());
        }
        for (auto user_it : stackObj->users())
        {
            // errs() << "\t Use" << *user_it << "\n";
            if (canReach(unsafeOperationPoint, dyn_cast<Instruction>(user_it), cutBlocks))
            {
                // errs() << "\t Reachable" << *user_it << "\n";
                usableTargets.insert(stackObj);
                usableTargetsInFunc.insert(stackObj);
                isUsable = true;
                break;
            }
        }

        if (stackObjectsToMayAliasUses.find(stackObj) == stackObjectsToMayAliasUses.end())
            continue;
        if (!isUsable)
        {
            for (auto user_it : stackObjectsToMayAliasUses[stackObj])
            {
                // errs() << "\t Use" << *user_it << "\n";
                if (canReach(unsafeOperationPoint, user_it, cutBlocks))
                {
                    // errs() << "\t Reachable" << *user_it << "\n";
                    usableTargets.insert(stackObj);
                    usableTargetsInFunc.insert(stackObj);
                    break;
                }
            }
        }
    }
    instructionToUsableTargets[unsafeOperationPoint] = usableTargetsInFunc;
}

void ReachabilityGraph::identifyUsableTargetsForUnsafePoints(InstructionSet &usableTargets)
{
    if (unsafePoints.empty())
        return;

    bool isUsable = false;
    std::set<BasicBlock *> cutBlocks;
    errs() << "\t\t\t # Stack objects:" << allStackObjects.size() << " : Points- " << unsafePoints.size() << "\n";

    for (Instruction *unsafePoint : unsafePoints)
    {
        errs() << "\t\t\t\t Unsafe point:" << *unsafePoint << "\n";
    }

    for (auto stackObj : allStackObjects)
    {
        if (usableTargets.find(stackObj) != usableTargets.end())
        {
            continue;
        }
        cutBlocks.clear();
        isUsable = false;
        // errs() << "Obj:" << *stackObj << "\n";
        if (stackObjectsToKills.find(stackObj) != stackObjectsToKills.end())
        {
            for (auto kill : stackObjectsToKills[stackObj])
                cutBlocks.insert(kill->getParent());
        }
        // errs() << "\t Cut blocks:" << cutBlocks.size() << "\n";

        for (auto user_it : stackObj->users())
        {
            // errs() << "\t Use" << *user_it << "\n";
            for (Instruction *unsafePoint : unsafePoints)
            {
                if (canReach(unsafePoint, dyn_cast<Instruction>(user_it), cutBlocks))
                {
                    // errs() << "\t Reachable" << *user_it << "\n";
                    usableTargets.insert(stackObj);
                    isUsable = true;
                    break;
                }
            }
            if (isUsable)
                break;
        }

        if (!isUsable)
        {
            if (stackObjectsToMayAliasUses.find(stackObj) == stackObjectsToMayAliasUses.end())
                continue;
            for (auto user_it : stackObjectsToMayAliasUses[stackObj])
            {
                // errs() << "\t Use" << *user_it << "\n";
                for (Instruction *unsafePoint : unsafePoints)
                {
                    if (canReach(unsafePoint, user_it, cutBlocks))
                    {
                        // errs() << "\t Reachable" << *user_it << "\n";
                        usableTargets.insert(stackObj);
                        isUsable = true;
                        break;
                    }
                }
                if (isUsable)
                    break;
            }
        }
    }
}

void ReachabilityGraph::removeBlock(llvm::BasicBlock *blockToRemove)
{
    // First remove all edges then remove the block itself
    edges.erase(blockToRemove);
    nodes.erase(blockToRemove);
    return;
}

void ReachabilityGraph::setAllTargets(InstructionSet &allStackObjectsIdentified)
{
    for (auto obj : allStackObjectsIdentified)
        allStackObjects.insert(obj);
}

void ReachabilityGraph::setKills(llvm::Instruction *stackObj, InstructionSet kills)
{
    InstructionSet localKills;
    for (auto killUse : kills)
        localKills.insert(killUse);
    stackObjectsToKills[stackObj] = localKills;
}

void ReachabilityGraph::getAllTargets(InstructionSet &usableTargets)
{
    for (auto obj : allStackObjects)
        usableTargets.insert(obj);
}

void ReachabilityGraph::addMayAliasUseForStackObject(llvm::Instruction *stackObject, llvm::Instruction *mayAliasUse)
{
    if (stackObjectsToMayAliasUses.find(stackObject) == stackObjectsToMayAliasUses.end())
    {
        InstructionSet mayAliasUses;
        stackObjectsToMayAliasUses[stackObject] = mayAliasUses;
    }
    stackObjectsToMayAliasUses[stackObject].insert(mayAliasUse);
}
