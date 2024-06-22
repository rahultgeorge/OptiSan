#include "DataDependencyGraph.hh"
#include "PDGUtils.hh"

char pdg::DataDependencyGraph::ID = 0;

using namespace llvm;

bool pdg::DataDependencyGraph::runOnModule(Module &M)
{
  ProgramGraph &g = ProgramGraph::getInstance();
  PTAWrapper &ptaw = PTAWrapper::getInstance();

  if (!ptaw.hasPTASetup())
    ptaw.setupPTA(M);

  for (auto &F : M)
  {
    if (F.isDeclaration() || F.empty())
      continue;

    checkForAliasesToStackData(F);
  }

  bool hasAliasesToStackData = !g.getAddressTakenStackObjects().empty();
  if (!g.isBuild())
  {
    g.build(M);
    if (hasAliasesToStackData)
    {
      g.bindDITypeToNodes(M);
      errs() << "# Address taken stack variables:" << g.getAddressTakenStackObjects().size() << "\n";
    }
  }

  if (hasAliasesToStackData)
  {
    for (auto &F : M)
    {
      if (F.isDeclaration() || F.empty())
        continue;

      _mem_dep_res = &getAnalysis<MemoryDependenceWrapperPass>(F).getMemDep();
      // setup alias query interface for each function
      for (auto inst_iter = inst_begin(F); inst_iter != inst_end(F); inst_iter++)
      {
        addDefUseEdges(*inst_iter);
        addAliasEdges(*inst_iter);
        addRAWEdges(*inst_iter);
      }
    }
  }

  ptaw.clearPTA();
  return false;
}

void pdg::DataDependencyGraph::checkForAliasesToStackData(Function &F)
{
  PTAWrapper &ptaw = PTAWrapper::getInstance();
  ProgramGraph &g = ProgramGraph::getInstance();

  SVF::NodeID nodeId;
  SVF::PointsTo pointsToInfo;
  for (auto inst_iter = inst_begin(F); inst_iter != inst_end(F); inst_iter++)
  {
    AllocaInst *stackObj = dyn_cast<AllocaInst>(&*inst_iter);

    if (!stackObj)
      continue;

    if (ptaw.getPAG()->hasValueNode(stackObj))
    {
      nodeId = ptaw.getPAG()->getValueNode(stackObj);
      auto aliasesToMemObj = ptaw.getReversePointsTo(nodeId);
      if (aliasesToMemObj.empty())
        continue;
      // errs() << "Stack data:" << *stackObj << "\n";
      // errs() << "\t Aliases:" << aliasesToMemObj.size() << "\n";
      // Iterate through the objects
      for (auto memObjID = aliasesToMemObj.begin();
           memObjID != aliasesToMemObj.end(); memObjID++)
      {
        auto *aliasSVFNode = ptaw.getPAG()->getObject(*memObjID);
        if (aliasSVFNode)
        {
          auto aliasPtr = const_cast<Value *>(aliasSVFNode->getRefVal());
          if (aliasPtr && aliasPtr->getType()->isPointerTy())
          {
            // errs() << "\t" << *aliasPtr << "\n";
            if (stackObj != aliasPtr)
              // TODO - Record this stack object as we need to check for such objects
              g.addAddressTakenStackObject(stackObj);
          }
        }
      }
    }
  }
}

void pdg::DataDependencyGraph::addAliasEdges(Instruction &inst)
{
  ProgramGraph &g = ProgramGraph::getInstance();
  PTAWrapper &ptaw = PTAWrapper::getInstance();
  Function *func = inst.getFunction();
  for (auto inst_iter = inst_begin(func); inst_iter != inst_end(func); inst_iter++)
  {
    if (&inst == &*inst_iter)
      continue;
    if (!inst.getType()->isPointerTy())
      continue;
    auto anders_aa_result = ptaw.queryAlias(inst, *inst_iter);
    auto alias_result = queryAliasUnderApproximate(inst, *inst_iter);

    if (anders_aa_result != NoAlias || alias_result != NoAlias)
    {
      Node *src = g.getNode(inst);
      Node *dst = g.getNode(*inst_iter);
      if (src == nullptr || dst == nullptr)
        continue;
      // use type info to eliminate dubious gep
      if (!isa<BitCastInst>(*inst_iter) && !isa<BitCastInst>(&inst))
      {
        if (inst.getType() != inst_iter->getType())
          continue;
      }
      src->addNeighbor(*dst, EdgeType::DATA_ALIAS);
      dst->addNeighbor(*src, EdgeType::DATA_ALIAS);
    }
  }
}

void pdg::DataDependencyGraph::addDefUseEdges(Instruction &inst)
{
  ProgramGraph &g = ProgramGraph::getInstance();
  for (auto user : inst.users())
  {
    Node *src = g.getNode(inst);
    Node *dst = g.getNode(*user);
    if (src == nullptr || dst == nullptr)
      continue;
    EdgeType edge_type = EdgeType::DATA_DEF_USE;
    if (dst->getNodeType() == GraphNodeType::ANNO_VAR)
      edge_type = EdgeType::ANNO_VAR;
    if (dst->getNodeType() == GraphNodeType::ANNO_GLOBAL)
      edge_type = EdgeType::ANNO_GLOBAL;
    src->addNeighbor(*dst, edge_type);
  }
}

void pdg::DataDependencyGraph::addRAWEdges(Instruction &inst)
{
  if (!isa<LoadInst>(&inst))
    return;

  ProgramGraph &g = ProgramGraph::getInstance();
  auto dep_res = _mem_dep_res->getDependency(&inst);
  auto dep_inst = dep_res.getInst();

  if (!dep_inst || !isa<StoreInst>(dep_inst))
    return;

  Node *src = g.getNode(inst);
  Node *dst = g.getNode(*dep_inst);
  if (src == nullptr || dst == nullptr)
    return;
  dst->addNeighbor(*src, EdgeType::DATA_RAW);
}

AliasResult pdg::DataDependencyGraph::queryAliasUnderApproximate(Value &v1, Value &v2)
{
  if (!v1.getType()->isPointerTy() || !v2.getType()->isPointerTy())
    return NoAlias;
  // check bit cast
  if (BitCastInst *bci = dyn_cast<BitCastInst>(&v1))
  {
    if (bci->getOperand(0) == &v2)
      return MustAlias;
  }
  // handle load instruction
  if (LoadInst *li = dyn_cast<LoadInst>(&v1))
  {
    auto load_addr = li->getPointerOperand();
    for (auto user : load_addr->users())
    {
      if (StoreInst *si = dyn_cast<StoreInst>(user))
      {
        if (si->getPointerOperand() == load_addr)
        {
          if (si->getValueOperand() == &v2)
            return MustAlias;
        }
      }
    }
  }
  return NoAlias;
}

void pdg::DataDependencyGraph::getAnalysisUsage(AnalysisUsage &AU) const
{
  AU.addRequired<MemoryDependenceWrapperPass>();
  AU.setPreservesAll();
}

static RegisterPass<pdg::DataDependencyGraph>
    DDG("ddg", "Data Dependency Graph Construction", false, true);
