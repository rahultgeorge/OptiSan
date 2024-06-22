#include "PTAWrapper.hh"

using namespace llvm;
using namespace SVF;

void pdg::PTAWrapper::setupPTA(Module &M)
{
  SVFModule *module = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
  PAGBuilder builder;
  PAG *pag = builder.build(module);
  _pta = AndersenWaveDiff::createAndersenWaveDiff(pag);
  // _pta = SVF::Steensgaard::createSteensgaard(pag);
}

void pdg::PTAWrapper::clearPTA()
{
  // Release SVF module, PAG and PTA
  AndersenWaveDiff::releaseAndersenWaveDiff();
  SVF::PAG::releasePAG();
  SVF::LLVMModuleSet::releaseLLVMModuleSet();
}

const SVF::NodeSet &pdg::PTAWrapper::getReversePointsTo(SVF::NodeID objectNodeID)
{
  return _pta->getRevPts(objectNodeID);
}

AliasResult pdg::PTAWrapper::queryAlias(Value &v1, Value &v2)
{
  assert(_pta != nullptr && "cannot obtain ander pointer analysis!\n");
  return _pta->alias(&v1, &v2);
}
