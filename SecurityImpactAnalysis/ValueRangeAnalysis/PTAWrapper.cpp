#include "PTAWrapper.hh"

using namespace llvm;
using namespace SVF;

void alias::PTAWrapper::setupPTA(Module &M)
{
  SVFModule *module = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
  PAGBuilder builder;
  PAG *pag = builder.build(module);
  _ander_pta = AndersenWaveDiff::createAndersenWaveDiff(pag);
  //_ander_pta = Steensgaard::createSteensgaard(pag);
}

#ifdef USE_SEA_DSA
void alias::PTAWrapper::setupSeaDsaPTA()
{
  seadsa::SeaDsaAAWrapperPass *seaDsaWrapperPass = new seadsa::SeaDsaAAWrapperPass();
  seaDsaWrapperPass->initializePass();
  _seadsa_aa = &seaDsaWrapperPass->getResult();
}
#endif

void alias::PTAWrapper::clearPTA()
{
  AndersenWaveDiff::releaseAndersenWaveDiff();
  Steensgaard::releaseSteensgaard();
}

AliasResult alias::PTAWrapper::queryAlias(Value &v1, Value &v2)
{
  assert(_ander_pta != nullptr && "cannot obtain ander pointer analysis!\n");
  return _ander_pta->alias(&v1, &v2);
}
