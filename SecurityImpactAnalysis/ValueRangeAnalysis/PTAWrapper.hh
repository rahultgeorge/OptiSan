#ifndef _PTAWRAPPER_H_
#define _PTAWRAPPER_H_
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/ADT/GraphTraits.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Analysis/AliasAnalysis.h"

#include "config.h"
#ifdef USE_SEA_DSA
#include "seadsa/Global.hh"
#include "seadsa/DsaAnalysis.hh"
#include "seadsa/DsaLibFuncInfo.hh"
#include "seadsa/support/RemovePtrToInt.hh"
#include "seadsa/SeaDsaAliasAnalysis.hh"
#include "seadsa/InitializePasses.hh"
#include "seadsa/Info.hh"
#include "seadsa/Graph.hh"
#else
#include "SVF-FE/PAGBuilder.h"
#include "WPA/Andersen.h"
#include "WPA/Steensgaard.h"
#include "SVF-FE/LLVMUtil.h"
#endif

namespace alias
{
  class PTAWrapper final
  {
  public:
    PTAWrapper() = default;
    PTAWrapper(const PTAWrapper &) = delete;
    PTAWrapper(PTAWrapper &&) = delete;
    PTAWrapper &operator=(const PTAWrapper &) = delete;
    PTAWrapper &operator=(PTAWrapper &&) = delete;
    static PTAWrapper &getInstance()
    {
      static PTAWrapper ptaw{};
      return ptaw;
    }
    void setupPTA(llvm::Module &M);
#ifdef USE_SEA_DSA 
    void setupSeaDsaPTA();
    // SVF::Steensgaard *_ander_pta;
    seadsa::SeaDsaAAResult *_seadsa_aa;
#endif
    void clearPTA();

    bool hasPTASetup() { return (_ander_pta != nullptr); }
    llvm::AliasResult queryAlias(llvm::Value &v1, llvm::Value &v2);
    // SVF::PAG* getPAG();
    SVF::AndersenWaveDiff *_ander_pta;
  };

}

#endif
