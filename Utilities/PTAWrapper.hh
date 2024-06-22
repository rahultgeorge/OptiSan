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
#include "SVF-FE/PAGBuilder.h"
#include "WPA/Andersen.h"
#include "SVF-FE/LLVMUtil.h"


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
    void clearPTA();

    bool hasPTASetup() { return (_ander_pta != nullptr); }
    llvm::AliasResult queryAlias(llvm::Value &v1, llvm::Value &v2);
    //SVF::PAG* getPAG();
    SVF::AndersenWaveDiff *_ander_pta;
  };
} 

#endif
