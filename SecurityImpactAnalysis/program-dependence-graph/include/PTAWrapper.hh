#ifndef _PTAWRAPPER_H_
#define _PTAWRAPPER_H_
#include "LLVMEssentials.hh"

#include "SVF-FE/PAGBuilder.h"
#include "WPA/Andersen.h"
#include "WPA/Steensgaard.h"
#include "SVF-FE/LLVMUtil.h"
#include "Graphs/PTACallGraph.h"

namespace pdg
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
    bool hasPTASetup() { return (_pta != nullptr); }
    llvm::AliasResult queryAlias(llvm::Value &v1, llvm::Value &v2);
    void clearPTA();

    const SVF::NodeSet &getReversePointsTo(SVF::NodeID objectNodeID);

    SVF::PAG *getPAG()
    {
      return _pta->getPAG();
    }

    const SVF::PointsTo &getPointsToInfo(SVF::NodeID nodeID)
    {
      return _pta->getPts(nodeID);
    }

    SVF::PTACallGraph *getPTACallGraph()
    {
      return _pta->getPTACallGraph();
    }

  private:
    SVF::AndersenWaveDiff *_pta;
    // SVF::Steensgaard *_pta;
  };
} // namespace pdg

#endif