#ifndef _ValueRange_
#define _ValueRange_

#include "llvm/ADT/APSInt.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Bitcode/BitcodeWriter.h"

#include <set>
#include <bitset>
#include <memory>
#include <string>

#include <neo4j-client.h>
#include "CoverageUtilities.hh"
#include "DataflowAnalysis.hh"
#include "PTAWrapper.hh"
#include "AnalysisState.hpp"
#include "GraphConstants.h"

#ifdef USE_SEA_DSA
#include "seadsa/DsaAnalysis.hh"
#endif

using namespace llvm;

void valueRangeAnalysis(Module *, std::set<Value *>, std::map<llvm::Instruction *, std::string>, alias::PTAWrapper &);

// void valueRangeAnalysis(Module *, std::set<Value *>, std::map<llvm::Instruction *, std::string>);

#endif
