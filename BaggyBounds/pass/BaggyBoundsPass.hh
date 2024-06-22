//
// Created by Rahul Titus George on 10/22/21.
//

#ifndef BAGGY_BOUNDS_PASS_HH
#define BAGGY_BOUNDS_PASS_HH

#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Pass.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#include "Util.h"
#include <vector>
#include <algorithm>
#include "address_constants.h"

#define BAGGY_CTOR_NAME "baggy_ctor"
#define BAGGY_GLOBALS_CTOR_NAME "baggy_globals_ctor"

using namespace llvm;
using std::max;

namespace BaggyBounds {
    class BaggyBoundsPass : public ModulePass {
    public:
        static char ID;

        BaggyBoundsPass() : ModulePass(ID) {}

        bool runOnModule(Module &m);

        void getAnalysisUsage(AnalysisUsage &AU);

    private:
        DataLayout *DL;
        Module *currentModule = NULL;


        void initializeBaggyBoundsAndHandleMain();

        void replaceAllLibraryCalls();

        void replaceAllHeapAllocationFunctionCalls();

        void addNecessaryGlobalsAndBaggyMethods();

        void saveGlobalObjectsBounds();


    };

}

#endif //BAGGY_BOUNDS_PASS_HH
