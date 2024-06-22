#include "FunctionScanPass.hh"

inline ConstantExpr *hasConstantGEP(Value *V)
{
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(V))
    {
        if (CE->getOpcode() == Instruction::GetElementPtr)
        {
            return CE;
        }
        else
        {
            for (unsigned index = 0; index < CE->getNumOperands(); ++index)
            {
                if (hasConstantGEP(CE->getOperand(index)))
                    return CE;
            }
        }
    }

    return 0;
}

void FunctionScanPass::processFunction(Function *currFunc)
{
    Instruction *instruction = NULL;
    std::string instructionDbgID;
    DILocation *loc = NULL;

    instructionDbgIDMap.clear();
    instructionIRToInstMap.clear();
    std::string currInstString;
    llvm::raw_string_ostream rso(currInstString);
    bool containsGEPExpression = false;

    for (auto inst_it = inst_begin(currFunc); inst_it != inst_end(currFunc); inst_it++)
    {
        instruction = &*inst_it;
        GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(instruction);
        containsGEPExpression = false;
        if ((!gep))
        {
            for (auto &operand : instruction->operands())
            {
                if (auto constantGepExpression = hasConstantGEP(operand.get()))
                {
                    containsGEPExpression = true;
                    break;
                }
            }
            if (!containsGEPExpression)
                continue;
        }

        // else if (gep->hasAllZeroIndices())
        //     continue;

        loc = instruction->getDebugLoc();
        if (!loc || loc->isImplicitCode())
        {
            // errs() << "No dbg info(or corrupt):" << *instruction << "\n";
            continue;
        }
        instructionDbgID = loc->getFilename();
        instructionDbgID =
            instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" + std::to_string(loc->getColumn());

        if (instructionDbgIDToIRMap.find(instructionDbgID) == instructionDbgIDToIRMap.end() &&
            (instructionDbgIDMap.find(instructionDbgID) == instructionDbgIDMap.end()))
        {
            instructionDbgIDMap[instructionDbgID] = instruction;
        }
        else
        {
            std::set<std::string> potentialMatches;
            // errs() << "\t Multiple :" << instructionDbgID << "\n";
            if (instructionDbgIDToIRMap.find(instructionDbgID) == instructionDbgIDToIRMap.end())
            {

                // Insert the prev one
                rso << *instructionDbgIDMap[instructionDbgID];
                potentialMatches.insert(currInstString);
                instructionIRToInstMap[currInstString] = instructionDbgIDMap[instructionDbgID];
                currInstString.clear();
                rso.flush();
                instructionDbgIDMap.erase(instructionDbgID);
            }
            else
                potentialMatches = instructionDbgIDToIRMap[instructionDbgID];
            // Insert this one
            rso << *instruction;
            potentialMatches.insert(currInstString);
            instructionDbgIDToIRMap[instructionDbgID] = potentialMatches;
            //            assert (instructionIRToInstMap.find(currInstString) == instructionIRToInstMap.end());
            //            exit(1);
            instructionIRToInstMap[currInstString] = instruction;
            rso.flush();
        }
        currInstString.clear();
        rso.flush();
        instructionDbgID.clear();
    }
}

bool FunctionScanPass::runOnFunction(Function &F)
{
    // errs() << "Processing function:" << F.getName().str() << "\n";
    funcBeingAnalyzed = &F;
    processFunction(&F);
    return false;
}

void FunctionScanPass::getAnalysisUsage(AnalysisUsage &AU) const { AU.setPreservesAll(); }

char FunctionScanPass::ID = 0;
static RegisterPass<FunctionScanPass>
    Y("dbgscan-func", "Scan function instructions and record debug info based id for interesting instructions",
      false, true);
