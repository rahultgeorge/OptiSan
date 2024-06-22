#include "FunctionScanPass.hh"

void FunctionScanPass::processFunction(Function *currFunc)
{
    Instruction *instruction = nullptr;
    std::string instructionDbgID;
    DILocalScope *scope = nullptr;
    for (auto inst_it = inst_begin(currFunc); inst_it != inst_end(currFunc); inst_it++)
    {
        instruction = &*inst_it;
        scope = nullptr;

        if (DbgDeclareInst *dbi = dyn_cast<DbgDeclareInst>(instruction))
        {
            DILocalVariable *variable = dbi->getVariable();
            if (!variable)
                continue;
            scope = variable->getScope();
        }
        else if (DbgValueInst *dbi = dyn_cast<DbgValueInst>(instruction))
        {
            DILocalVariable *variable = dbi->getVariable();
            if (!variable)
                continue;
            scope = variable->getScope();
        }
        if (DISubprogram *subprogram = dyn_cast_or_null<DISubprogram>(scope))
        {
            instructionDbgID = subprogram->getName();
            if (!subprogram->getLinkageName().empty())
                instructionDbgID = subprogram->getLinkageName();
            if (functionDbgIDToIRMap.find(instructionDbgID) == functionDbgIDToIRMap.end() &&
                (functionDbgIDMap.find(instructionDbgID) == functionDbgIDMap.end()))
            {
                functionDbgIDMap[instructionDbgID] = currFunc;
            }
            else
            {
                std::set<std::string> potentialMatches;
                // errs() << "\t Multiple :" << instructionDbgID << "\n";
                if (functionDbgIDToIRMap.find(instructionDbgID) == functionDbgIDToIRMap.end())
                {

                    // Insert the prev one
                    auto prevFunc = functionDbgIDMap[instructionDbgID];
                    if (prevFunc)
                        potentialMatches.insert(prevFunc->getName().str());

                    functionDbgIDMap.erase(instructionDbgID);
                }
                else
                    potentialMatches = functionDbgIDToIRMap[instructionDbgID];
                // Insert this one
                potentialMatches.insert(currFunc->getName().str());
                functionDbgIDToIRMap[instructionDbgID] = potentialMatches;
            }
        }

        instructionDbgID.clear();
    }
}

bool FunctionScanPass::runOnFunction(Function &F)
{
    funcBeingAnalyzed = &F;
    return false;
}

void FunctionScanPass::processFunction()
{
    if (funcBeingAnalyzed)
    {
        // errs() << "\t Processing function (scan pass):" << funcBeingAnalyzed->getName().str() << "\n";
        processFunction(funcBeingAnalyzed);
    }
}

void FunctionScanPass::getAnalysisUsage(AnalysisUsage &AU) const { AU.setPreservesAll(); }

char FunctionScanPass::ID = 0;
static RegisterPass<FunctionScanPass>
    Y("dbgscan-func", "Scan function instructions and record debug info based id for interesting instructions",
      false, true);
