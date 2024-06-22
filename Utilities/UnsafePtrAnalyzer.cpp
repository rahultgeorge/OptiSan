#include "UnsafePtrAnalyzer.hh"

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

inline std::string
processStringEscapeCharacters(std::string instructionString)
{
    // Neo4j (or its C driver) escapes " in strings automatically. This means if
    // we use the instruction string to match then we need to deal with this (DBG
    // is the future)
    std::size_t replacePos = instructionString.find("\\\"");
    while (replacePos != std::string::npos)
    {
        // Deal with double quotes
        // errs()<<"DEALING\n";
        instructionString.replace(replacePos, 2, "\"");
        replacePos = instructionString.find("\\\"");
    }

    return instructionString;
}

inline std::string
addNecessaryEscapeCharacters(std::string instructionString)
{

    std::size_t replacePos = instructionString.find("\"");
    bool isChanged = false;
    while (replacePos != std::string::npos)
    {
        // Deal with double quotes
        //        errs() << "replacePos:" << replacePos << "\n";
        //        errs() << "instructionString:" << instructionString << "\n";
        instructionString.replace(replacePos, 2, "\\\"");
        replacePos = instructionString.find("\"", replacePos + 3);
        isChanged = true;
    }

    // TODO - Fix me later
    //     instructionString = "alloca";
    // if (isChanged)
    //     errs() << "\t Final:" << instructionString.c_str() << "\n";
    return instructionString;
}

inline std::string getDebugID(Instruction *instruction)
{
    std::string instructionDbgID = "";
    DILocation *loc = NULL;
    loc = instruction->getDebugLoc();
    if (!loc || loc->isImplicitCode())
    {
        // errs() << "No dbg info(or corrupt):" << *instruction << "\n";
        return instructionDbgID;
    }
    instructionDbgID = loc->getFilename();
    instructionDbgID =
        instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" + std::to_string(loc->getColumn());
    return instructionDbgID;
}

Instruction *UnsafePtrAnalyzer::findInstructionInFunctionUsingIR(std::string instructionString, Function *function)
{
    Instruction *instruction = NULL;
    std::string currInstString;
    llvm::raw_string_ostream rso(currInstString);
    if (irToInstructionCache.find(instructionString) != irToInstructionCache.end())
        return irToInstructionCache[instructionString];

    for (auto bb_iter = function->begin(); bb_iter != function->end(); bb_iter++)
    {
        for (auto inst_it = bb_iter->begin(); inst_it != bb_iter->end(); inst_it++)
        {
            instruction = &*inst_it;
            if (!instruction)
                continue;
            if (!(isa<StoreInst>(instruction) || isa<GetElementPtrInst>(instruction)))
                continue;
            rso << *instruction;
            if (instructionString.compare(currInstString) == 0)
            {
                // Match
                // errs() << "\t DBG match:" << instructionDbgID << "\n";
                irToInstructionCache[currInstString] = instruction;
                return instruction;
            }
            irToInstructionCache[currInstString] = instruction;
            rso.flush();
            currInstString.clear();
        }
    }

    return nullptr;
}

void UnsafePtrAnalyzer::identifyFormalArguments(Function *function)
{
    if (functionToArgCache.find(function) != functionToArgCache.end())
        return;
    // This included args and in case of O0 the stack variable which takes the address of the arg (promotable alloca)
    std::set<Value *> argValues;
    std::set<DbgDeclareInst *> dbgInsts;
    if (function->hasFnAttribute(Attribute::OptimizeNone))
    {
        for (inst_iterator I = inst_begin(function),
                           E = inst_end(function);
             I != E; ++I)
        {
            if (DbgDeclareInst *dbg_declare_inst = dyn_cast<DbgDeclareInst>(&*I))
            {
                dbgInsts.insert(dbg_declare_inst);
            }
        }
    }

    for (auto &arg : function->args())
    {

        argValues.insert(&arg);
        for (auto dbg_declare_inst : dbgInsts)
        {

            DILocalVariable *di_local_var = dbg_declare_inst->getVariable();
            if (!di_local_var)
                continue;
            if (di_local_var->getArg() == arg.getArgNo() + 1 && !di_local_var->getName().empty() &&
                di_local_var->getScope()->getSubprogram() == function->getSubprogram())
            {
                if (AllocaInst *ai = dyn_cast<AllocaInst>(dbg_declare_inst->getVariableLocation()))
                {
                    argValues.insert(ai);
                    argValues.insert(dbg_declare_inst);
                }
            }
        }
    }

    functionToArgCache[function] = argValues;
}

Argument *
UnsafePtrAnalyzer::findArgument(Value *argOrGV)
{
    Instruction *argAlloca = NULL;
    Argument *argument = NULL;
    Function *currFunc = NULL;

    argAlloca = dyn_cast<AllocaInst>(argOrGV);
    if (argAlloca)
    {
        // Find the argument
        currFunc = argAlloca->getFunction();
        for (auto argRelatedValue : functionToArgCache[currFunc])
        {
            if (DbgDeclareInst *dbg_declare_inst = dyn_cast<DbgDeclareInst>(argRelatedValue))
            {
                DILocalVariable *di_local_var = dbg_declare_inst->getVariable();
                if (argAlloca == dyn_cast<AllocaInst>(dbg_declare_inst->getVariableLocation()))
                {
                    argument = currFunc->getArg(di_local_var->getArg() - 1);
                    break;
                }
            }
        }
    }
    else
        argument = dyn_cast<Argument>(argOrGV);
    if (!argument || argument->hasByValAttr())
    {
        errs() << "Failed to find argument or byval:"
               << "\n";
        return nullptr;
    }

    errs() << "\tFormal argument found:" << *argument << "\n";
    return argument;
}

std::set<Instruction *> UnsafePtrAnalyzer::findStackDataSource(GetElementPtrInst *oobGEP)
{
    std::set<Instruction *> stackSources;
    if (!oobGEP)
        return stackSources;
    auto addressTakenVariable = oobGEP->getPointerOperand();
    Function *currFunc = oobGEP->getFunction();
    std::queue<Value *> workList;
    std::set<Value *> valuesSeen;
    Argument *argument = nullptr;

    errs() << "GEP:" << *oobGEP << "\n";
    workList.push(addressTakenVariable);

    if (valueToStackObjects.find(oobGEP) != valueToStackObjects.end())
    {
        errs() << "\t Cache hit\n";
        return valueToStackObjects[oobGEP];
    }

    SVF::NodeID nodeId;
    alias::PTAWrapper &ptaw = alias::PTAWrapper::getInstance();
    SVF::PointsTo pointsToInfo;

    if (!ptaw.hasPTASetup())
    {
        errs() << "Points to info not computed\n";
    }

    else
    {
        if (!(ptaw._ander_pta->getPAG()->hasValueNode(oobGEP)) &&
            !(ptaw._ander_pta->getPAG()->hasValueNode(oobGEP->getPointerOperand())))
        {
            errs() << "No SVF node so check if can find out using CCured's value range analysis"
                   << "\n";
        }
        else
        {
            if (isa<ExtractValueInst>(oobGEP->getPointerOperand()))
            {
                // SVF crashes with extract value so
                nodeId = ptaw._ander_pta->getPAG()->getValueNode(oobGEP);
            }
            else
                nodeId = ptaw._ander_pta->getPAG()->getValueNode(oobGEP->getPointerOperand());

            pointsToInfo = ptaw._ander_pta->getPts(nodeId);

            // Iterate through the objects
            for (auto memObjID = pointsToInfo.begin();
                 memObjID != pointsToInfo.end(); memObjID++)
            {
                auto *targetObj = ptaw._ander_pta->getPAG()->getObject(*memObjID);

                // If any element in the points to set is not on the stack (Conservative)
                if (targetObj->isStack())
                {
                    auto stackObj = dyn_cast<Instruction>(targetObj->getRefVal());
                    if (stackObj)
                    {
                        errs() << "\t" << *stackObj << "\n";
                        stackSources.insert(const_cast<Instruction *>(stackObj));
                    }
                }
            }
            if (!stackSources.empty())
            {
                valueToStackObjects[oobGEP] = stackSources;
                return stackSources;
            }
        }
    }
    errs() << "\t Address taken var:" << *addressTakenVariable << "\n";

    identifyFormalArguments(currFunc);

    while (!workList.empty())
    {
        auto curr = workList.front();

        if (valuesSeen.find(curr) != valuesSeen.end())
        {
            workList.pop();
            continue;
        }

        //        errs() << "\t Curr:" << *curr << "\n";
        if (AllocaInst *AI = dyn_cast<AllocaInst>(curr))
        {
            currFunc = AI->getFunction();
            identifyFormalArguments(currFunc);
            if (functionToArgCache[currFunc].find(AI) != functionToArgCache[currFunc].end())
            {
                argument = findArgument(AI);

                for (auto user_it : currFunc->users())
                {
                    if (CallInst *callInst = dyn_cast<CallInst>(user_it))
                    {
                        //                        errs() << "\tCall site:" << *callInst << "\n";
                        if (callInst->getNumOperands() >= argument->getArgNo() + 1)
                        {
                            workList.push(callInst->getOperand(argument->getArgNo()));
                        }
                    }
                }
            }
            else if (!AI->getAllocatedType()->isPointerTy())
            {
                errs() << "\t Stack data:" << *AI << ":" << AI->getFunction()->getName() << "\n";
                stackSources.insert(AI);
            }
            else
            {
                errs() << "\t Stack ptr:" << *AI << ":" << *AI->getAllocatedType() << "\n";
                for (auto user_it : AI->users())
                {
                    // This is an over approximation
                    if (StoreInst *storeInst = dyn_cast<StoreInst>(user_it))
                    {
                        workList.push(storeInst->getOperand(0));
                    }
                }
            }
        }
        else if (GlobalValue *GV = dyn_cast<GlobalValue>(curr))
        {
            errs() << "\t Global value:" << GV->getName() << "\n";
            if (GV->getType()->isPointerTy())
            {
                for (auto user_it : GV->users())
                {
                    // This is an over approximation
                    if (StoreInst *storeInst = dyn_cast<StoreInst>(user_it))
                    {
                        //                    errs() << "\t Store:" << *storeInst << "\n";
                        //                    errs() << "\t Store:" << *storeInst->getOperand(0) << "\n";
                        workList.push(storeInst->getOperand(0));
                    }
                }
            }
        }
        else if (CallInst *callInst = dyn_cast<CallInst>(curr))
        {
            std::string calleeName = "";
            if (callInst->getCalledFunction())
                calleeName = callInst->getCalledFunction()->getName().str();
            errs() << "\t Call Inst:" << calleeName << "\n";
        }
        else if (Instruction *dataInst = dyn_cast<Instruction>(curr))
        {
            if (dataInst->isCast() || dataInst->isUnaryOp())
            {
                //                errs() << "Cast inst src:" << *dataInst->getOperand(0) << "\n";
                workList.push(dataInst->getOperand(0));
            }
            else if (LoadInst *loadInst = dyn_cast<LoadInst>(curr))
            {
                Value *loadSource = loadInst->getOperand(0);

                // Try to find all prev stores
                workList.push(loadSource);
            }
            else if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(curr))
            {
                if (valueToStackObjects.find(gep) != valueToStackObjects.end())
                {
                    for (auto stackObj : valueToStackObjects[gep])
                        stackSources.insert(stackObj);
                }
                else
                    workList.push(gep->getPointerOperand());
            }
        }
        else if (PHINode *phiNode = dyn_cast<PHINode>(curr))
        {
            for (unsigned int val_no = 0; val_no < phiNode->getNumIncomingValues(); val_no++)
                workList.push(phiNode->getIncomingValue(val_no));
        }

        valuesSeen.insert(curr);
        workList.pop();
    }

    errs() << "# Stack sources found:" << stackSources.size() << "\n";
    valueToStackObjects[oobGEP] = stackSources;
    return stackSources;
}

std::string UnsafePtrAnalyzer::getFunctionDebugInfo(std::string functionName)
{
    std::string statement;
    std::string field_string;
    std::string dbgID;

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t functionNameValue;

    neo4j_map_entry_t mapEntries[3];
    neo4j_result_stream_t *results;
    neo4j_result_t *record;
    neo4j_value_t params;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    functionNameValue = neo4j_string(functionName.c_str());

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("function_name", functionNameValue);
    mapEntries[2] = neo4j_map_entry("entry_node", neo4j_string("ENTRY:"));

    statement =
        "MATCH (p:Entry) WHERE p.program_name=$program_name AND p.function_name=$function_name AND p.instruction CONTAINS $entry_node RETURN  p.dbgID";

    params = neo4j_map(mapEntries, 3);

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // Func dbg ID
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);
    }
    if (dbgID.empty())
        errs() << "\t Failed to find function dbg id: " << functionName << "\n";

    neo4j_close_results(results);
    neo4j_close(connection);
    return dbgID;
}

std::string UnsafePtrAnalyzer::getFunctionUsingDebugInfo(std::string debugInfo)
{
    std::string statement;
    std::string field_string;
    std::string functionName = "";

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t functionNameValue;

    neo4j_map_entry_t mapEntries[3];
    neo4j_result_stream_t *results;
    neo4j_result_t *record;
    neo4j_value_t params;

    if (debugInfo.empty())
        return functionName;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("function_name", neo4j_string(debugInfo.c_str()));
    mapEntries[2] = neo4j_map_entry("entry_node", neo4j_string("ENTRY:"));

    statement =
        "MATCH (p:Entry) WHERE p.program_name=$program_name AND p.dbgID=$function_name AND p.instruction CONTAINS $entry_node RETURN  p.function_name";

    params = neo4j_map(mapEntries, 3);

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // Func dbg ID
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);
    }
    if (functionName.empty())
        errs() << "\t Failed to find function dbg id\n";

    neo4j_close_results(results);
    neo4j_close(connection);
    return functionName;
}

void UnsafePtrAnalyzer::fetchOOBStatesAndAnalyze()
{

    // Step 1 - Fetch all OOB states (GEP)
    std::string statement;
    std::string functionName;
    std::string instructionString;
    std::string unsafeOOBStateID;
    std::string dbgID;
    std::map<std::string, Instruction *> unsafeOOBIDToInstruction;
    // Unsafe oob state ID to sources (unsafe objects)
    std::map<std::string, std::set<Instruction *>> unsafeOOBStatesToSources;
    std::set<std::string> unsafeOOBStateIDS;
    std::set<Instruction *> unsafeOOBInsts;
    Instruction *unsafeOOBInstruction = NULL;
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t stateTypeValue;

    neo4j_map_entry_t mapEntries[2];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    FunctionScanPass *functionScanPass = NULL;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    stateTypeValue = neo4j_string(UNSAFE_POINTER_STATE_TYPE);
    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("oob_state_type", stateTypeValue);
    params = neo4j_map(mapEntries, 2);

    std::string currFunctionName = "";
    std::string functionDebugInfo;
    std::string currentFuncDI;
    Function *function = nullptr;
    bool functionFound = false;

    statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND  a.state_type=$oob_state_type  AND (NOT (:AttackGraphNode)-[:SOURCE]->(a)) RETURN p.dbgID, p.function_name, a.id, p.instruction ORDER BY p.function_name";

    results = neo4j_run(connection, statement.c_str(), params);

    std::string currInstString;
    llvm::raw_string_ostream rso(currInstString);
    std::set<std::string> potentialMatches;

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First dbgID
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);
        // Second function
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);
        // Third ag ID
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        unsafeOOBStateID = std::string(field);
        unsafeOOBStateID = unsafeOOBStateID.substr(1, unsafeOOBStateID.length() - 2);
        unsafeOOBStateIDS.insert(unsafeOOBStateID);
        // Fourth instruction string
        neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);

        unsafeOOBInstruction = nullptr;

        if (functionName.compare(currFunctionName) != 0)
        {
            functionDebugInfo = getFunctionDebugInfo(functionName);
            function = module->getFunction(functionName);
            currentFuncDI.clear();
            functionFound = false;
            if (function)
            {
                DISubprogram *subprogram = function->getSubprogram();
                if (!subprogram)
                {
                    errs() << "\t No func DI exiting\n";
                    exit(1);
                }
                currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
            }

            if (currentFuncDI.compare(functionDebugInfo) != 0)
            {
                // Find the function
                for (auto &func : module->functions())
                {
                    DISubprogram *subprogram = func.getSubprogram();
                    if (!subprogram)
                        continue;
                    currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
                    if (currentFuncDI.compare(functionDebugInfo) == 0)
                    {
                        function = &func;
                        functionFound = true;
                        break;
                    }
                }
            }
            else
                functionFound = true;

            if (!functionFound)
            {
                errs() << "\t Failed to find function:" << functionName << ":" << functionDebugInfo << "\n";
                //                exit(1);
                continue;
            }
            functionScanPass = &getAnalysis<FunctionScanPass>(*function);
            currFunctionName = functionName;
        }

        instructionString = processStringEscapeCharacters(instructionString);

        unsafeOOBInstruction = functionScanPass->findInstructionUsingDBGID(
            dbgID);

        if (!unsafeOOBInstruction)
        {
            potentialMatches = functionScanPass->findInstructionIRUsingDBGID(dbgID);

            //            errs() << "\t Multiple matching geps need to use IR:" << instructionString << ":" << functionName << ":"
            //                   << potentialMatches.size() <<
            //                   "\n";

            for (auto potentialMatchInstString : potentialMatches)
            {
                if (instructionString.compare(potentialMatchInstString) == 0)
                {
                    // Match
                    // errs() << instructionString << "==" << potentialMatchInstString << "\n";

                    unsafeOOBInstruction = functionScanPass->instructionIRToInstMap[instructionString];
                    break;
                }
                else if (GetElementPtrInst *tempGEP = dyn_cast<GetElementPtrInst>(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                {
                    unsafeOOBInstruction = tempGEP;
                }
                else if (hasConstantGEP(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                {
                    unsafeOOBInstruction = functionScanPass->instructionIRToInstMap[potentialMatchInstString];
                }
            }
        }

        if (!unsafeOOBInstruction)
        {
            errs() << "\t Failed to find inst :" << instructionString << ":" << functionName << ":" << dbgID << "\n";
            errs() << "\t\t # DBG ID based IR matches found :" << potentialMatches.size() << "\n";
            //            exit(1);
            continue;
        }

        unsafeOOBInsts.insert(unsafeOOBInstruction);
        // Can remove it from the set since we already found it
        unsafeOOBIDToInstruction[unsafeOOBStateID] = unsafeOOBInstruction;

        memset(field, 0, 500);
        unsafeOOBStateID.clear();
    }

    neo4j_close_results(results);
    neo4j_close(connection);

    errs() << "# unsafe ptr states sources found :" << unsafeOOBInsts.size() << "=="
           << unsafeOOBIDToInstruction.size()
           << "\n";
    if (unsafeOOBStateIDS.empty())
        return;

    alias::PTAWrapper &ptaw = alias::PTAWrapper::getInstance();

    ptaw.setupPTA(*module);

    // Step 2 - Find corresponding stack objects
    std::set<Instruction *> dataSources;
    DILocation *loc = NULL;
    std::string instructionDbgID;
    // TODO - deal with these escape characters and name mangling later
    bool canHandle = true;

    for (auto idInstPair : unsafeOOBIDToInstruction)
    {
        if (!idInstPair.second)
            continue;
        auto gepInst = dyn_cast<GetElementPtrInst>(idInstPair.second);
        dataSources = findStackDataSource(gepInst);
        if (dataSources.empty())
        {
            // loc = gepInst->getDebugLoc();
            // //            errs() << "\t Failed to find data source:" << idInstPair.first << ":" << *gepInst << "\n";
            // if (loc)
            // {
            //     instructionDbgID = loc->getFilename();
            //     instructionDbgID =
            //         instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" +
            //         std::to_string(loc->getColumn());
            //     //                errs() << "\t Failed to find data source:" << instructionDbgID << "\n";
            // }
            //            exit(1);
            errs() << "\t Stack objects not found\n";
        }
        else
        {
            /* canHandle = true;
            currInstString.clear();
            for (auto dataSource : dataSources)
            {
                rso << *dataSource;
                if (currInstString.find("\"") != std::string::npos)
                {
                    canHandle = false;
                    break;
                }
                currInstString.clear();
            }
            if (canHandle) */
            unsafeOOBStatesToSources[idInstPair.first] = dataSources;
        }
    }

    // Step 4 - Update DB
    neo4j_map_entry_t secondQueryMapEntries[3];
    neo4j_value_t unsafeObjectStateTypeValue;
    neo4j_value_t unsafeObjectIDValue;

    std::string unsafeObjectAGID;
    // To avoid creating duplicate AG nodes (AG to pdg always 1:1)
    std::map<std::string, std::string> pdgLabelToAttackGraphNodeID;
    programNameValue = neo4j_string(programName.c_str());
    stateTypeValue = neo4j_string(STATE_TYPE);
    unsafeObjectStateTypeValue = neo4j_string(UNSAFE_STACK_OBJECT);

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    //    errs() << "Can handle sources found for " << unsafeOOBStatesToSources.size() << "\n";

    for (auto mapIt : unsafeOOBStatesToSources)
    {

        // Find the pdg labels corresponding to the data sources  and connect them
        for (auto source_it : mapIt.second)
        {
            //            errs() << "\t Trying to find:" << *source_it << ":" << source_it->getFunction()->getName() << "\n";
            auto pdg_label = findProgramInstructionInPDG(source_it);
            if (pdg_label.empty())
            {
                errs() << "Failed to find inst in DB:" << *source_it << "\n";
                continue;
            }
            if (pdgLabelToAttackGraphNodeID.find(pdg_label) == pdgLabelToAttackGraphNodeID.end())
            {
                // Create the new AG node for the unsafe object
                errs() << "\t Creating source ag node for obj " << *source_it << ":" << source_it->getFunction() << "\n";
                statement = "CREATE (a:AttackGraphNode{id:randomUUID(),type:$state_type,program_name:$program_name,state_type:$unsafe_object_state_type}) RETURN  a.id";

                secondQueryMapEntries[0] = neo4j_map_entry("program_name", programNameValue);
                secondQueryMapEntries[1] = neo4j_map_entry("unsafe_object_state_type", unsafeObjectStateTypeValue);
                secondQueryMapEntries[2] = neo4j_map_entry("state_type", stateTypeValue);
                params = neo4j_map(secondQueryMapEntries, 3);
                results = neo4j_run(connection, statement.c_str(), params);
                while ((record = neo4j_fetch_next(results)) != NULL)
                {
                    // ag ID
                    neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
                    unsafeObjectAGID = std::string(field);
                    unsafeObjectAGID = unsafeObjectAGID.substr(1, unsafeObjectAGID.length() - 2);
                    memset(field, 0, 500);
                }

                neo4j_close_results(results);
                pdgLabelToAttackGraphNodeID[pdg_label] = unsafeObjectAGID;
                // Connect ag node to pdg node (unsafe object)
                unsafeObjectIDValue = neo4j_string(unsafeObjectAGID.c_str());
                secondQueryMapEntries[0] = neo4j_map_entry("unsafe_object_id", unsafeObjectIDValue);
                secondQueryMapEntries[1] = neo4j_map_entry("label", neo4j_string(pdg_label.c_str()));
                statement = "MATCH (unsafeObjectState:AttackGraphNode) WHERE unsafeObjectState.id=$unsafe_object_id WITH unsafeObjectState MATCH (p:ProgramInstruction) WHERE p.label=$label WITH unsafeObjectState,p MERGE (unsafeObjectState)-[e:EDGE]->(p) ";
                params = neo4j_map(secondQueryMapEntries, 2);
                results = neo4j_run(connection, statement.c_str(), params);
                neo4j_close_results(results);
            }
            else
            {
                unsafeObjectAGID = pdgLabelToAttackGraphNodeID[pdg_label];
            }

            // Now connect each unsafe object (source) to the OOB state through a special edge

            unsafeObjectIDValue = neo4j_string(unsafeObjectAGID.c_str());
            secondQueryMapEntries[0] = neo4j_map_entry("unsafe_object_id", unsafeObjectIDValue);
            secondQueryMapEntries[1] = neo4j_map_entry("oob_state_id", neo4j_string(mapIt.first.c_str()));

            statement = "MATCH (unsafeObject:AttackGraphNode) WHERE unsafeObject.id=$unsafe_object_id  WITH unsafeObject MATCH (oobState:AttackGraphNode) WHERE oobState.id=$oob_state_id MERGE (unsafeObject)-[e:SOURCE]->(oobState) ";

            params = neo4j_map(secondQueryMapEntries, 2);
            results = neo4j_run(connection, statement.c_str(), params);
            neo4j_close_results(results);
        }
    }

    neo4j_close(connection);
}

void UnsafePtrAnalyzer::fetchPotentialStackOOBStatesAndAnalyze()
{
    // Step 1 - Fetch all may point to stack OOB states (GEP)
    std::string statement;
    std::string functionName;
    std::string instructionString;
    std::string unsafeOOBStateID;
    std::string dbgID;
    std::map<std::string, Instruction *> unsafeOOBIDToInstruction;
    std::set<std::string> unsafeOOBStateIDS;
    std::set<Instruction *> unsafeOOBInsts;
    std::map<std::string, std::set<Instruction *>> unsafeOOBStatesToSources;
    Instruction *unsafeOOBInstruction = NULL;
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t stateTypeValue;

    neo4j_map_entry_t mapEntries[2];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    FunctionScanPass *functionScanPass = NULL;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    stateTypeValue = neo4j_string(UNSAFE_MAYBE_STACK_OOB_STATE_TYPE);
    // stateTypeValue = neo4j_string("71");
    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("oob_state_type", stateTypeValue);
    params = neo4j_map(mapEntries, 2);

    statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND  a.state_type=$oob_state_type RETURN p.dbgID, p.function_name, a.id, p.instruction ORDER BY p.function_name";

    std::string currFunctionName = "";
    std::string functionDebugInfo;
    std::string currentFuncDI;
    Function *function = nullptr;
    bool functionFound = false;
    std::set<std::string> potentialMatches;

    results = neo4j_run(connection, statement.c_str(), params);

    std::string currInstString;
    llvm::raw_string_ostream rso(currInstString);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First dbgID
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);
        // Second function
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);
        // Third ag ID
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        unsafeOOBStateID = std::string(field);
        unsafeOOBStateID = unsafeOOBStateID.substr(1, unsafeOOBStateID.length() - 2);
        unsafeOOBStateIDS.insert(unsafeOOBStateID);
        // Fourth instruction string
        neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);

        unsafeOOBInstruction = NULL;
        if (functionName.compare(currFunctionName) != 0)
        {
            functionDebugInfo = getFunctionDebugInfo(functionName);
            function = module->getFunction(functionName);
            currentFuncDI.clear();
            functionFound = false;
            if (function)
            {
                DISubprogram *subprogram = function->getSubprogram();
                if (!subprogram)
                {
                    errs() << "\t No func DI exiting\n";
                    exit(1);
                }
                currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
            }

            if (currentFuncDI.compare(functionDebugInfo) != 0)
            {
                // Find the function
                for (auto &func : module->functions())
                {
                    DISubprogram *subprogram = func.getSubprogram();
                    if (!subprogram)
                        continue;
                    currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
                    if (currentFuncDI.compare(functionDebugInfo) == 0)
                    {
                        function = &func;
                        functionFound = true;
                        break;
                    }
                }
            }
            else
                functionFound = true;

            if (!functionFound)
            {
                errs() << "\t Failed to find function:" << functionName << ":" << functionDebugInfo << "\n";
                //                exit(1);
                continue;
            }
            functionScanPass = &getAnalysis<FunctionScanPass>(*function);
            currFunctionName = functionName;
        }

        instructionString = processStringEscapeCharacters(instructionString);

        unsafeOOBInstruction = functionScanPass->findInstructionUsingDBGID(
            dbgID);

        if (!unsafeOOBInstruction)
        {
            // unsafeOOBInstruction = findInstructionInFunctionUsingIR(instructionString, function);

            potentialMatches = functionScanPass->findInstructionIRUsingDBGID(dbgID);

            //            errs() << "\t Multiple matching geps need to use IR:" << instructionString << ":" << functionName << ":"
            //                   << potentialMatches.size() <<
            //                   "\n";

            for (auto potentialMatchInstString : potentialMatches)
            {
                if (instructionString.compare(potentialMatchInstString) == 0)
                {
                    // Match
                    //                    errs() << instructionString << "==" << potentialMatchInstString << "\n";

                    unsafeOOBInstruction = functionScanPass->instructionIRToInstMap[instructionString];
                    break;
                }
            }
        }

        if (!unsafeOOBInstruction)
        {
            errs() << "\t Failed to find inst :" << instructionString << ":" << functionName << ":" << dbgID << "\n";
            errs() << "\t\t # DBG ID based IR matches found :" << potentialMatches.size() << "\n";
            //            exit(1);
            // continue;
        }

        if (!unsafeOOBInstruction)
            continue;
        unsafeOOBInsts.insert(unsafeOOBInstruction);
        // Can remove it from the set since we already found it
        unsafeOOBIDToInstruction[unsafeOOBStateID] = unsafeOOBInstruction;

        memset(field, 0, 500);
        unsafeOOBStateID.clear();
    }

    neo4j_close_results(results);
    neo4j_close(connection);

    errs() << "# may point to stack unsafe OOB  sources found :" << unsafeOOBInsts.size() << "=="
           << unsafeOOBIDToInstruction.size()
           << "\n";
    if (unsafeOOBStateIDS.empty())
        return;

    /* alias::PTAWrapper &ptaw = alias::PTAWrapper::getInstance();
    ptaw.setupPTA(*module); */

    // Step 2 - Find corresponding stack objects
    std::set<Instruction *> dataSources;
    for (auto idInstPair : unsafeOOBIDToInstruction)
    {
        auto gepInst = dyn_cast<GetElementPtrInst>(idInstPair.second);
        dataSources = findStackDataSource(gepInst);
        if (dataSources.empty())
        {
            errs() << "\t Failed to find data source check manually:" << *gepInst << "\n";
            // gepInst->getDebugLoc().print(errs());
            errs() << "\n";
        }
        else
        {
            unsafeOOBStatesToSources[idInstPair.first] = dataSources;
        }
    }

    // TODO - Update this to delete the node if confirmed that it does not point to a stack object
    // Step 4 - Update DB
    neo4j_map_entry_t secondQueryMapEntries[3];
    neo4j_value_t unsafeObjectIDValue;

    std::string unsafeObjectAGID;

    programNameValue = neo4j_string(programName.c_str());

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    errs() << "# Genuine may point to stack (i.e stack sources found):" << unsafeOOBStatesToSources.size() << "\n";

    // To avoid creating duplicate AG nodes (AG to pdg always 1:1)
    std::map<std::string, std::string> pdgLabelToAttackGraphNodeID;
    for (auto mapIt : unsafeOOBStatesToSources)
    {
        // Find the pdg labels corresponding to the data sources  and connect them
        for (auto source_it : mapIt.second)
        {
            auto pdg_label = findProgramInstructionInPDG(source_it);
            if (pdg_label.empty())
            {
                errs() << "Failed to find obj inst in DB:" << *source_it << "\n";
                continue;
            }

            if (pdgLabelToAttackGraphNodeID.find(pdg_label) == pdgLabelToAttackGraphNodeID.end())
            {
                // Find or else will create both node and rel
                unsafeObjectAGID = findLogicalNodeInDBForUnsafeObject(pdg_label);
                pdgLabelToAttackGraphNodeID[pdg_label] = unsafeObjectAGID;
            }
            else
            {
                unsafeObjectAGID = pdgLabelToAttackGraphNodeID[pdg_label];
            }
            unsafeObjectIDValue = neo4j_string(unsafeObjectAGID.c_str());
        }

        // Now connect the unsafe object (source) to the OOB state through a special edge
        statement = "MATCH (unsafeObject:AttackGraphNode) WHERE unsafeObject.id=$unsafe_object_id  WITH unsafeObject MATCH (oobState:AttackGraphNode) WHERE oobState.id=$oob_state_id MERGE (unsafeObject)-[e:SOURCE]->(oobState)  ";
        secondQueryMapEntries[0] = neo4j_map_entry("unsafe_object_id", unsafeObjectIDValue);
        secondQueryMapEntries[1] = neo4j_map_entry("oob_state_id", neo4j_string(mapIt.first.c_str()));

        params = neo4j_map(secondQueryMapEntries, 2);
        results = neo4j_run(connection, statement.c_str(), params);
        neo4j_close_results(results);

        // Also update oob state type to stack unsafe ptr
        statement = "MATCH (oobState:AttackGraphNode) WHERE oobState.id=$oob_state_id SET oobState.state_type=$oob_state_type  ";
        secondQueryMapEntries[0] = neo4j_map_entry("oob_state_id", neo4j_string(mapIt.first.c_str()));
        secondQueryMapEntries[1] = neo4j_map_entry("oob_state_type", neo4j_string(UNSAFE_POINTER_STATE_TYPE));

        params = neo4j_map(secondQueryMapEntries, 2);
        results = neo4j_run(connection, statement.c_str(), params);
        neo4j_close_results(results);
    }

    neo4j_close(connection);
}

std::string
UnsafePtrAnalyzer::findProgramInstructionInPDG(Instruction *instruction)
{
    std::string statement;
    std::string instructionString;
    std::string pdgLabel = "";
    std::string functionName = "";
    // Set a hard character limit on any field returned from the query
    char *field = (char *)malloc(sizeof(char) * 500);
    raw_string_ostream rso(instructionString);
    neo4j_connection_t *connection;
    neo4j_value_t instructionValue;
    neo4j_value_t programNameValue;
    neo4j_value_t functionNameValue;
    neo4j_value_t dbgIDValue;
    neo4j_map_entry_t mapEntries[4];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    std::string currentFunctionDI = "";
    std::string functionDebugInfoDB;

    if (!instruction)
        return "";
    rso << *instruction;
    instructionString = addNecessaryEscapeCharacters(instructionString);

    if (instruction->getFunction())
    {
        DISubprogram *subprogram = instruction->getFunction()->getSubprogram();
        if (!subprogram)
        {
            errs() << "\t No func DI exiting\n";
            return instructionString;
        }
        currentFunctionDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
        functionName = instruction->getFunction()->getName();
        functionDebugInfoDB = getFunctionDebugInfo(functionName);
    }

    if ((!currentFunctionDI.empty()) && (!functionDebugInfoDB.empty()))
    {
        if (currentFunctionDI.compare(functionDebugInfoDB) != 0)
        {

            functionName = getFunctionUsingDebugInfo(currentFunctionDI);
        }
    }
    if (functionName.empty())
    {
        errs() << "\t Failed to find function (db name):" << functionName << ":" << currentFunctionDI << "\n";
        return instructionString;
    }

    instructionValue = neo4j_string(instructionString.c_str());
    functionNameValue = neo4j_string(functionName.c_str());
    programNameValue = neo4j_string(programName.c_str());
    dbgIDValue = neo4j_string(getDebugID(instruction).c_str());

    mapEntries[0] = neo4j_map_entry("instruction", instructionValue);
    mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[2] = neo4j_map_entry("function_name", functionNameValue);
    mapEntries[3] = neo4j_map_entry("dbgID", dbgIDValue);

    params = neo4j_map(mapEntries, 4);
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    // statement = " MATCH (p:ProgramInstruction) WHERE p.instruction ="
    //             "$instruction AND p.function_name=$function_name AND "
    //             "p.program_name=$program_name  RETURN p.label";

    statement = "MERGE (p:ProgramInstruction{dbgID:$dbgID, instruction:$instruction, function_name:$function_name, program_name:$program_name}) ON CREATE SET p.label=randomUUID() RETURN p.label ";

    results = neo4j_run(connection, statement.c_str(), params);

    // There should only be one record
    if ((record = neo4j_fetch_next(results)) != NULL)
    {
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        pdgLabel = std::string(field);
        pdgLabel = pdgLabel.substr(1, pdgLabel.length() - 2);
    }
    else
    {
        errs() << "Failed to obtain record:" << instructionString << ":" << functionName << ":" << programName << "\n";
        //        continue;
        // exit(1);
    }
    neo4j_close_results(results);
    neo4j_close(connection);
    currentFunctionDI.clear();
    return pdgLabel;
}

std::string
UnsafePtrAnalyzer::findLogicalNodeInDBForUnsafeObject(std::string pdgLabel)
{
    std::string statement;
    std::string logicalNodeID;
    // Set a hard character limit on any field returned from the query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t stateTypeValue;
    neo4j_value_t unsafeObjectStateTypeValue;
    neo4j_value_t pdgLabelValue;
    neo4j_map_entry_t mapEntries[4];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    programNameValue = neo4j_string(programName.c_str());
    stateTypeValue = neo4j_string(STATE_TYPE);
    unsafeObjectStateTypeValue = neo4j_string(UNSAFE_STACK_OBJECT);
    pdgLabelValue = neo4j_string(pdgLabel.c_str());

    mapEntries[0] = neo4j_map_entry("state_type", stateTypeValue);
    mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[2] = neo4j_map_entry("unsafe_object_state_type", unsafeObjectStateTypeValue);
    mapEntries[3] = neo4j_map_entry("label", pdgLabelValue);

    params = neo4j_map(mapEntries, 4);
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    statement = "MATCH (p:ProgramInstruction) WHERE p.label=$label WITH p MERGE (a:AttackGraphNode{type:$state_type,program_name:$program_name,state_type:$unsafe_object_state_type})-[:EDGE]->(p) ON CREATE SET a.id=randomUUID()  RETURN  a.id";

    results = neo4j_run(connection, statement.c_str(), params);

    // There should only be one record
    if ((record = neo4j_fetch_next(results)) != NULL)
    {
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        logicalNodeID = std::string(field);
        logicalNodeID = logicalNodeID.substr(1, logicalNodeID.length() - 2);
    }
    else
    {
        errs() << "Failed to obtain record:" << pdgLabel << ":" << programName << "\n";
        //        continue;
        // exit(1);
    }
    neo4j_close_results(results);
    neo4j_close(connection);
    return logicalNodeID;
}

bool UnsafePtrAnalyzer::runOnModule(Module &M)
{

    programName = M.getModuleIdentifier();
    programName = programName.substr(0, programName.length() - 3);
    module = &M;
    if (PRUNE_MAY_POINT_TO_STACK_OOBS)
        fetchPotentialStackOOBStatesAndAnalyze();
    else
        fetchOOBStatesAndAnalyze();
    return false;
}

void UnsafePtrAnalyzer::getAnalysisUsage(AnalysisUsage &AU) const
{
    AU.addRequired<FunctionScanPass>();
    AU.setPreservesAll();
}

char UnsafePtrAnalyzer::ID = 0;
static RegisterPass<UnsafePtrAnalyzer>
    Y("analyze-oob", "Analyze the potential OOB instructions found by dataguard", false, true);
