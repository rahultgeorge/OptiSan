#include "TargetAnalysis.h"

UsableTargetsAnalysis::UsableTargetsAnalysis() : ModulePass(ID) {}

inline UPAType UsableTargetsAnalysis::isInterestingUPAType(std::string upaType)
{
    // We only care about stack PMIs and write UPAs
    if (upaType.compare(UNSAFE_POINTER_PROPAGATION_STACK_ACTION_TYPE) == 0)
        return UPAType::UPAPropagationStack;
    else if (upaType.compare(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE) == 0)
        return UPAType::UPAStackWrite;
    else if (upaType.compare(UNSAFE_POINTER_READ_STACK_ACTION_TYPE) == 0)
        return UPAType::UPAStackRead;
    return UPAType::None;
}

inline std::string upaTypeToString(UPAType upaType)
{
    // We only care about stack PMIs and write UPAs
    if (upaType == UPAType::UPAPropagationStack)
        return UNSAFE_POINTER_PROPAGATION_STACK_ACTION_TYPE;
    else if (upaType == UPAType::UPAStackWrite)
        return UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE;
    else if (upaType == UPAType::UPAStackRead)
        return UNSAFE_POINTER_READ_STACK_ACTION_TYPE;
    return "";
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

inline std::string getFunctionDebugInfo(std::string functionName, std::string programName)
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

    // PDG all faux nodes - entry nodes will be labeled as Entry
    //  statement =
    //      "MATCH (p:ProgramInstruction) WHERE p.program_name=$program_name AND p.function_name=$function_name AND p.instruction CONTAINS $entry_node RETURN  p.dbgID";

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
        errs() << "\t Failed to find function dbg id\n";

    neo4j_close_results(results);
    neo4j_close(connection);
    return dbgID;
}

bool UsableTargetsAnalysis::runOnModule(Module &M)
{
    // Initialization
    _module = &M;
    programName = M.getModuleIdentifier();
    programName = programName.substr(0, programName.length() - 3);
    errs() << "Usable targets pass:" << programName << "\n";

    // Initialize connection to the db
    neo4j_client_init();

    // Step 1 - Fetch relevant UPAs filtered using isInterestingUPAType
    fetchUnsafeMemoryOperations();
    if (upaActions.empty())
        return false;

    // Ref to intra target analysis
    intraTargetAnalysisPass = &getAnalysis<IntraTargetAnalysisPass>();

    // Step 3 - Construct call graph and reachability graphs
    // _callGraph = &getAnalysis<CallGraphWrapperPass>().getCallGraph();

    for (auto &func : _module->functions())
    {
        if (func.isDeclaration() || func.isIntrinsic())
            continue;
    }

    // Step 4 - Compute targets
    InstructionStringMap upaWriteActionsMap = upaActions[UPAType::UPAStackWrite];

    errs() << "Stack unsafe store operations found:" << upaWriteActionsMap.size() << "\n";
    for (auto it = upaWriteActionsMap.begin(); it != upaWriteActionsMap.end(); it++)
    {
        errs() << "Unsafe store operation:" << *it->first << " in function: " << it->first->getFunction()->getName() << "\n";
        computeUsableTargets(it->first, UPAType::UPAStackWrite);
    }

    InstructionStringMap upaReadActionsMap = upaActions[UPAType::UPAStackRead];

    errs() << "Stack unsafe load operations found:" << upaReadActionsMap.size() << "\n";
    for (auto it = upaReadActionsMap.begin(); it != upaReadActionsMap.end(); it++)
    {
        errs() << "Unsafe load operation:" << *it->first << " in function: " << it->first->getFunction()->getName() << "\n";
        computeUsableTargets(it->first, UPAType::UPAStackRead);
    }
    errs() << "\t # Total usable targets:" << totalTargets << "\n";

    neo4j_client_cleanup();
    return false;
}

void UsableTargetsAnalysis::computeUsableTargets(Instruction *unsafeMemoryOperation,
                                                 UPAType upaType)
{
    bool mayUnderFlow = false;
    int numOfUsableTargetsForUnsafeOperation = 0;
    std::string actionID = upaActions[upaType][unsafeMemoryOperation];
    Function *functionContainingUnsafeOperation = unsafeMemoryOperation->getFunction();
    Function *functionContainingUnsafeStackObject = NULL;
    InstructionSet usableTargetsInFunc;
    std::set<std::string> usableTargetObjectStateIDs;
    std::queue<FunctionInstPairTy> workList;
    std::set<Function *> candidateTargetFunctions;
    std::set<FunctionInstPairTy> functionToPointPairsSeen;
    std::set<Instruction *> unsafeStackOjects;

    if (unsafeOperationIDToUnsafeObjects.find(actionID) == unsafeOperationIDToUnsafeObjects.end())
        unsafeStackOjects = _results->getUnsafeObjectsForAccess(unsafeMemoryOperation);
    else
        unsafeStackOjects = unsafeOperationIDToUnsafeObjects[actionID];

    if (unsafeStackOjects.empty())
    {
        // errs() << "\t No obj for unsafe operation found:" << *unsafeMemoryOperation << "\n";
        auto tmpInst = functionContainingUnsafeOperation->getFunction().getEntryBlock().getFirstNonPHI();
        if (tmpInst)
            unsafeStackOjects.insert(const_cast<Instruction *>(tmpInst));
        // return;
    }

    // Compute overflow targets
    for (auto obj : unsafeStackOjects)
    {
        // errs() << "\t" << *obj << "\n";
        functionContainingUnsafeStackObject = obj->getFunction();

        if (allStackFramesWithLastFunctionUsableTargetsCache.find(functionContainingUnsafeStackObject) != allStackFramesWithLastFunctionUsableTargetsCache.end() && upaType == UPAType::UPAStackWrite)
        {
            // Cache hit i.e., we've analyzed all possible stack frames with this function on top (last frame)
            usableTargetsInFunc = allStackFramesWithLastFunctionUsableTargetsCache[functionContainingUnsafeStackObject];
        }
        else
        {
            // We initialize with all possible immediate callers - the relevant call sites
            for (auto callSite : findAllPossiblePreviousCallers(functionContainingUnsafeStackObject))
                workList.push(FunctionInstPairTy(callSite->getFunction(), callSite));

            // Identify all possible frames/call strings along with the points/edges
            while (!workList.empty())
            {
                auto functionInstPair = workList.front();
                if (functionToPointPairsSeen.find(functionInstPair) != functionToPointPairsSeen.end())
                {
                    workList.pop();
                    continue;
                }
                // errs() << "\t " << functionInstPair.first->getName() << ": \n\t\t" << *functionInstPair.second << "\n";
                functionToPointPairsSeen.insert(functionInstPair);
                candidateTargetFunctions.insert(functionInstPair.first);
                auto currFuncGraph = intraTargetAnalysisPass->getCFG(*functionInstPair.first);
                currFuncGraph->addUnsafePoint(functionInstPair.second);

                // Check cache to see if we know all usable targets for all frames/call strings ending with this function
                if (allStackFramesWithLastFunctionUsableTargetsCache.find(functionInstPair.first) != allStackFramesWithLastFunctionUsableTargetsCache.end() && upaType == UPAType::UPAStackWrite)
                {
                    auto cachedUsableTargetsForAllPossibleFrames = allStackFramesWithLastFunctionUsableTargetsCache[functionInstPair.first];
                    for (auto target : cachedUsableTargetsForAllPossibleFrames)
                        usableTargetsInFunc.insert(target);
                    workList.pop();
                    continue;
                }

                for (auto callSite : findAllPossiblePreviousCallers(functionInstPair.first))
                {
                    workList.push(FunctionInstPairTy(callSite->getFunction(), callSite));
                }
                workList.pop();
            }

            errs() << "\t Done identifying all call strings ending with: " << functionContainingUnsafeStackObject->getName() << "\n";

            // Compute (overflow) targets given
            computeUsableTargetsHelper(upaType, candidateTargetFunctions, usableTargetsInFunc);
            allStackFramesWithLastFunctionUsableTargetsCache[functionContainingUnsafeStackObject] = usableTargetsInFunc;
            candidateTargetFunctions.clear();
        }

        // We deal with the local usable targets in function containing unsafe object here to enable caching
        auto currFuncGraph = intraTargetAnalysisPass->getCFG(*functionContainingUnsafeStackObject);
        candidateTargetFunctions.insert(functionContainingUnsafeStackObject);
        if (functionContainingUnsafeOperation == functionContainingUnsafeStackObject)
        {
            currFuncGraph->addUnsafePoint(unsafeMemoryOperation);
            functionToPointPairsSeen.insert(FunctionInstPairTy(functionContainingUnsafeStackObject, unsafeMemoryOperation));
        }
        else
        {
            for (auto callSite : findRelevantCallSitesInSourceToSink(functionContainingUnsafeStackObject, functionContainingUnsafeOperation))
            {
                currFuncGraph->addUnsafePoint(callSite);
                functionToPointPairsSeen.insert(FunctionInstPairTy(functionContainingUnsafeStackObject, callSite));
            }
            mayUnderFlow = true;
        }

        // Compute  local targets (func containing unsafe object)
        computeUsableTargetsHelper(upaType, candidateTargetFunctions, usableTargetsInFunc);

        // Save all overflow including local targets (in DB)
        analyzeUsableTargets(usableTargetsInFunc, usableTargetObjectStateIDs);
        numOfUsableTargetsForUnsafeOperation += usableTargetsInFunc.size();
        candidateTargetFunctions.clear();
        usableTargetsInFunc.clear();
    }

    // We deal with underflow here
    if (mayUnderFlow)
        computeUsableTargetsThroughUnderflow(unsafeMemoryOperation, upaType, functionToPointPairsSeen, candidateTargetFunctions);

    // Compute underflow targets
    computeUsableTargetsHelper(upaType, candidateTargetFunctions, usableTargetsInFunc);
    numOfUsableTargetsForUnsafeOperation += usableTargetsInFunc.size();
    errs() << "\t\t # usable targets found (overflow + underflow ) :" << numOfUsableTargetsForUnsafeOperation << "\n";

    // Save underflow targets in DB
    analyzeUsableTargets(usableTargetsInFunc, usableTargetObjectStateIDs);
    // Connect unsafe operation to all usable targets (underflow + overflow)
    connectActionAndStateTransactionBased(actionID, usableTargetObjectStateIDs);
}

void UsableTargetsAnalysis::computeUsableTargetsThroughUnderflow(Instruction *unsafeMemoryOperation, UPAType unsafeOperationType, std::set<std::pair<Function *, Instruction *>> &functionToPointPairsSeen, std::set<Function *> &candidateTargetFunctions)
{
    int numOfUsableTargetsForUnsafeOperation = 0;
    std::string actionID = upaActions[unsafeOperationType][unsafeMemoryOperation];
    std::set<Instruction *> unsafeStackOjects;
    std::set<FunctionReachabilityPointPairTy> underFlowFunctionsReachabilityPointPairs;
    InstructionSet usableTargetsInFunc;

    Function *functionContainingUnsafeOperation = unsafeMemoryOperation->getFunction();

    if (unsafeOperationIDToUnsafeObjects.find(actionID) == unsafeOperationIDToUnsafeObjects.end())
        unsafeStackOjects = _results->getUnsafeObjectsForAccess(unsafeMemoryOperation);
    else
        unsafeStackOjects = unsafeOperationIDToUnsafeObjects[actionID];

    for (auto obj : unsafeStackOjects)
    {

        auto functionContainingUnsafeStackObject = obj->getFunction();
        if (functionContainingUnsafeOperation != functionContainingUnsafeStackObject)
        {
            // errs() << "\t Source:" << functionContainingUnsafeStackObject->getName() << "->" << functionContainingUnsafeOperation->getName() << "\n";

            findAllFunctionsAlongPath(functionContainingUnsafeStackObject, functionContainingUnsafeOperation, underFlowFunctionsReachabilityPointPairs);

            // errs() << "# func point pairs found:" << underFlowFunctionsReachabilityPointPairs.size() << "\n";
            for (auto funcToPointPair : underFlowFunctionsReachabilityPointPairs)
            {
                // errs() << "\t " << funcToPointPair.first->getName() << " " << funcToPointPair.second << "\n";
                if (functionToPointPairsSeen.find(funcToPointPair) != functionToPointPairsSeen.end())
                {
                    // errs() << "\t\t Seen already\n";
                    continue;
                }
                functionToPointPairsSeen.insert(funcToPointPair);
                candidateTargetFunctions.insert(funcToPointPair.first);
                auto currFuncGraph = intraTargetAnalysisPass->getCFG(*funcToPointPair.first);
                currFuncGraph->addUnsafePoint(funcToPointPair.second);
            }
            underFlowFunctionsReachabilityPointPairs.clear();
        }
    }
}

void UsableTargetsAnalysis::computeUsableTargetsHelper(UPAType unsafeOperationType, std::set<Function *> &candidateTargetFunctions, InstructionSet &usableTargetsInFunc)
{
    if (!intraTargetAnalysisPass)
    {
        errs() << "Intra target analysis pass not initialized\n";
        exit(1);
    }
    errs() << "\t  Computing targets for candidate target functions : " << candidateTargetFunctions.size()
           << "\n";
    for (auto functionIt : candidateTargetFunctions)
    {
        errs() << "\t\t " << functionIt->getName() << "\n";
        intraTargetAnalysisPass->reduceUnsafePoints(functionIt);
        auto currFuncGraph = intraTargetAnalysisPass->getCFG(*functionIt);
        if (unsafeOperationType == UPAStackWrite)
            currFuncGraph->identifyUsableTargetsForUnsafePoints(usableTargetsInFunc);
        else if (unsafeOperationType == UPAStackRead)
            currFuncGraph->getAllTargets(usableTargetsInFunc);
        currFuncGraph->clearUnsafePoints();
    }
}

inline void UsableTargetsAnalysis::analyzeUsableTargets(const InstructionSet &usableTargets, std::set<std::string> &usableTargetObjectStateIDs)
{
    bool isImpactedObjectPointer;
    std::string pdgLabel;
    std::string stateID;

    AllocaInst *allocaInst = nullptr;
    for (auto object : usableTargets)
    {

        if (instToImpactedStatesCreated.find(object) == instToImpactedStatesCreated.end())
        {
            isImpactedObjectPointer = false;
            allocaInst = dyn_cast<AllocaInst>(object);
            if (!allocaInst)
            {
                // errs() << "\t ERROR stack object def invalid: " << *object << "\n";
                continue;
            }
            if (allocaInst->getAllocatedType()->isPointerTy())
            {
                isImpactedObjectPointer = true;
                // errs() << "\t Pointer on stack:" << *object << "\n";
            }

            // Update graph
            pdgLabel = findProgramInstructionInPDG(object);
            // Create a new attack state corresponding to this impacted object - ptr or data object
            if (isImpactedObjectPointer)
                stateID = createAttackState(IMPACTED_STACK_POINTER, pdgLabel);
            else
                stateID = createAttackState(IMPACTED_STACK_OBJECT, pdgLabel);

            instToImpactedStatesCreated[object] = stateID;
            usableTargetObjectStateIDs.insert(stateID);
        }
        else
            stateID = instToImpactedStatesCreated[object];

        usableTargetObjectStateIDs.insert(stateID);
    }
}

/*
 * Find all call sites in source that can reach sink
 * Making this a general method wherein X->......->Y
 * (any number of intermediate methods so find all appropriate call sites)
 */
InstructionSet UsableTargetsAnalysis::findRelevantCallSitesInSourceToSink(Function *sourceFunc, Function *sinkFunc)
{

    bool canSourceReachSinkFromCurrentCallSite;
    InstructionSet callSitesThatReach;
    FunctionSet callCandidates;
    Function *currentFunc = nullptr;
    Value *calleeOperand = nullptr;

    pdg::PDGCallGraph &call_g = pdg::PDGCallGraph::getInstance();

    if (sourceSinkPairToRelevantCallSitesInSource.find(std::pair<Function *, Function *>(sourceFunc, sinkFunc)) != sourceSinkPairToRelevantCallSitesInSource.end())
        return sourceSinkPairToRelevantCallSitesInSource[std::pair<Function *, Function *>(sourceFunc, sinkFunc)];

    assert(call_g.isBuild());
    auto sinkFuncCallGraphNode = call_g.getNode(*sinkFunc);

    for (inst_iterator I = inst_begin(sourceFunc), E = inst_end(sourceFunc); I != E; ++I)
    {
        canSourceReachSinkFromCurrentCallSite = false;
        if (CallInst *callSite = dyn_cast<CallInst>(&*I))
        {
            callCandidates.clear();
            calleeOperand = callSite->getCalledOperand();
            currentFunc = dyn_cast<Function>(calleeOperand->stripPointerCasts());

            if (currentFunc)
                callCandidates.insert(currentFunc);
            else
            {
                for (auto indirectCallee : call_g.getIndirectCallCandidates(*callSite, *_module))
                {
                    callCandidates.insert(indirectCallee);
                }
            }

            for (auto callee : callCandidates)
            {
                if (callee->isDeclaration() || callee->isIntrinsic())
                    continue;

                auto calleeNode = call_g.getNode(*callee);
                if (!calleeNode)
                {
                    errs() << "Call graph missing node:" << callee->getName() << "\n";
                    continue;
                }
                if (call_g.canReach(*calleeNode, *sinkFuncCallGraphNode))
                {
                    canSourceReachSinkFromCurrentCallSite = true;
                    break;
                }
            }
            if (canSourceReachSinkFromCurrentCallSite)
            {
                callSitesThatReach.insert(callSite);
            }
        }
    }

    if (callSitesThatReach.empty())
    {
        errs() << "Failed to find any call sites (Check for indirect calls):" << sourceFunc->getName() << "--" << sinkFunc->getName() << "\n";
        //        exit(1);
    }

    sourceSinkPairToRelevantCallSitesInSource[std::pair<Function *, Function *>(sourceFunc, sinkFunc)] = callSitesThatReach;
    return callSitesThatReach;
}

void UsableTargetsAnalysis::findAllFunctionsAlongPath(Function *sourceFunc, Function *sinkFunc, std::set<FunctionReachabilityPointPairTy> &functionReachabilityPointPairsSet)
{

    // FunctionSet visited;
    // std::set<CallGraphNode::CallRecord> visited;
    // std::queue<CallGraphNode::CallRecord> workList;
    // std::set<CallGraphNode::CallRecord> currentPath;

    std::set<Function *> visited;
    pdg::ProgramGraph &pdg = pdg::ProgramGraph::getInstance();
    pdg::PDGCallGraph &call_g = pdg::PDGCallGraph::getInstance();

    // TODO - Cache? Seems like too much since source, sink -> <Function*,Instruction*>
    /*     if (sourceSinkPairToIntermediateFunctions.find(std::pair<Function *, Function *>(sourceFunc, sinkFunc)) != sourceSinkPairToIntermediateFunctions.end())
        {
            for (auto func : sourceSinkPairToIntermediateFunctions[std::pair<Function *, Function *>(sourceFunc, sinkFunc)])
            {
                functionsAlongAllPaths.insert(func);
            }
            return;
        } */

    auto sourceNode = call_g.getNode(*sourceFunc);
    auto sinkNode = call_g.getNode(*sinkFunc);

    if (!call_g.canReach(*sourceNode, *sinkNode))
    {
        return;
    }

    // Initialization using all calls in source func
    auto sourceFW = pdg.getFuncWrapper(*sourceFunc);
    for (auto callInst : sourceFW->getCallInsts())
    {
        findAllFunctionsAlongPathHelper(callInst, sinkFunc, {}, visited, functionReachabilityPointPairsSet);
    }
}

void UsableTargetsAnalysis::findAllFunctionsAlongPathHelper(CallInst *currentNode, Function *sinkFunc, std::vector<CallInst *> currentPath, std::set<Function *> &visited, std::set<FunctionReachabilityPointPairTy> &functionReachabilityPointPairsSet)
{

    if (!currentNode || !currentNode->getFunction())
        return;

    if (visited.find(currentNode->getFunction()) != visited.end())
        return;

    // errs() << "Call inst:" << *currentNode << ":" << currentNode->getFunction()->getName() << "\n";

    visited.insert(currentNode->getFunction());
    currentPath.push_back(currentNode);

    Value *calleeOperand = nullptr;
    Function *calleeFunc = nullptr;
    FunctionSet callCandidates;

    pdg::ProgramGraph &pdg = pdg::ProgramGraph::getInstance();
    pdg::PDGCallGraph &call_g = pdg::PDGCallGraph::getInstance();

    calleeOperand = currentNode->getCalledOperand();
    if (calleeOperand)
        calleeFunc = dyn_cast<Function>(calleeOperand->stripPointerCasts());

    if (calleeFunc)
        callCandidates.insert(calleeFunc);
    else
    {
        for (auto indirectCallee : call_g.getIndirectCallCandidates(*currentNode, *_module))
        {
            callCandidates.insert(indirectCallee);
        }
    }

    bool foundPathsToSinkFromCallee;
    for (auto calleeFunc : callCandidates)
    {
        if (calleeFunc->isDeclaration() || calleeFunc->isIntrinsic())
            continue;
        if (calleeFunc == sinkFunc)
        {
            // Found a path
            for (auto callInstAlongPath : currentPath)
            {
                functionReachabilityPointPairsSet.insert(FunctionReachabilityPointPairTy(callInstAlongPath->getFunction(), callInstAlongPath));
            }
            continue;
        }

        foundPathsToSinkFromCallee = false;
        for (auto functionInstPointPairIt : functionReachabilityPointPairsSet)
        {
            if (functionInstPointPairIt.first == calleeFunc)
            {
                foundPathsToSinkFromCallee = true;
                break;
            }
        }

        if (foundPathsToSinkFromCallee)
        {
            // Reachable from this function we already processed
            for (auto callInstAlongPath : currentPath)
            {
                functionReachabilityPointPairsSet.insert(FunctionReachabilityPointPairTy(callInstAlongPath->getFunction(), callInstAlongPath));
            }
            continue;
        }

        auto calleeFuncW = pdg.getFuncWrapper(*calleeFunc);
        if (calleeFuncW)
        {
            for (auto callInst : calleeFuncW->getCallInsts())
            {
                findAllFunctionsAlongPathHelper(callInst, sinkFunc, currentPath, visited, functionReachabilityPointPairsSet);
            }
        }
    }
    currentPath.pop_back();
}

// Helper functions to interact with DB. Queries are simple, parameterized and short.

bool UsableTargetsAnalysis::cacheFunction(Function *function)
{
    std::string functionName = function->getName();
    std::string instructionString;
    std::string indexString;
    Instruction *inst;
    raw_string_ostream rso(instructionString);
    if (function == NULL || function->isIntrinsic() || function->empty())
        return false;

    for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; I++)
    {

        inst = &*I;
        if (!isa<AllocaInst>(inst))
            continue;
        rso << *inst;
        indexString = functionName + instructionString;
        cache[indexString] = inst;
        rso.flush();
        instructionString.clear();
    }

    return true;
}

void UsableTargetsAnalysis::fetchUnsafeMemoryOperations()
{
    _results = MemorySafetyResults::getInstance();

    if (!_results->getUnsafeMemoryAcceses().empty())
    {
        for (auto unsafeMemAccess : _results->getUnsafeMemoryAcceses())
        {
            if (isa<StoreInst>(unsafeMemAccess))
                upaActions[UPAType::UPAStackWrite][unsafeMemAccess] = "";
            else
                upaActions[UPAType::UPAStackRead][unsafeMemAccess] = "";
        }
    }
    else
        fetchUnsafeMemoryOperationsFromDB();
}

bool UsableTargetsAnalysis::fetchUnsafeMemoryOperationsFromDB()
{
    bool functionFound = false;
    std::string statement;
    std::string indexString;
    std::string actionID, instructionString, functionName;
    std::string currFunctionName = "";
    std::string currentFuncDI;
    std::string functionDebugInfo;
    std::string temp_inst, field_string;
    std::string upaActionType;
    std::string dbgID;
    std::queue<std::string> unsafeOperationIDs;
    std::set<std::string> potentialMatches;

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t typeValue, actionTypeValue, programNameValue;
    neo4j_map_entry_t mapEntries[3];
    neo4j_result_stream_t *results;
    neo4j_result_t *record;
    neo4j_value_t params;
    llvm::raw_string_ostream rso(temp_inst);
    Function *function = nullptr;
    FunctionScanPass *functionScanPass = nullptr;
    Instruction *unsafeOOBInstruction = NULL;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    programNameValue = neo4j_string(programName.c_str());
    typeValue = neo4j_string(ACTION_TYPE);

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("type", typeValue);

    for (auto upaType : {UPAStackWrite, UPAStackRead})
    {

        actionTypeValue = neo4j_string(upaTypeToString(upaType).c_str());
        mapEntries[2] = neo4j_map_entry("action_type", actionTypeValue);

        statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction)  WHERE a.type=$type AND a.program_name=p.program_name=$program_name AND a.action_type=$action_type AND NOT (a)-[:EDGE]->(:AttackGraphNode) RETURN p.instruction, p.function_name ,a.id,a.action_type,p.dbgID ORDER BY p.function_name";

        params = neo4j_map(mapEntries, 3);

        results = neo4j_run(connection, statement.c_str(), params);

        if (results == NULL)
        {
            errs() << "Failed to query \n";
            return false;
        }

        while ((record = neo4j_fetch_next(results)) != NULL)
        {

            // First instruction
            neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
            instructionString = std::string(field);
            instructionString = instructionString.substr(1, instructionString.length() - 2);
            memset(field, 0, 500);
            // Function name
            neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
            functionName = std::string(field);
            functionName = functionName.substr(1, functionName.length() - 2);
            memset(field, 0, 500);
            // Action ID
            neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
            actionID = std::string(field);
            actionID = actionID.substr(1, actionID.length() - 2);
            memset(field, 0, 500);
            // UPA Type
            neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
            upaActionType = std::string(field);
            upaActionType = upaActionType.substr(1, upaActionType.length() - 2);
            memset(field, 0, 500);
            // DBG ID
            neo4j_ntostring(neo4j_result_field(record, 4), field, 500);
            dbgID = std::string(field);
            dbgID = dbgID.substr(1, dbgID.length() - 2);
            // ALL UPA's would be unique (Guaranteed by query)
            instructionString = processStringEscapeCharacters(instructionString);

            if (functionName.compare(currFunctionName) != 0)
            {
                functionDebugInfo = getFunctionDebugInfo(functionName, programName);
                function = _module->getFunction(functionName);
                currentFuncDI.clear();
                functionFound = false;
                if (function)
                {
                    DISubprogram *subprogram = function->getSubprogram();
                    if (!subprogram)
                    {
                        errs() << "\t No func DI so skipping ****";
                        continue;
                    }
                    currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
                }

                if (currentFuncDI.compare(functionDebugInfo) != 0)
                {
                    // Find the function
                    for (auto &func : _module->functions())
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
                functionScanPass->processFunction();
                currFunctionName = functionName;
            }

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

                    else if (upaType == UPAType::UPAStackRead)
                    {
                        if (LoadInst *loadInst = dyn_cast<LoadInst>(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                            unsafeOOBInstruction = loadInst;
                        else if (CallInst *callInst = dyn_cast<CallInst>(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                            unsafeOOBInstruction = callInst;
                    }

                    else if (upaType == UPAType::UPAStackWrite)
                    {
                        if (StoreInst *storeInst = dyn_cast<StoreInst>(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                            unsafeOOBInstruction = storeInst;
                        else if (CallInst *callInst = dyn_cast<CallInst>(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                            unsafeOOBInstruction = callInst;
                    }
                }
            }

            if (!unsafeOOBInstruction)
            {
                errs() << "\t Failed to find inst :" << instructionString << ":" << functionName << ":" << dbgID << "\n";
                errs() << "\t\t # DBG ID based IR matches found :" << potentialMatches.size() << "\n";
                continue;
            }

            _results->addUnsafeMemoryAccess(unsafeOOBInstruction);
            upaActions[upaType][unsafeOOBInstruction] = actionID;
            unsafeOperationIDs.push(actionID);
        }
    }
    neo4j_close_results(results);
    neo4j_close(connection);

    errs() << "# Unsafe operations found:" << unsafeOperationIDs.size() << "\n";

    neo4j_value_t actionIDValue;
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    mapEntries[0] = neo4j_map_entry("unsafe_object_type", neo4j_string(UNSAFE_STACK_OBJECT));
    currFunctionName = "";
    functionScanPass = nullptr;
    std::string unsafeObjectGraphNodeID = "";

    // Fetch unsafe objects (functions more specifically)
    while (!unsafeOperationIDs.empty())
    {
        auto unsafeOperationID = unsafeOperationIDs.front();
        unsafeOperationIDs.pop();
        std::set<Instruction *> unsafeObjects;
        unsafeOperationIDToUnsafeObjects[unsafeOperationID] = unsafeObjects;
        actionIDValue = neo4j_string(unsafeOperationID.c_str());
        mapEntries[1] = neo4j_map_entry("action_id", actionIDValue);
        statement = " MATCH (obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(unsafeOperation:AttackGraphNode) WHERE unsafeOperation.id=$action_id AND obj.state_type=$unsafe_object_type WITH DISTINCT obj MATCH (obj)-[:EDGE]->(p:ProgramInstruction) RETURN  obj.id, p.instruction, p.function_name  ORDER BY p.function_name";
        params = neo4j_map(mapEntries, 2);
        results = neo4j_run(connection, statement.c_str(), params);
        unsafeObjectGraphNodeID.clear();

        while ((record = neo4j_fetch_next(results)) != NULL)
        {
            // Unsafe stack object id
            neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
            unsafeObjectGraphNodeID = std::string(field);
            unsafeObjectGraphNodeID = unsafeObjectGraphNodeID.substr(1, unsafeObjectGraphNodeID.length() - 2);
            memset(field, 0, 500);
            //  instruction
            neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
            instructionString = std::string(field);
            instructionString = instructionString.substr(1, instructionString.length() - 2);
            memset(field, 0, 500);
            // Function name
            neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
            functionName = std::string(field);
            functionName = functionName.substr(1, functionName.length() - 2);
            memset(field, 0, 500);

            if (cache.find(unsafeObjectGraphNodeID) != cache.end())
            {
                unsafeOperationIDToUnsafeObjects[unsafeOperationID].insert(cache[unsafeObjectGraphNodeID]);
                continue;
            }
            // ALL UPA's would be unique (Guaranteed by query)
            instructionString = processStringEscapeCharacters(instructionString);
            //            errs() << "\t:" << instructionString << "\n";
            indexString = functionName + instructionString;

            if (functionName.compare(currFunctionName) != 0)
            {
                functionDebugInfo = getFunctionDebugInfo(functionName, programName);
                function = _module->getFunction(functionName);
                currentFuncDI.clear();
                functionFound = false;
                if (function)
                {
                    DISubprogram *subprogram = function->getSubprogram();
                    if (!subprogram)
                    {
                        errs() << "\t No func DI so skipping ****";
                        continue;
                    }
                    currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
                }

                if (currentFuncDI.compare(functionDebugInfo) != 0)
                {
                    // Find the function
                    for (auto &func : _module->functions())
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
                    errs() << "\t Failed to find function (unsafe stack obj):" << functionName << ":" << functionDebugInfo << "\n";
                    //                exit(1);
                    continue;
                }
                functionScanPass = &getAnalysis<FunctionScanPass>(*function);
                currFunctionName = functionName;
            }

            auto stackObjInst = functionScanPass->findInstructionUsingIR(instructionString);

            if (!stackObjInst)
            {
                stackObjInst = function->getEntryBlock().getFirstNonPHI();
            }

            if (stackObjInst)
            {
                unsafeOperationIDToUnsafeObjects[unsafeOperationID].insert(stackObjInst);
                cache[unsafeObjectGraphNodeID] = stackObjInst;
            }
            else
            {
                errs() << "Failed to find exact object inst:" << instructionString << ":" << functionName << ":"
                       << "\n";
            }
        }
        neo4j_close_results(results);
    }
    errs() << "Found unsafe stack objects \n";
    neo4j_close(connection);
    return true;
}

std::string UsableTargetsAnalysis::findProgramInstructionInPDG(Instruction *instruction)
{
    std::string statement;
    std::string instructionString;
    std::string pdgLabel = "";
    std::string functionName;
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

    std::string currentFunctionDI;
    std::string functionDebugInfoDB;

    if (!instruction)
        return "";
    rso << *instruction;
    //    instructionString = addNecessaryEscapeCharacters(instructionString);
    if (instruction->getFunction())
        functionName = instruction->getFunction()->getName();
    else
        functionName = std::string("NULL");

    /*
        functionDebugInfoDB = getFunctionDebugInfo(functionName);


        if (instruction->getFunction()) {
            DISubprogram *subprogram = instruction->getFunction()->getSubprogram();
            if (!subprogram) {
                errs() << "\t No func DI exiting\n";
                return instructionString;
            }
            currentFunctionDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
        }

        if (currentFunctionDI.compare(functionDebugInfoDB) != 0) {

            functionName = getFunctionUsingDebugInfo(currentFunctionDI);
            if (functionName.empty()) {
                errs() << "\t Failed to find function (db name):" << functionName << ":" << currentFunctionDI << "\n";
                return instructionString;
            }
        }
    */

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

// Creates arg state given the pdg label of the arg node itself
std::string UsableTargetsAnalysis::createAttackState(std::string attackStateType, std::string pdgLabel)
{

    std::string statement;
    std::string stateID = "";
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t labelValue, stateNodeTypeValue, stateTypeValue;
    neo4j_map_entry_t stateQueryMapEntries[3];
    neo4j_result_stream_t *results;
    neo4j_result_t *record;
    neo4j_value_t params;

    if (pdgLabel.empty())
        return stateID;

    statement =
        " MATCH (p:ProgramInstruction) WHERE p.label=$label MERGE (a:AttackGraphNode{type:$node_type, state_type:$state_type, program_name:p.program_name})-[:EDGE]->(p) ON CREATE SET a.id=randomUUID() RETURN a.id as id";

    labelValue = neo4j_string(pdgLabel.c_str());
    stateNodeTypeValue = neo4j_string(STATE_TYPE);
    stateTypeValue = neo4j_string(attackStateType.c_str());

    stateQueryMapEntries[0] = neo4j_map_entry("label", labelValue);
    stateQueryMapEntries[1] = neo4j_map_entry("node_type", stateNodeTypeValue);
    stateQueryMapEntries[2] = neo4j_map_entry("state_type", stateTypeValue);

    params = neo4j_map(stateQueryMapEntries, 3);
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    results = neo4j_run(connection, statement.c_str(), params);

    if ((record = neo4j_fetch_next(results)) != NULL)
    {
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        stateID = std::string(field);
        stateID = stateID.substr(1, stateID.length() - 2);
    }

    neo4j_close_results(results);
    neo4j_close(connection);

    return stateID;
}

bool UsableTargetsAnalysis::connectActionAndState(std::string actionID, std::string stateID, std::string customLabel)
{
    std::string statement;
    neo4j_connection_t *connection;
    neo4j_value_t actionIDValue, stateIDValue, edgeLabelValue;
    neo4j_map_entry_t mapEntries[3];
    neo4j_value_t params;
    neo4j_result_stream_t *results;

    if (actionID.empty() || stateID.empty())
        return false;

    statement = " MATCH (action:AttackGraphNode) WHERE action.id=$action_id  WITH action MATCH (aState:AttackGraphNode) WHERE aState.id=$state_id WITH action,aState MERGE (action)-[:EDGE{label:$edge_label}]->(aState) RETURN aState";
    actionIDValue = neo4j_string(actionID.c_str());
    stateIDValue = neo4j_string(stateID.c_str());
    if (customLabel.empty())
        edgeLabelValue = neo4j_string(DATA_EDGE_LABEL);
    else
        edgeLabelValue = neo4j_string(customLabel.c_str());

    mapEntries[0] = neo4j_map_entry("action_id", actionIDValue);
    mapEntries[1] = neo4j_map_entry("state_id", stateIDValue);
    mapEntries[2] = neo4j_map_entry("edge_label", edgeLabelValue);

    params = neo4j_map(mapEntries, 3);
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    results = neo4j_run(connection, statement.c_str(), params);
    if (results == NULL)
        return false;

    neo4j_close_results(results);
    neo4j_close(connection);
    return true;
}

bool UsableTargetsAnalysis::connectActionAndStateTransactionBased(std::string actionID, std::set<std::string> stateIDs,
                                                                  std::string customLabel)
{
    std::string statement;
    neo4j_connection_t *connection;
    neo4j_value_t actionIDValue, stateIDValue, edgeLabelValue;
    neo4j_map_entry_t mapEntries[3];
    neo4j_value_t params;
    neo4j_result_stream_t *results;
    uint64_t edgeNumber = 1;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    actionIDValue = neo4j_string(actionID.c_str());

    for (auto stateID : stateIDs)
    {

        if (actionID.empty() || stateID.empty())
        {
            neo4j_close(connection);
            return false;
        }

        stateIDValue = neo4j_string(stateID.c_str());
        if (customLabel.empty())
            edgeLabelValue = neo4j_string(DATA_EDGE_LABEL);
        else
            edgeLabelValue = neo4j_string(customLabel.c_str());
        if (edgeNumber == 1)
        {
            statement = "BEGIN;";
            results = neo4j_run(connection, statement.c_str(), neo4j_null);
            if (results == NULL)
            {
                errs() << "ERROR - FAILED TO START TRANSACTION\n";
                neo4j_close(connection);
                return false;
            }
            else
                neo4j_close_results(results);
        }

        statement = " MATCH (action:AttackGraphNode) WHERE action.id=$action_id  WITH action MATCH (aState:AttackGraphNode) WHERE aState.id=$state_id WITH action,aState MERGE (action)-[:EDGE{label:$edge_label}]->(aState) RETURN aState";

        mapEntries[0] = neo4j_map_entry("action_id", actionIDValue);
        mapEntries[1] = neo4j_map_entry("state_id", stateIDValue);
        mapEntries[2] = neo4j_map_entry("edge_label", edgeLabelValue);

        params = neo4j_map(mapEntries, 3);
        results = neo4j_run(connection, statement.c_str(), params);
        if (results == NULL)
            return false;

        neo4j_close_results(results);

        // Commit
        if (edgeNumber == TRANSACTION_SIZE)
        {
            statement = "COMMIT;";
            results = neo4j_run(connection, statement.c_str(), neo4j_null);
            if (results == NULL)
            {
                errs() << "ERROR - FAILED TO COMMIT TRANSACTION\n";
                neo4j_close(connection);
                return false;
            }
            else
                neo4j_close_results(results);
            // Reset
            edgeNumber = 0;
        }
        ++edgeNumber;
    }
    // Commit any open transaction with < TRANSACTION_SIZE queries
    if (edgeNumber < TRANSACTION_SIZE || 1)
    {
        statement = "COMMIT;";
        results = neo4j_run(connection, statement.c_str(), neo4j_null);
        if (results == NULL)
        {
            errs() << "ERROR - FAILED TO COMMIT TRANSACTION\n";
            neo4j_close(connection);
            return false;
        }
        else
            neo4j_close_results(results);
    }

    neo4j_close(connection);
    return true;
}

// TODO - Use call graph here, see if can use sea-dsa or some open source context sensitive CG
std::set<Instruction *> UsableTargetsAnalysis::findAllPossiblePreviousCallers(Function *callee, int numLevels)
{

    std::set<Instruction *> callSites;
    pdg::ProgramGraph &pdg = pdg::ProgramGraph::getInstance();
    pdg::PDGCallGraph &call_g = pdg::PDGCallGraph::getInstance();
    if (!callee)
        return callSites;

    /*     if (false)
        {
            pdg::PTAWrapper &ptaw = pdg::PTAWrapper::getInstance();
            auto ptaCG = ptaw.getPTACallGraph();
            SVF::PTACallGraphEdge::CallInstSet ptaCallSiteSet;
            auto calleeSVFNode = ptaw.getPAG()->getModule()->getSVFFunction(callee);
            ptaCG->getAllCallSitesInvokingCallee(calleeSVFNode, ptaCallSiteSet);
            for (auto callBlockNode : ptaCallSiteSet)
            {
                if (callBlockNode->getCallSite())
                    callSites.insert(const_cast<Instruction *>(callBlockNode->getCallSite()));
            }
        } */

    //   errs()<<"Using PDG\n";
    auto fw = pdg.getFuncWrapper(*callee);
    if (fw && fw->getEntryNode())
    {
        auto callSiteNodes = fw->getEntryNode()->getInNeighborsWithDepType(pdg::EdgeType::CONTROLDEP_CALLINV);
        // errs() << "CS returned from PDG:" << callSiteNodes.size() << '\n';
        for (auto callSiteNode : callSiteNodes)
        {
            // errs() << "\t CS:" << callSiteNode->getValue() << "\n";

            if (callSiteNode && callSiteNode->getValue())
            {
                // errs() << "\t CS:" << *callSiteNode->getValue() << "\n";
                if (Instruction *CI = dyn_cast<Instruction>(callSiteNode->getValue()))
                    callSites.insert(CI);
            }
        }

        auto indirectCallSiteNodes = fw->getEntryNode()->getInNeighborsWithDepType(pdg::EdgeType::IND_CALL);
        // errs() << "CS returned from PDG:" << callSiteNodes.size() << '\n';
        for (auto indirectCallSiteNode : indirectCallSiteNodes)
        {
            // errs() << "\t CS:" << callSiteNode->getValue() << "\n";

            if (indirectCallSiteNode && indirectCallSiteNode->getValue())
            {
                // errs() << "\t CS:" << *callSiteNode->getValue() << "\n";
                if (Instruction *CI = dyn_cast<Instruction>(indirectCallSiteNode->getValue()))
                    callSites.insert(CI);
            }
        }
    }
    else
    {
        errs() << "Func not present in PDG call graph:" << callee->getName() << "\n";
    }

    if (callSites.empty())
    {

        for (auto user_it : callee->users())
        {
            if (CallBase *CI = dyn_cast<CallBase>(user_it))
            {
                callSites.insert(CI);
            }
        }
        /*  if (callSites.empty())
         {
             errs() << "\t PDG and PTA Call graph failed to identify call sites to:" << callee->getName() << "\n";
             errs() << "\t\t Call sites found using def use:" << callSites.size() << "\n";
         } */
    }
    // errs() << "Call sites returned:" << callSites.size() << "\n";
    return callSites;
}

Instruction *UsableTargetsAnalysis::findInstructionInFunctionUsingDebugInfo(std::string dbgID, unsigned int opcode,
                                                                            std::string instructionString,
                                                                            Function *function)
{
    std::set<Instruction *> potentialMatches;
    Instruction *instruction = NULL;
    Instruction *requiredInst = NULL;
    std::string instructionDbgID;
    if (dbgID.compare("ul") == 0)
    {
        return instruction;
    }
    if (function == NULL)
    {
        errs() << "FUNCTION NULL\n";
        return instruction;
    }

    for (auto bb_iter = function->begin(); bb_iter != function->end(); bb_iter++)
    {
        for (auto inst_it = bb_iter->begin(); inst_it != bb_iter->end(); inst_it++)
        {
            instruction = &*inst_it;
            if (instruction->getOpcode() != opcode)
                continue;
            DILocation *loc = instruction->getDebugLoc();
            if (!loc || loc->isImplicitCode())
            {
                continue;
            }
            instructionDbgID = loc->getFilename();
            instructionDbgID =
                instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" +
                std::to_string(loc->getColumn());
            if (instructionDbgID.compare(dbgID) == 0)
            {
                // Match
                //                errs() << "\t DBG match:" << *instruction << "\n";
                requiredInst = instruction;
                potentialMatches.insert(instruction);
            }
            instructionDbgID.clear();
        }
    }

    if (potentialMatches.empty())
    {
        return NULL;
    }
    else if (potentialMatches.size() == 1)
        return requiredInst;
    // Use the IR string sans dbg info (also may need to deal with neo4j's escape characters :( )
    else
    {
        std::string currentIRString;
        raw_string_ostream rso(currentIRString);
        instructionString = processStringEscapeCharacters(instructionString);
        instructionString = instructionString.substr(0, instructionString.find("!dbg"));
        for (auto potentialInst : potentialMatches)
        {
            rso << *potentialInst;
            if (currentIRString.find(instructionString) != std::string::npos)
                return potentialInst;
            rso.flush();
            currentIRString.clear();
        }
    }

    return nullptr;
}

void UsableTargetsAnalysis::getAnalysisUsage(AnalysisUsage &AU) const
{
    AU.addRequiredTransitive<IntraTargetAnalysisPass>();
    // AU.addRequired<CallGraphWrapperPass>();
    AU.addRequired<FunctionScanPass>();
    AU.addRequired<pdg::ProgramDependencyGraph>();
    AU.setPreservesAll();
}

char UsableTargetsAnalysis::ID = 0;

static RegisterPass<UsableTargetsAnalysis> P("compute-usable-targets", "Compute unsafe pointer action effects on sys calls", false, true);
