#include "EstimationPass.hh"
#include "GraphConstants.h"

/**
 * @brief
 * Two configurations
 * 1. Compute cost estimates (Check and per object MD) for a monitor (DEFAULT)
 * 2. Generate frequency info for all unsafe operations (input to solver)
 */

#define ASAN_STACK_OBJECT "asanStackObj"

cl::opt<bool> shouldGenerateCoverageData("cov", cl::desc(
                                                    "Read and save coverage/frequency data for relevant operations (monitoring points)"));

cl::opt<bool> generateFrequencyInformationForAllUnsafeOperations("all-cov", cl::desc(
                                                                                "Read and save frequency data for all operations (monitoring points)"));

Function *CostEstimationPass::findFunctionUsingNameAndMD(std::string functionName, bool &multiple, std::set<std::string> &candidates)
{
    Function *function = _module->getFunction(functionName);
    std::string targetFunctionDI = getFunctionDebugInfo(functionName);
    DISubprogram *subprogram = nullptr;
    std::string funcDI = "";
    multiple = false;
    if (function)
    {
        subprogram = function->getSubprogram();
        if (subprogram)
        {
            funcDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
            if (targetFunctionDI.compare(funcDI) == 0 || targetFunctionDI.empty())
            {
                return function;
            }
            else
                function = nullptr;
        }
    }
    if (!targetFunctionDI.empty())
    {
        // Search using debug id
        for (auto &func : _module->functions())
        {
            DISubprogram *subprogram = func.getSubprogram();
            if (!subprogram)
                continue;
            std::string funcDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
            if (targetFunctionDI.compare(funcDI) == 0)
            {
                // errs() << "\t\t Func found:" << func.getName() << "==" << functionName << "\n";
                function = &func;
            }
        }
        // Check if  function was inlined using metadata
        if (!function)
        {

            // targetFunctionDI = targetFunctionDI.substr(0, targetFunctionDI.find(":"));

            function = scanPass->findFunctionUsingDBGID(functionName);
            if (!function)
            {
                auto potentialMatches = scanPass->findFunctionsUsingDBGID(functionName);
                if (potentialMatches.size() == 1)
                {
                    function = _module->getFunction(*potentialMatches.begin());
                }
                else if (!potentialMatches.empty())
                {
                    multiple = true;
                    // errs() << "Function " << functionName << " using :" << targetFunctionDI << "\n";
                    // errs() << "\t Potential matches :" << potentialMatches.size() << "\n";
                    candidates = potentialMatches;
                }
            }
        }
    }
    return function;
}

void CostEstimationPass::updateFrequencyInfoInDB(std::map<std::string, uint64_t> instructionFrequencyCount)
{
    // Update DB with frequency counts for workload type specified
    std::string statement;
    std::string nodeID;
    uint64_t executionCount;
    neo4j_connection_t *connection;
    neo4j_map_entry_t mapEntries[2];
    neo4j_result_stream_t *results;
    neo4j_value_t params;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    for (auto it : instructionFrequencyCount)
    {
        nodeID = it.first;
        executionCount = it.second;
        mapEntries[0] = neo4j_map_entry("node_id", neo4j_string(nodeID.c_str()));
        mapEntries[1] = neo4j_map_entry("execution_count", neo4j_string(std::to_string(executionCount).c_str()));
        // Update coverage info monitoring points
        // TODO - Make dynamic wrt workload
        // AG node because we support all now
        statement =
            "MATCH (mp:AttackGraphNode) WHERE mp.id=$node_id SET mp.count_ref=$execution_count";

        params = neo4j_map(mapEntries, 2);

        results = neo4j_run(connection, statement.c_str(), params);
        if (!results)
        {
            errs() << "ERROR - Failed to update exiting\n";
            break;
        }
        neo4j_close_results(results);
    }
    neo4j_close(connection);
}

void CostEstimationPass::updateObjCountInDB()
{
    std::string statement;
    std::string functionName;
    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t functionNameValue;
    neo4j_map_entry_t mapEntries[4];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    // TODO - Include DBG id to deal with internal linkage issue
    for (auto it : stackObjInstrumentedPerFunctionMap)
    {
        auto func = _module->getFunction(it.first);
        if (!func)
        {
            errs() << "Function:" << it.first << " not found \n";
        }

        programNameValue = neo4j_string(programName.c_str());
        functionNameValue = neo4j_string(it.first.c_str());
        mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
        mapEntries[1] = neo4j_map_entry("func_dbg_id", functionNameValue);
        mapEntries[2] = neo4j_map_entry("entry_node", neo4j_string("ENTRY:"));
        mapEntries[3] = neo4j_map_entry("obj_count", neo4j_string(std::to_string(it.second).c_str()));

        params = neo4j_map(mapEntries, 4);

        // Step 1 - Fetch monitored unsafe functions - contain unsafe operations
        statement =
            " MATCH (p:ProgramInstruction) WHERE p.program_name=$program_name AND p.function_name=$func_dbg_id AND p.instruction CONTAINS $entry_node  SET p.obj_count=$obj_count";

        results = neo4j_run(connection, statement.c_str(), params);
        if (!results)
        {
            errs() << "ERROR - FAILED TO SET OBJ COUNT\n";
            neo4j_close(connection);
            return;
        }
        neo4j_close_results(results);
    }
    neo4j_close(connection);
}

void CostEstimationPass::searchForInlinedFunctions()
{

    for (auto &func : _module->functions())
    {
        if (func.empty() || func.isIntrinsic() || func.isDeclaration())
            continue;
        auto functionName = func.getName();
        if (functionName.contains("_llvm_") || functionName.contains("_gcov_") ||
            functionName.contains("baggy"))
            continue;
        // DISubprogram *subprogram = func.getSubprogram();

        // if (subprogram)
        // {

        //     auto scope = subprogram->getScope();
        //     errs() << "DI:" << func.getName() << ":" << *subprogram << "\n";
        //     if (scope)
        //         errs() << "\t" << *scope << "\n";
        //     std::string funcDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
        // }

        scanPass = &getAnalysis<FunctionScanPass>(func);
        scanPass->processFunction();
    }
}

std::set<std::string> CostEstimationPass::findAllMetadataFunctions()
{
    std::string statement;
    std::string functionName;
    std::string instructionString;
    std::string dbgID;
    std::string functionDBGID;
    std::string monitorType;
    std::string unsafeOperationToMonitorID;
    std::set<std::string> unsafeOperationIDS;
    std::set<Instruction *> instructionsToBeAnalyzed;
    std::set<std::string> metadataFunctionNames;
    std::set<Function *> metadataFunctions;
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t upaIDValue;
    neo4j_map_entry_t mapEntries[3];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    // Step 1 - Fetch  unsafe functions - contain unsafe operations UPAs
    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("upa_type", neo4j_string(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE));
    mapEntries[2] = neo4j_map_entry("read_upa_type", neo4j_string(UNSAFE_POINTER_READ_STACK_ACTION_TYPE));

    params = neo4j_map(mapEntries, 3);

    statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND (a.action_type=$upa_type OR a.action_type=$read_upa_type) RETURN DISTINCT p.function_name, a.id ";

    results = neo4j_run(connection, statement.c_str(), params);
    if (results == NULL)
    {
        errs() << "ERROR - FAILED TO START TRANSACTION\n";
        neo4j_close(connection);
    }

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First function name
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        metadataFunctionNames.insert(functionName);
        memset(field, 0, 500);

        // Second unsafe operation ID
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        unsafeOperationToMonitorID = std::string(field);
        unsafeOperationToMonitorID = unsafeOperationToMonitorID.substr(1, unsafeOperationToMonitorID.length() - 2);
        unsafeOperationIDS.insert(unsafeOperationToMonitorID);
        memset(field, 0, 500);
    }

    neo4j_close_results(results);
    neo4j_close(connection);

    if (!unsafeOperationIDS.empty())
    {

        // Step 2 - Fetch functions containing the unsafe use/OOB GEP
        connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
        for (auto upaID : unsafeOperationIDS)
        {
            upaIDValue = neo4j_string(upaID.c_str());
            mapEntries[0] = neo4j_map_entry("upa_id", upaIDValue);
            params = neo4j_map(mapEntries, 1);

            statement = " MATCH (state:AttackGraphNode)-[:EDGE]->(action:AttackGraphNode) WHERE action.id=$upa_id WITH DISTINCT state MATCH (state)-[:EDGE]->(p:ProgramInstruction) RETURN  DISTINCT p.function_name";

            results = neo4j_run(connection, statement.c_str(), params);

            while ((record = neo4j_fetch_next(results)) != NULL)
            {

                // Function name
                neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
                functionName = std::string(field);
                functionName = functionName.substr(1, functionName.length() - 2);
                memset(field, 0, 500);
                metadataFunctionNames.insert(functionName);
            }
        }
        neo4j_close_results(results);

        // Step 3 - Fetch functions containing the unsafe objects
        for (auto upaID : unsafeOperationIDS)
        {
            upaIDValue = neo4j_string(upaID.c_str());
            mapEntries[0] = neo4j_map_entry("upa_id", upaIDValue);
            params = neo4j_map(mapEntries, 1);

            statement = " MATCH (source:AttackGraphNode)-[:SOURCE]->(state:AttackGraphNode)-[:EDGE]->(action:AttackGraphNode) WHERE action.id=$upa_id WITH DISTINCT source MATCH (source)-[:EDGE]->(p:ProgramInstruction) RETURN  DISTINCT p.function_name";

            results = neo4j_run(connection, statement.c_str(), params);

            while ((record = neo4j_fetch_next(results)) != NULL)
            {
                // Function name
                neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
                functionName = std::string(field);
                functionName = functionName.substr(1, functionName.length() - 2);
                memset(field, 0, 500);
                metadataFunctionNames.insert(functionName);
            }
        }
        neo4j_close_results(results);
        neo4j_close(connection);
    }
    errs() << "# Overall Metadata Functions :" << metadataFunctionNames.size() << "\n";

    return metadataFunctionNames;
}

uint64_t CostEstimationPass::getAllocaSizeInBytes(const AllocaInst &AI)
{
    uint64_t ArraySize = 1;
    if (AI.isArrayAllocation())
    {
        const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
        assert(CI && "non-constant array size");
        ArraySize = CI->getZExtValue();
    }
    Type *Ty = AI.getAllocatedType();
    uint64_t SizeInBytes =
        AI.getModule()->getDataLayout().getTypeAllocSize(Ty);
    return SizeInBytes * ArraySize;
}

bool CostEstimationPass::isInterestingAlloca(const AllocaInst &AI)
{

    // All stack objects must be aligned to slot size for this instrumentation (just alignment)to work or alternatively modify the size of the allocation as well
    //    return true;
    bool IsInteresting =
        (AI.getAllocatedType()->isSized() &&
         // alloca() may be called with 0 size, ignore it.
         ((!AI.isStaticAlloca()) || getAllocaSizeInBytes(AI) > 0) &&
         // We are only interested in allocas not promotable to registers.
         // Promotable allocas are common under -O0.
         (!isAllocaPromotable(&AI)) &&
         // inalloca allocas are not treated as static, and we don't want
         // dynamic alloca instrumentation for them as well.
         !AI.isUsedWithInAlloca() &&
         // swifterror allocas are register promoted by ISel
         !AI.isSwiftError());

    return IsInteresting;
}

inline bool CostEstimationPass::isConstantSizeAlloca(const AllocaInst &AI)
{
    if (AI.isArrayAllocation())
    {
        const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
        if (!CI)
            return false;
    }
    Type *Ty = AI.getAllocatedType();
    return Ty->isSized();
}

uint64_t CostEstimationPass::estimateNetObjects(Function *func)
{
    uint64_t numObjects = 0;

    for (auto inst_it = inst_begin(func); inst_it != inst_end(func); inst_it++)
    {
        if (AllocaInst *AI = dyn_cast<AllocaInst>(&*inst_it))
        {
            if (isInterestingAlloca(*AI))
                ++numObjects;
        }
    }

    if (numObjects)
    {
        errs() << "\t Num objects (md) found:" << numObjects << " in " << func->getName() << "\n";
    }
    return numObjects;
}

uint64_t CostEstimationPass::getNumOfStackObjects(Function *func)
{

    std::string statement;
    std::string functionName;

    uint64_t numStackObjects = 0;
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_map_entry_t mapEntries[3];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    functionName = func->getName().str();
    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("alloca_instruction", neo4j_string("alloca"));
    mapEntries[2] = neo4j_map_entry("function_name", neo4j_string(functionName.c_str()));

    params = neo4j_map(mapEntries, 3);

    // Step 1 - Fetch monitored unsafe functions - contain unsafe operations,
    statement = "MATCH (p:ProgramInstruction) WHERE p.program_name=$program_name AND p.instruction CONTAINS \" alloca \" AND p.function_name=$function_name RETURN  COUNT(DISTINCT p.instruction)";
    results = neo4j_run(connection, statement.c_str(), params);
    if (results == NULL)
    {
        errs() << "ERROR - FAILED TO START TRANSACTION\n";
        neo4j_close(connection);
    }

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First function name
        //        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        numStackObjects = neo4j_int_value(neo4j_result_field(record, 0));
    }

    neo4j_close_results(results);
    neo4j_close(connection);
    free(field);
    //    assert(numStackObjects > 0 && "Failed to find # stack objects");
    return numStackObjects;
}

uint64_t CostEstimationPass::identifyObjectMetadataOperations(Function *func)
{
    uint64_t netObjectMetadataOperations = 0;
    uint64_t numObjects = 0;
    uint64_t avgObjSize = 0;
    uint64_t functionFrequency = 0;
    uint64_t executionCount = 0;
    bool stackMDOperationsPresent = false;

    if (CURRENT_MONITOR == MonitorType::BaggyBounds)
    {
        for (auto inst_it = inst_begin(func); inst_it != inst_end(func); inst_it++)
        {
            if (CallInst *callInst = dyn_cast<CallInst>(&*inst_it))
            {
                if (callInst->getCalledFunction() && callInst->getCalledFunction()->hasName())
                {
                    if (callInst->getCalledFunction()->getName().equals("baggy_save_in_table"))
                    {
                        numObjects++;
                        stackMDOperationsPresent = true;
                        break;

                        /*  if (!functionFrequency)
                         {
                             if (func->getName().equals("main"))
                                 functionFrequency = 1;
                             else
                                 functionFrequency = getExecutionCount(func->getEntryBlock().getFirstNonPHI());
                         }
                         // Because we create a new function to deal with cmd args gcno file is inaccurate this should help
                         if (func->getName().equals("main"))
                             netObjectMetadataOperations += 1;
                         else
                         {
                             executionCount = getExecutionCount(callInst);
                             if (executionCount != functionFrequency)
                             {
                                 errs()
                                     << "\t\t EXCEPTION Stack MD freq != function entry BB (Weird coverage issue? mismatch using CFG?\n";
                                 executionCount = functionFrequency;
                             }
                             netObjectMetadataOperations += executionCount;
                         }

                         if (auto objSize = dyn_cast<ConstantInt>(callInst->getArgOperand(1)))
                             avgObjSize += objSize->getZExtValue(); */
                    }
                    // else if (callInst->getCalledFunction()->getName().contains("baggy_malloc") ||
                    //          callInst->getCalledFunction()->getName().contains("baggy_calloc") ||
                    //          callInst->getCalledFunction()->getName().contains("baggy_realloc"))
                    // {
                    //     numObjects++;
                    //     netObjectMetadataOperations += getExecutionCount(callInst);
                    // }
                }
            }
        }
#ifndef IDENTIFY_INDIVIDUAL_STACK_MD_OPERATIONS
        return stackMDOperationsPresent;
#endif
    }

    /**
     * ASAN handles dyn allocas. This means function freq* num stack object may not be equal to number of md operations
     * Dyn allocas may be hotter, at least theoretically.
     * TODO - Make this code robust to deal with this case later
     */
    else if (CURRENT_MONITOR == MonitorType::ASAN)
    {

        // ASAN makes explicit calls to asan_alloca_poison for dyn allocas and adds another stack variable (so another alloca)
        uint64_t numDynAllocaObjects = 0;
        bool areThereDynAllocas = false;
        AllocaInst *randomStaticAlloca = nullptr;

        // uint64_t numOriginalStackObjects = getNumOfStackObjects(func);

        // if (!numOriginalStackObjects) {
        //     errs() << "\t Failed to find # original stack objects in:" << func->getName() << "\n";
        //     return 0;
        // }

        // // Byval args- ASAN will add new allocas (with redzones)
        // for (auto &arg: func->args()) {
        //     if (arg.hasByValAttr())
        //         numOriginalStackObjects++;
        // }

        for (auto inst_it = inst_begin(func); inst_it != inst_end(func); inst_it++)
        {
            if (AllocaInst *allocaInst = dyn_cast<AllocaInst>(&*inst_it))
            {
                numObjects++;
                if (!isConstantSizeAlloca(*allocaInst))
                    areThereDynAllocas = true;
                else
                    randomStaticAlloca = allocaInst;
            }
            else if (areThereDynAllocas)
            {
                CallInst *callInst = dyn_cast<CallInst>(&*inst_it);
                if (callInst && callInst->getCalledFunction() && callInst->getCalledFunction()->hasName())
                {
                    if (callInst->getCalledFunction()->getName().contains("__asan_alloca_poison"))
                    {
                        numDynAllocaObjects++;
                        stackMDOperationsPresent = true;
                    }
                }
            }
            else if (!stackMDOperationsPresent)
            {
                CallInst *callInst = dyn_cast<CallInst>(&*inst_it);
                if (callInst && callInst->getCalledFunction() && callInst->getCalledFunction()->hasName())
                {
                    if (callInst->getCalledFunction()->getName().contains("__asan_stack_malloc"))
                    {
                        stackMDOperationsPresent = true;
                        break;
                    }
                }
            }
        }

#ifndef IDENTIFY_INDIVIDUAL_STACK_MD_OPERATIONS
        return stackMDOperationsPresent;
#endif
        // Get execution count only when we are sure it contains any stack MD operations
        //     if (!netObjectMetadataOperations)
        //         netObjectMetadataOperations = getExecutionCount(randomStaticAlloca);

        //     functionFrequency = getExecutionCount(func->getEntryBlock().getFirstNonPHI());
        //     // ASAN adds an extra alloca for each dyn alloca so we do not count these and count other allocas which are modified first

        //     numObjects -= numDynAllocaObjects;

        //     if (numOriginalStackObjects < (numObjects - 1))
        //     {
        //         errs() << "Failed to identify stack md correctly in:" << func->getName() << "\n";
        //         errs() << "\t" << numOriginalStackObjects << ":" << numObjects << "\n";
        //         exit(1);
        //     }
        //     else if ((numOriginalStackObjects + 1) == numObjects)
        //         numObjects = 1;
        //     else
        //         numObjects = (numOriginalStackObjects - numObjects) + 2;

        //     // We now account for the dyn allocas
        //     numObjects += numDynAllocaObjects;
        //     netObjectMetadataOperations = numObjects * netObjectMetadataOperations;
    }

    // if (netObjectMetadataOperations)
    // {
    //     errs() << "Func:" << func->getName() << "\n";
    //     errs() << "\t Num objects (md) found:" << numObjects << "\n";
    //     errs() << "\t Net objects (md) operations:" << netObjectMetadataOperations << "\n";
    //     errs() << "\t Total stack obj bytes for which bounds are tracked:" << avgObjSize << "\n";

    //     errs() << "\t Function frequency:" << functionFrequency << "\n";

    //     assert((functionFrequency * numObjects) <= netObjectMetadataOperations);

    //     avgObjSize = avgObjSize / numObjects;
    //     errs() << "\t Avg obj size:" << avgObjSize << "\n";
    // }
    // stackObjInstrumentedPerFunctionMap[func->getName().str()] = numObjects;
    // return netObjectMetadataOperations;
}

bool CostEstimationPass::runOnModule(Module &M)
{

    StringRef functionName;
    std::map<OperationType, uint64_t> operationTypeToCount;

    programName = M.getModuleIdentifier();
    programName = programName.substr(0, programName.length() - 3);
    if (programName.find(".profile") != std::string::npos)
        programName = programName.substr(0, programName.find(".profile"));
    errs() << "Program name:" << programName << "\n";

    _module = &M;
    if (shouldGenerateCoverageData && generateFrequencyInformationForAllUnsafeOperations)
    {
        errs() << "\t Invalid options selected\n";
        exit(1);
    }

    // Read and save frequency information of relevant(or all) unsafe operations
    if (shouldGenerateCoverageData || generateFrequencyInformationForAllUnsafeOperations)
    {
        generateCoverageData();
        return false;
    }

    // Config 1 - Estimate monitor/sanitizer cost (Check cost and MD cost) (DEFAULT)
    readCoverageData(programName, monitorTypeToString(CURRENT_MONITOR));

    operationTypeToCount[OperationType::CheckOperations] = 0;
    operationTypeToCount[OperationType::MetadataOperations] = 0;

    // Step 1 - Find  check operations in each function
    if (COMPUTE_PER_CHECK_COST)
    {
        uint64_t netCheckOperationsForFunction = 0;
        uint64_t numberOfChecks = 0;
        for (auto &func : M.functions())
        {
            if (func.empty() || func.isIntrinsic() || func.isDeclaration())
                continue;
            functionName = func.getName();
            if (functionName.contains("_llvm_") || functionName.contains("_gcov_") ||
                functionName.contains("baggy"))
                continue;

            CostEstimationFunctionPass *estimationFunctionPass = &getAnalysis<CostEstimationFunctionPass>(func);
            netCheckOperationsForFunction = 0;

            for (auto const &it : estimationFunctionPass->getMonitoredMemoryOperations())
            {
                netCheckOperationsForFunction += getExecutionCount(it);
                numberOfChecks += 1;
            }
            operationTypeToCount[OperationType::CheckOperations] += netCheckOperationsForFunction;
        }
        errs() << "# Total individual check operations found:" << numberOfChecks << "\n";
        errs() << "# Effective check operations executed :" << operationTypeToCount[OperationType::CheckOperations] << "\n";
    }

    // Step 2 - Estimate the cost of metadata operations (Mainly focused on stack MD)
    if (COMPUTE_METADATA_COST)
    {
        uint64_t netFunctionMetadataOperations = 0;
        uint64_t noInstrumentedFunctionsWithMDOperations = 0;
        uint64_t numObjects;
        uint64_t netObjectMetadataOperations = 0;

        for (auto &func : M.functions())
        {
            if (func.empty() || func.isIntrinsic() || func.isDeclaration())
                continue;
            functionName = func.getName();
            if (functionName.contains("_llvm_") || functionName.contains("_gcov_") ||
                functionName.contains("baggy"))
                continue;

            if (CURRENT_MONITOR == MonitorType::ASAN)
            {
                if (!func.hasFnAttribute(Attribute::SanitizeAddress))
                    continue;
            }

            // Per stack object metadata cost

            netObjectMetadataOperations = identifyObjectMetadataOperations(&func);
            // Net object metadata operations
#ifdef IDENTIFY_INDIVIDUAL_STACK_MD_OPERATIONS
            operationTypeToCount[OperationType::MetadataOperations] += netObjectMetadataOperations;
#else
            if (netObjectMetadataOperations)
            {
                noInstrumentedFunctionsWithMDOperations++;
                netFunctionMetadataOperations = getExecutionCount(func.getEntryBlock().getFirstNonPHI());
                operationTypeToCount[OperationType::MetadataOperations] += netFunctionMetadataOperations;
            }
#endif
        }
        errs() << "# Total instrumented functions found (stack MD):" << noInstrumentedFunctionsWithMDOperations << "\n";
#ifndef IDENTIFY_INDIVIDUAL_STACK_MD_OPERATIONS
        errs() << "# Total  function MD operations (function granularity + frequency):"
               << operationTypeToCount[OperationType::MetadataOperations]
               << "\n";

        errs() << "Avg  function MD frequency  (function granularity + frequency):"
               << (static_cast<float>(operationTypeToCount[OperationType::MetadataOperations]) /
                   static_cast<float>(noInstrumentedFunctionsWithMDOperations))
               << "\n";
#else
        errs() << "# Total net object metadata operations found:"
               << operationTypeToCount[OperationType::MetadataOperations]
               << "\n";
#endif
        // updateObjCountInDB();
    }

    // Step 3 - Store the cost estimates (For each class of operations accounting for coverage)
    dumpCostEstimateInfo(operationTypeToCount);

    return false;
}

/**
 * Reads coverage data and writes to file (Needed for solver :( )
 * Updates DB with count/frequency info for workload
 */
void CostEstimationPass::generateCoverageData()
{
    searchForInlinedFunctions();
    std::map<std::string, uint64_t> monitoringPointsFrequencyMap;
    // Generate coverage data in order for monitoring points
    readCoverageData(programName, "");
    if (shouldGenerateCoverageData)
        findRelevantMonitoringPoints(monitoringPointsFrequencyMap);
    else if (generateFrequencyInformationForAllUnsafeOperations)
        findAllMonitoringPoints(monitoringPointsFrequencyMap);

    uint64_t executionCount = 0;
    errs() << "# MPs found:" << monitoringPoints.size() << "==" << monitoringPointIDs.size() << "\n";
    /*     // For ASAN this is the actual memory dereference
        std::ofstream coverageFileWriter = createFileWriter(programName + "_coverage.txt");
    Instruction *monitoringPoint = nullptr;
        for (int pos = 0; pos < monitoringPoints.size(); pos++)
        {
            monitoringPoint = monitoringPoints[pos];
            executionCount = getExecutionCount(monitoringPoint);
            if (executionCount == 0)
            {
                //            errs() << "Not actually executed setting to 1:" << *monitoringPoint << "\n";
                executionCount = 0;
            }

            coverageFileWriter << std::to_string(executionCount) << "\n";
            monitoringPointsFrequencyMap[monitoringPointIDs[pos]] = executionCount;
        }
        coverageFileWriter.close();
        */

    // Store frequency info of monitoring points in DB
    updateFrequencyInfoInDB(monitoringPointsFrequencyMap);

    if (shouldGenerateCoverageData || generateFrequencyInformationForAllUnsafeOperations)
    {
        // Now store frequency info of relevant functions in DB
        std::string statement;
        std::string functionName;
        neo4j_connection_t *connection;
        neo4j_value_t programNameValue;
        neo4j_value_t functionNameValue;
        neo4j_map_entry_t mapEntries[4];
        neo4j_value_t params;
        neo4j_result_t *record;
        neo4j_result_stream_t *results;
        connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

        std::string funcDI;
        std::set<std::string> metadataFunctionNames = findAllMetadataFunctions();

        Function *tempFunc = nullptr;
        bool hasBeenEntirelyInlined = false;
        std::set<std::string> potentialMatches;
        bool funcFound = false;
        for (auto func_name : metadataFunctionNames)
        {
            hasBeenEntirelyInlined = false;
            funcFound = false;
            potentialMatches.clear();
            executionCount = 0;
            tempFunc = findFunctionUsingNameAndMD(func_name, hasBeenEntirelyInlined, potentialMatches);
            funcDI = getFunctionDebugInfo(func_name);

            if (tempFunc)
            {
                funcFound = true;
                auto instInFunc = tempFunc->getEntryBlock().getFirstNonPHI();
                if (!instInFunc)
                {
                    errs() << "Failed to get inst in entry block"
                           << "\n";
                    continue;
                }
                executionCount = getExecutionCount(instInFunc);
            }
            else if (hasBeenEntirelyInlined && !potentialMatches.empty())
            {
                funcFound = true;
                for (auto matchFunc : potentialMatches)
                {
                    tempFunc = _module->getFunction(matchFunc);
                    auto instInFunc = tempFunc->getEntryBlock().getFirstNonPHI();
                    executionCount += getExecutionCount(instInFunc);
                }
            }
            if (funcFound)
            {
                errs() << "Function:" << func_name << ":" << executionCount << "\n";
                programNameValue = neo4j_string(programName.c_str());
                functionNameValue = neo4j_string(funcDI.c_str());
                mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
                mapEntries[1] = neo4j_map_entry("func_dbg_id", functionNameValue);
                mapEntries[2] = neo4j_map_entry("entry_node", neo4j_string("ENTRY:"));
                mapEntries[3] = neo4j_map_entry("execution_count", neo4j_string(std::to_string(executionCount).c_str()));

                params = neo4j_map(mapEntries, 4);

                // Step 1 - Fetch monitored unsafe functions - contain unsafe operations
                // statement =
                //         " MATCH (p:ProgramInstruction) WHERE p.program_name=$program_name AND p.dbgID=$func_dbg_id AND p.instruction CONTAINS $entry_node  SET p.count_ref=$execution_count";
                statement =
                    " MATCH (p:Entry) WHERE p.program_name=$program_name AND p.dbgID=$func_dbg_id AND p.instruction CONTAINS $entry_node  SET p.count_ref=$execution_count";

                results = neo4j_run(connection, statement.c_str(), params);
                if (!results)
                {
                    errs() << "ERROR - FAILED TO SET FREQUENCY\n";
                    neo4j_close(connection);
                    return;
                }
                neo4j_close_results(results);
            }
            else
            {
                errs() << "\t"
                       << "Failed to find function:" << func_name << ":" << funcDI << " using DI and checking for inlining\n";
            }
        }
        errs() << "#  Metadata Functions found using DI :" << metadataFunctionNames.size() << "\n";

        neo4j_close(connection);
    }
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

// TODO - When we update schema to include opcode this will simplify greatly for now let's do Baggy, ASAN specific
bool CostEstimationPass::findRelevantMonitoringPoints(std::map<std::string, uint64_t> &monitoringPointsFrequencyMap)
{
    // Fetch all UPAs
    std::string statement;
    std::string actionID, instructionString, functionName;
    std::string temp_inst, field_string;
    std::string calleeName;
    std::string dbgID;
    std::string mpID;
    std::string actionType;

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_map_entry_t mapEntries[3];
    neo4j_result_stream_t *results;
    neo4j_result_t *record;
    neo4j_value_t params;
    llvm::raw_string_ostream rso(temp_inst);

    Instruction *inst = nullptr;
    bool isEntirelyInlined = false;
    std::set<std::string> candidates;
    uint64_t executionCount = 0;

    connection = neo4j_connect(URI, nullptr, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    // Fetch monitoring points
    statement =
        "MATCH (mp:MP)-[:EDGE]->(p:ProgramInstruction) WHERE mp.program_name=$program_name AND (mp)-[:EDGE]->(:AttackGraphNode) RETURN mp.id, p.dbgID,p.instruction,p.function_name,mp.action_type ORDER BY mp.id";

    params = neo4j_map(mapEntries, 1);

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First MP ID
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        mpID = std::string(field);
        mpID = mpID.substr(1, mpID.length() - 2);
        memset(field, 0, 500);

        // Second dbg ID
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);

        // instruction
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);
        memset(field, 0, 500);

        // Function name
        neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        // Action type just to figure out frequency accurately
        neo4j_ntostring(neo4j_result_field(record, 4), field, 500);
        actionType = std::string(field);
        actionType = actionType.substr(1, actionType.length() - 2);
        memset(field, 0, 500);

        instructionString = processStringEscapeCharacters(instructionString);

        if (instructionString.find("call ") != std::string::npos)
            inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Call, instructionString,
                                                           functionName);
        else if (actionType.compare("ul") == 0)
            inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::GetElementPtr,
                                                           instructionString,
                                                           functionName);
        else if (actionType.compare(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE) == 0)
        {
            inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Store, instructionString,
                                                           functionName);
        }
        else if (actionType.compare(UNSAFE_POINTER_READ_STACK_ACTION_TYPE) == 0)
        {

            inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Load, instructionString,
                                                           functionName);
        }
        else
            errs() << "\t Invalid attack action type found:" << actionType << "\n";

        if (!inst)
        {
            errs() << "Failed to find MP instruction using debug information :" << instructionString << ":" << dbgID << ":"
                   << functionName << ":" << actionType << "\n";

            isEntirelyInlined = false;
            candidates.clear();
            Function *function = findFunctionUsingNameAndMD(functionName, isEntirelyInlined, candidates);

            // Approximates coverage
            executionCount = 0;
            if (!inst && function)
            {
                inst = function->getEntryBlock().getFirstNonPHI();
                errs() << "\t Actually failed so over-approximating " << instructionString << ":" << dbgID << ":"
                       << functionName << ":" << actionType << "\n\n";
                executionCount = getExecutionCount(inst);
            }
            else if (!candidates.empty())
            {
                for (auto candidateFuncName : candidates)
                {
                    auto candidateFunc = _module->getFunction(candidateFuncName);
                    inst = candidateFunc->getEntryBlock().getFirstNonPHI();
                    executionCount += getExecutionCount(inst);
                }
            }

            if (inst)
            {
                monitoringPoints.push_back(inst);
            }
        }
        else
        {
            executionCount = getExecutionCount(inst);
            monitoringPoints.push_back(inst);
        }
        monitoringPointsFrequencyMap[mpID] = executionCount;
        monitoringPointIDs.push_back(mpID);
    }

    neo4j_close_results(results);
    neo4j_close(connection);

    return true;
}

/**
 * Finds monitoring points for all unsafe operations - irrespective of any reachable uses
 * We do not actually instrument these so we do not care about order.
 * We do not annotate these  so find them manually and set them in the DB  (ONLY FOR ANALYSIS)
 */
bool CostEstimationPass::findAllMonitoringPoints(std::map<std::string, uint64_t> &monitoringPointsFrequencyMap)
{
    // Fetch all UPAs
    std::string statement;
    std::string actionID, instructionString, functionName;
    std::string temp_inst, field_string;
    std::string calleeName;
    std::string dbgID;
    std::string mpID;
    std::string actionType;

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_map_entry_t mapEntries[4];
    neo4j_result_stream_t *results;
    neo4j_result_t *record;
    neo4j_value_t params;
    llvm::raw_string_ostream rso(temp_inst);

    Instruction *inst = nullptr;
    bool isEntirelyInlined = false;
    std::set<std::string> candidates;
    uint64_t executionCount = 0;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("read_upa", neo4j_string(UNSAFE_POINTER_READ_STACK_ACTION_TYPE));
    mapEntries[2] = neo4j_map_entry("write_upa", neo4j_string(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE));

    // Fetch ASAN monitoring points
    statement =
        "MATCH (mp:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE mp.program_name=$program_name AND (mp.action_type=$read_upa OR mp.action_type=$write_upa)   RETURN mp.id, p.dbgID,p.instruction,p.function_name,mp.action_type ORDER BY mp.id";

    params = neo4j_map(mapEntries, 3);

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First MP ID
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        mpID = std::string(field);
        mpID = mpID.substr(1, mpID.length() - 2);
        memset(field, 0, 500);

        // Second dbg ID
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);

        // instruction
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);
        memset(field, 0, 500);

        // Function name
        neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        // Action type just to figure out frequency accurately
        neo4j_ntostring(neo4j_result_field(record, 4), field, 500);
        actionType = std::string(field);
        actionType = actionType.substr(1, actionType.length() - 2);
        memset(field, 0, 500);

        instructionString = processStringEscapeCharacters(instructionString);

        if (instructionString.find("call ") != std::string::npos)
            inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Call, instructionString,
                                                           functionName);

        else if (actionType.compare(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE) == 0)
        {
            inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Store, instructionString,
                                                           functionName);
        }
        else if (actionType.compare(UNSAFE_POINTER_READ_STACK_ACTION_TYPE) == 0)
        {
            inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Load, instructionString,
                                                           functionName);
        }
        else
            errs() << "\t Invalid attack action type found:" << actionType << "\n";

        if (!inst)
        {
            errs() << "Failed to find MP instruction using debug information :" << instructionString << ":" << dbgID << ":"
                   << functionName << ":" << actionType << "\n\n";

            isEntirelyInlined = false;
            candidates.clear();
            Function *function = findFunctionUsingNameAndMD(functionName, isEntirelyInlined, candidates);

            // Approximates coverage
            executionCount = 0;
            if (function)
            {
                inst = function->getEntryBlock().getFirstNonPHI();
                errs() << "\t Actually failed so approximating using entry BB " << instructionString << ":" << dbgID << ":"
                       << functionName << ":" << actionType << "\n\n";
                executionCount = getExecutionCount(inst);
            }
            else if (!candidates.empty())
            {
                for (auto candidateFuncName : candidates)
                {
                    auto candidateFunc = _module->getFunction(candidateFuncName);
                    inst = candidateFunc->getEntryBlock().getFirstNonPHI();
                    executionCount += getExecutionCount(inst);
                }
            }

            if (inst)
            {
                monitoringPoints.push_back(inst);
            }
        }
        else
        {
            executionCount = getExecutionCount(inst);
            monitoringPoints.push_back(inst);
        }
        monitoringPointsFrequencyMap[mpID] = executionCount;
        monitoringPointIDs.push_back(mpID);
    }

    neo4j_close_results(results);

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("read_upa", neo4j_string(UNSAFE_POINTER_READ_STACK_ACTION_TYPE));
    mapEntries[2] = neo4j_map_entry("write_upa", neo4j_string(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE));
    mapEntries[3] = neo4j_map_entry("oob_gep", neo4j_string(UNSAFE_POINTER_STATE_TYPE));

    // Fetch Baggy monitoring points
    statement =
        "MATCH (gep:AttackGraphNode)-[:EDGE]->(mp:AttackGraphNode) WHERE mp.program_name=$program_name AND (mp.action_type=$read_upa OR mp.action_type=$write_upa) AND gep.state_type=$oob_gep WITH DISTINCT gep MATCH (gep)-[:EDGE]->(p:ProgramInstruction) RETURN gep.id, p.dbgID,p.instruction,p.function_name ORDER BY gep.id";

    params = neo4j_map(mapEntries, 4);

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First MP ID
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        mpID = std::string(field);
        mpID = mpID.substr(1, mpID.length() - 2);
        memset(field, 0, 500);

        // Second dbg ID
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);

        // instruction
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);
        memset(field, 0, 500);

        // Function name
        neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        instructionString = processStringEscapeCharacters(instructionString);

        inst = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::GetElementPtr, instructionString,
                                                       functionName);

        if (!inst)
        {
            errs() << "Failed to find MP instruction using debug information :" << instructionString << ":" << dbgID << ":"
                   << functionName << ":" << actionType << "\n\n";

            isEntirelyInlined = false;
            candidates.clear();
            Function *function = findFunctionUsingNameAndMD(functionName, isEntirelyInlined, candidates);

            // Approximates coverage
            executionCount = 0;
            if (function)
            {
                inst = function->getEntryBlock().getFirstNonPHI();
                errs() << "\t Approximating using entry BB " << instructionString << ":" << dbgID << ":"
                       << functionName << ":" << actionType << "\n\n";
                executionCount = getExecutionCount(inst);
            }

            else if (!candidates.empty())
            {
                for (auto candidateFuncName : candidates)
                {
                    auto candidateFunc = _module->getFunction(candidateFuncName);
                    inst = candidateFunc->getEntryBlock().getFirstNonPHI();
                    executionCount += getExecutionCount(inst);
                }
            }

            if (inst)
            {
                monitoringPoints.push_back(inst);
            }
        }
        else
        {
            executionCount = getExecutionCount(inst);
            monitoringPoints.push_back(inst);
        }
        monitoringPointsFrequencyMap[mpID] = executionCount;
        monitoringPointIDs.push_back(mpID);
    }

    neo4j_close_results(results);
    neo4j_close(connection);
    return true;
}

std::string CostEstimationPass::getFunctionDebugInfo(std::string functionName)
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

    // Fetch monitoring points
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
    if (dbgID.empty() || dbgID.compare("ul") == 0)
        errs() << "\t Failed to find function dbg id :" << functionName << "\n";

    neo4j_close_results(results);
    neo4j_close(connection);
    return dbgID;
}

// Goal here is to correlate for frequency info so any instruction in BB will do
Instruction *CostEstimationPass::findInstructionInFunctionUsingDebugInfo(std::string dbgID, unsigned int opcode,
                                                                         std::string instructionString,
                                                                         std::string functionName)
{
    std::set<Instruction *> potentialMatches;
    Instruction *instruction = NULL;
    Instruction *requiredInst = NULL;
    std::string instructionDbgID;
    bool multiple = false;
    std::set<std::string> candidates;
    Function *function = findFunctionUsingNameAndMD(functionName, multiple, candidates);
    if (dbgID.compare("ul") == 0)
    {
        errs() << "\t Invalid inst DI:" << functionName << "\n";
        return instruction;
    }

    if (!function)
    {

        // TODO - query here to find all functions which container DI i.e. same file as the function we're looking for
        if (candidates.empty())
            errs()
                << "\t Function not found:" << functionName << " - even using DI and checking for inlining using DI:"<< getFunctionDebugInfo(functionName)<<"\n";
        return nullptr;
    }

    for (auto bb_iter = function->begin(); bb_iter != function->end(); bb_iter++)
    {
        for (auto inst_it = bb_iter->begin(); inst_it != bb_iter->end(); inst_it++)
        {
            instruction = &*inst_it;

            if (instruction->getOpcode() != opcode)
                continue;
            //            errs() << "\t" << instruction->getOpcode() << "==" << opcode << "\n";
            DILocation *loc = instruction->getDebugLoc();
            if (!loc)
            {
                continue;
            }
            instructionDbgID = loc->getFilename();
            instructionDbgID =
                instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" +
                std::to_string(loc->getColumn());
            // errs() << "\t" << dbgID << "==" << instructionDbgID << "\n";
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
        //        errs() << "\t Looking for" << instructionString << "\n";
        std::string currInstString;
        llvm::raw_string_ostream rso(currInstString);
        for (auto bb_iter = function->begin(); bb_iter != function->end(); bb_iter++)
        {
            for (auto inst_it = bb_iter->begin(); inst_it != bb_iter->end(); inst_it++)
            {
                instruction = &*inst_it;

                if (instruction->getOpcode() != opcode)
                    continue;
                DILocation *loc = instruction->getDebugLoc();
                if (!loc || (loc->getLine() == 0 && loc->getColumn() == 0))
                    potentialMatches.insert(instruction);
                if (loc)
                {
                    rso << *instruction;
                    currInstString = currInstString.substr(0, currInstString.find("!dbg"));
                    if (instructionString.find(currInstString) != std::string::npos)
                        return instruction;
                }
            }
        }

        currInstString.clear();
        rso.flush();
        for (auto pInst : potentialMatches)
        {
            rso << *pInst;
            if ((currInstString.find("=") != std::string::npos) &&
                (currInstString.find("\*") != std::string::npos))
            {

                // if (isa<StoreInst>(pInst))
                return pInst;
                currInstString = currInstString.substr(currInstString.find("="),
                                                       currInstString.find("\*") - currInstString.find("="));
                // errs()<<"\t"<<currInstString<<"=="<<instructionString<<"\n";
                if (instructionString.find(currInstString) != std::string::npos)
                {
                    //                    errs() << "\t" << *pInst << "\n";
                    //                        errs() << "\t" << currInstString << " in" << instructionString << "\n";
                    //                        errs() << "\t" << instructionString << "\n";
                    return pInst;
                }
            }
            rso.flush();
            currInstString.clear();
        }

        errs() << "\t No potential matches for IR instruction found using debug info in " << functionName << ":"
               << potentialMatches.size()
               << "\n";
        return nullptr;
    }
    else
        return requiredInst;

    /*  Macros are inconvenient as Debugloc info of the macro expansion instructions would map to a single source line.
        Doesn't matter for coverage as same BB */

    return nullptr;
}

bool CostEstimationPass::cacheFunction(Function *function)
{
    std::string functionName = function->getName();
    std::string instructionDbgID;
    DILocation *loc = NULL;
    Instruction *inst = NULL;
    if (function == NULL || function->isIntrinsic() || function->empty())
        return false;
    for (auto bb_iter = function->begin(); bb_iter != function->end(); bb_iter++)
    {
        for (auto inst_it = bb_iter->begin(); inst_it != bb_iter->end(); inst_it++)
        {
            inst = &*inst_it;
            loc = inst_it->getDebugLoc();
            if (!loc || loc->isImplicitCode())
            {
                // errs() << "No dbg info(or corrupt):" << *inst << "\n";
                continue;
            }
            instructionDbgID = loc->getFilename();
            instructionDbgID = instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" +
                               std::to_string(loc->getColumn());
            cache[instructionDbgID] = inst;
            instructionDbgID.clear();
        }
    }
    return true;
}

void CostEstimationPass::getAnalysisUsage(AnalysisUsage &AU) const
{
    // This pass has no reason to modify IR
    AU.addRequired<CostEstimationFunctionPass>();
    AU.addRequired<FunctionScanPass>();

    AU.setPreservesAll();
}

char CostEstimationPass::ID = 0;
static RegisterPass<CostEstimationPass>
    X("estimate-cost", "Estimates cost", false, true);
