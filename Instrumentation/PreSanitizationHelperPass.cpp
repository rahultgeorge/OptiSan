#include "SanitizerHelperPass.hh"

using namespace llvm;

/**
 * This is a pre sanitization pass - essentially guides the sanitization (Function granularity)
 * 1. Identifies which functions need to be instrumented
 * 2. Annotates instructions (monitoring points) as per computed placement
 */

inline void displayErrorAndExit(std::string message)
{
    errs() << message << "\n";
    exit(0);
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
        instructionString.replace(replacePos, 2, "\"");
        replacePos = instructionString.find("\\\"");
    }

    return instructionString;
}

inline std::string getFunctionDebugInfo(std::string functionName, std::string programName)
{
    std::string statement;
    std::string field_string;
    std::string dbgID = "";

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 1500);
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
        neo4j_ntostring(neo4j_result_field(record, 0), field, 1500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 1500);
    }
    if (dbgID.empty())
        errs() << "\t Failed to find function dbg id:" << functionName << "\n";

    neo4j_close_results(results);
    neo4j_close(connection);
    return dbgID;
}

Instruction *
PreSanitizationHelper::findInstructionInFunctionUsingDebugInfo(std::string dbgID, unsigned int opcode,
                                                               std::string instructionString, Function *function, FunctionScanPass *scanPass)
{
    std::set<Instruction *> potentialMatches;
    std::set<std::string> potentialIRMatches;
    Instruction *instruction = nullptr;
    Instruction *requiredInst = nullptr;
    std::string instructionDbgID;
    std::set<Instruction *> dbgAddrInstructions;

    if (dbgID.empty() || dbgID.compare("null") == 0 || !function)
        return nullptr;

    if (scanPass)
    {
        requiredInst = scanPass->findInstructionUsingDBGID(dbgID);
        if (requiredInst)
            return requiredInst;

        potentialIRMatches = scanPass->findInstructionIRUsingDBGID(dbgID);
        instructionString = processStringEscapeCharacters(instructionString);
        instructionString = instructionString.substr(0, instructionString.find("!dbg"));

        // errs() << "Instruction string:" << instructionString << "\n";
        for (auto potentialMatchInstString : potentialIRMatches)
        {
            if (scanPass->instructionIRToInstMap.find(potentialMatchInstString) == scanPass->instructionIRToInstMap.end())
            {
                // errs() << "Potential match:" << potentialMatchInstString << ":" << dbgID << "not found"
                //        << "\n";

                continue;
            }
            auto potentialMatchInst = scanPass->instructionIRToInstMap[potentialMatchInstString];
            if (potentialMatchInst)
            {
                // errs() << "\t" << *potentialMatchInst << "\n";

                if (potentialMatchInst->getOpcode() != opcode)
                    continue;
                if (opcode == llvm::Instruction::GetElementPtr)
                {
                    if (potentialMatchInst->hasMetadata(BAGGY_MONITORING_POINT))
                        continue;
                }
                else if (opcode == llvm::Instruction::Load || opcode == llvm::Instruction::Store)
                {
                    if (potentialMatchInst->hasMetadata(ASAN_MONITORING_POINT))
                        continue;
                }
                requiredInst = potentialMatchInst;

                potentialMatches.insert(potentialMatchInst);
                potentialMatchInstString = potentialMatchInstString.substr(0, potentialMatchInstString.find("!dbg"));
                if (instructionString.compare(potentialMatchInstString) == 0)
                {
                    // Match
                    // errs() << instructionString << "==" << potentialMatchInstString << "\n";
                    return requiredInst;
                }
            }
            else
            {
                errs() << "\t" << potentialMatchInstString << " not found in scan pass\n";
            }
        }
    }

    if (!potentialMatches.empty())
        return requiredInst;
    else
    {

        /*        if (opcode == llvm::Instruction::Alloca)
               {
                   for (auto inst_it = inst_begin(function); inst_it != inst_end(function); inst_it++)
                   {
                       instruction = &*inst_it;
                       if (isa<DbgDeclareInst>(instruction))
                       {
                           dbgAddrInstructions.insert(instruction);
                       }
                   }

                   for (auto dbgInst : dbgAddrInstructions)
                   {
                       DbgDeclareInst *dbgDeclareInst = dyn_cast<DbgDeclareInst>(dbgInst);
                       Instruction *stackVar = dyn_cast<Instruction>(dbgDeclareInst->getAddress());

                       DILocation *loc = dbgDeclareInst->getDebugLoc();
                       if (!loc || loc->isImplicitCode() || (!stackVar))
                       {
                           //                errs() << "No dbg info(or corrupt):" << *instruction << "\n";
                           continue;
                       }
                       instructionDbgID = loc->getFilename();
                       instructionDbgID =
                           instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" + std::to_string(loc->getColumn());
                       if (instructionDbgID.compare(dbgID) == 0)
                       {
                           // Match
                           // errs() << "\t DBG match:" << *stackVar << "\n";
                           requiredInst = stackVar;
                           potentialMatches.insert(stackVar);
                       }
                   }
               }
               else
               {
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
                               // errs() << "\t DBG match:" << instructionDbgID << "\n";

                               requiredInst = instruction;
                               potentialMatches.insert(instruction);
                           }
                           instructionDbgID.clear();
                       }
                   }
               }
               if (potentialMatches.size() == 1)
                   return requiredInst;

               std::string currInstIRString;
               raw_string_ostream rso(currInstIRString);

               instructionString = processStringEscapeCharacters(instructionString);
               instructionString = instructionString.substr(0, instructionString.find("!dbg"));

               // Macros are inconvenient as Debugloc info of the macro expansion instructions would map to a single source line. We are building the binary the same way (same flags) but for some reason exact dbg loc is off so cannot use string IR
               // A little hacky but difficult to reason about macros (We run this pass on the IR generated from (almost) the same config as we analyze O0 g
               for (auto inst_it : potentialMatches)

               {
                   instruction = &*inst_it;
                   rso << *instruction;
                   currInstIRString = currInstIRString.substr(0, currInstIRString.find("!dbg"));
                   if (instructionString.compare(currInstIRString) == 0)
                   {
                       // Match
                       // errs() << "\t Exact match:" << currInstIRString << "\n";
                       // errs() << "\t Inst string:" << instructionString << "\n";
                       return instruction;
                   }

                   rso.flush();
                   currInstIRString.clear();
               }
               // errs() << "\t Failed to find using IR string:" << instructionString << "\n";

               if (!potentialMatches.empty())
                   return requiredInst; */
        // errs() << "Potential matches:" << potentialMatches.size() << ":" << potentialIRMatches.size() << "\n";
        return nullptr;
    }
}

Function *PreSanitizationHelper::findFunctionUsingDebugInfo(std::string functionName)
{
    Function *function = nullptr;
    std::string functionDBGID = "";

    if (dbFunctionNameToModuleFunctionDI.empty())
        functionDBGID = getFunctionDebugInfo(functionName, programName);
    else
    {
        if (dbFunctionNameToModuleFunctionDI.find(functionName) != dbFunctionNameToModuleFunctionDI.end())
            functionDBGID = dbFunctionNameToModuleFunctionDI[functionName];
    }
    if (!functionDBGID.empty())
    {
        if (moduleFunctionDIToFunctionMap.find(functionDBGID) != moduleFunctionDIToFunctionMap.end())
            return moduleFunctionDIToFunctionMap[functionDBGID];
    }

    /*     std::string currentFuncDI = "";

        // Find the function
        for (auto &func : module->functions())
        {
            DISubprogram *subprogram = func.getSubprogram();
            if (!subprogram)
                continue;

            if (func.isDeclaration())
                continue;

            currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
            if (currentFuncDI.compare(functionDBGID) == 0)
            {
                function = &func;
                break;
            }
        }
        */

    return nullptr;
}

void PreSanitizationHelper::findAllWhiteListedFunctions()
{
    std::string statement;
    std::string functionName;

    std::set<std::string> metadataFunctionOperations;
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue, unsafeStackObjectValue;
    neo4j_map_entry_t mapEntries[1];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    unsafeStackObjectValue = neo4j_string(UNSAFE_STACK_OBJECT);

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("unsafe_stack_obj", unsafeStackObjectValue);

    params = neo4j_map(mapEntries, 2);

    // Whitelisted functions are ones which we don't have exec info for
    statement = "  MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=$program_name AND a.state_type=$unsafe_stack_obj WITH DISTINCT p MATCH (p1:Entry) WHERE p1.program_name=p.program_name AND p1.function_name=p.function_name AND NOT EXISTS (p1.count_ref)  RETURN DISTINCT p1.function_name ";

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        //  function name
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        functionsWhiteList.insert(functionName);
        memset(field, 0, 500);
    }

    neo4j_close_results(results);
    neo4j_close(connection);
#ifdef DEBUG
    {

        errs() << "# Whitelisted functions:" << functionsWhiteList.size()
               << "\n";
    }
#endif

}

bool PreSanitizationHelper::isCurrentModuleRelevant()
{

    std::string statement;
    std::string functionDebugID;
    std::string dbFunctionName;
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 1000);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t functionDebugIDValue;

    neo4j_map_entry_t mapEntries[2];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);

    // Identify functions in module which are relevant, funcMP or Entry (more general)
    statement = " MATCH (a:Entry) WHERE a.program_name=$program_name AND a.dbgID=$function_debug_id RETURN a.function_name ";

    for (auto functionDbgNameMapIt : moduleFunctionDIToFunctionMap)
    {
        functionDebugIDValue = neo4j_string(functionDbgNameMapIt.first.c_str());

        mapEntries[1] = neo4j_map_entry("function_debug_id", functionDebugIDValue);
        dbFunctionName.clear();
        params = neo4j_map(mapEntries, 2);
        results = neo4j_run(connection, statement.c_str(), params);
        // errs() << "CHecking for function DI:" << functionDbgNameMapIt.first << "\n";
        while ((record = neo4j_fetch_next(results)) != NULL)
        {
            // Node id
            neo4j_ntostring(neo4j_result_field(record, 0), field, 1000);
            dbFunctionName = std::string(field);
            dbFunctionName = dbFunctionName.substr(1, dbFunctionName.length() - 2);

            if (!dbFunctionName.empty())
            {
                dbFunctionNameToModuleFunctionDI[dbFunctionName] = functionDbgNameMapIt.first;
            }
            memset(field, 0, 1000);
        }
        // errs() << "\t Not present in DB function DI:" << functionDbgNameMapIt.first << ":" << functionDBNodeID << "\n";
    }
    neo4j_close_results(results);
    neo4j_close(connection);
    return !dbFunctionNameToModuleFunctionDI.empty();
}

void PreSanitizationHelper::fetchFunctionsToBeSanitized()
{
    std::string statement;
    std::string functionName;
    std::string instructionString;
    std::string dbgID;
    std::string monitorType;
    std::string monitoringPointID;
    std::set<std::string> monitoringPointIDS;
    MonitorType currMonitor;
    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t upaIDValue;
    neo4j_value_t functionNameValue;

    neo4j_map_entry_t mapEntries[2];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());
    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    params = neo4j_map(mapEntries, 1);

    // Check and find any functions which are whitelisted
    findAllWhiteListedFunctions();
#ifdef DEBUG
    start = std::chrono::high_resolution_clock::now();
#endif
    // Step 1 - Fetch functions containing check operations using relevant functions found in this module
    for (auto funcNameToDIIt : dbFunctionNameToModuleFunctionDI)
    {
        statement = " MATCH (a:MP)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND EXISTS (a.monitor) AND p.function_name=$function_name RETURN  DISTINCT p.function_name, a.monitor ";
        functionNameValue = neo4j_string(funcNameToDIIt.first.c_str());
        mapEntries[1] = neo4j_map_entry("function_name", functionNameValue);
        params = neo4j_map(mapEntries, 2);
        results = neo4j_run(connection, statement.c_str(), params);

        while ((record = neo4j_fetch_next(results)) != NULL)
        {
            // First function name
            neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
            functionName = std::string(field);
            functionName = functionName.substr(1, functionName.length() - 2);
            memset(field, 0, 500);

            // Second monitor
            neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
            monitorType = std::string(field);
            monitorType = monitorType.substr(1, monitorType.length() - 2);
            memset(field, 0, 500);
            if (monitorType.compare("BBC") == 0)
                currMonitor = MonitorType::BaggyBounds;
            else if (monitorType.compare("ASAN") == 0)
                currMonitor = MonitorType::ASAN;
            else
                currMonitor = MonitorType::UNKNOWN;

            if (monitorTypeToFunctions.find(currMonitor) == monitorTypeToFunctions.end())
            {
                errs() << "Unknown monitor specified:" << monitorType << "\n";
                continue;
            }

            // Only difference from code below is that the code below includes an unnecessary map lookup (dbFunctionNameToModuleFunctionDI)
            auto func = moduleFunctionDIToFunctionMap[funcNameToDIIt.second];
            monitorTypeToFunctions[currMonitor].insert(func);
            functionsToBeSanitizedInModule.insert(func);

            /*   if (functionsWhiteList.find(functionName) != functionsWhiteList.end())
                  continue;
              if (auto func = findFunctionUsingDebugInfo(functionName))
              {
                  monitorTypeToFunctions[currMonitor].insert(func);
                  functionsToBeSanitizedInModule.insert(func);
                  if (!func)
                      continue;
              } */
        }

        neo4j_close_results(results);
    }
    neo4j_close(connection);
#ifdef DEBUG
    {
        errs() << "# MPs as per the computed placement:" << monitoringPointIDS.size()
               << "\n";
        stop = std::chrono::high_resolution_clock::now();
        duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
        errs() << "Time for fetching functions (sub task only check functions):" << duration.count() << "\n";
        start = std::chrono::high_resolution_clock::now();
    }
#endif

    // Step 2 a - Fetch metadata functions - contain the unsafe objects for (ASAN) so obj->GEP->UPA
    neo4j_value_t asanMonitorTypeValue;
    neo4j_value_t baggyMonitorTypeValue;
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    programNameValue = neo4j_string(programName.c_str());
    currMonitor = MonitorType::ASAN;
    monitorType = monitorTypeToString(currMonitor);
    asanMonitorTypeValue = neo4j_string(monitorType.c_str());

    mapEntries[0] = neo4j_map_entry("asan_monitor", asanMonitorTypeValue);
    mapEntries[1] = neo4j_map_entry("program_name", programNameValue);

    params = neo4j_map(mapEntries, 2);

    statement = " MATCH (p:ProgramInstruction)<-[:EDGE]-(source:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(action:MP) WHERE action.monitor=$asan_monitor AND action.program_name=$program_name  RETURN  DISTINCT p.function_name";

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // Function name
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        if (monitorTypeToFunctions.find(currMonitor) == monitorTypeToFunctions.end())
        {
            errs() << "Unknown monitor specified:" << monitorType << "\n";
            continue;
        }
        if (functionsWhiteList.find(functionName) != functionsWhiteList.end())
            continue;
        if (auto func = findFunctionUsingDebugInfo(functionName))
        {
            monitorTypeToFunctions[currMonitor].insert(func);
            functionsToBeSanitizedInModule.insert(func);
        }
    }

    neo4j_close_results(results);

    // Step 2 b - Fetch functions containing the unsafe objects (Baggy) obj->GEP
    programNameValue = neo4j_string(programName.c_str());
    currMonitor = MonitorType::BaggyBounds;
    monitorType = monitorTypeToString(currMonitor);
    baggyMonitorTypeValue = neo4j_string(monitorType.c_str());

    mapEntries[0] = neo4j_map_entry("baggy_monitor", baggyMonitorTypeValue);
    mapEntries[1] = neo4j_map_entry("program_name", programNameValue);

    params = neo4j_map(mapEntries, 2);

    statement = " MATCH (p:ProgramInstruction)<-[:EDGE]-(source:AttackGraphNode)-[:SOURCE]->(gep:MP) WHERE gep.monitor=$baggy_monitor AND gep.program_name=$program_name  RETURN  DISTINCT p.function_name";

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // Function name
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        if (monitorTypeToFunctions.find(currMonitor) == monitorTypeToFunctions.end())
        {
            errs() << "Unknown monitor specified:" << monitorType << "\n";
            continue;
        }
        if (functionsWhiteList.find(functionName) != functionsWhiteList.end())
            continue;
        if (auto func = findFunctionUsingDebugInfo(functionName))
        {
            monitorTypeToFunctions[currMonitor].insert(func);
            functionsToBeSanitizedInModule.insert(func);
        }
    }

/*     connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
for (auto upaID : monitoringPointIDS)
{
    upaIDValue = neo4j_string(upaID.c_str());
    mapEntries[0] = neo4j_map_entry("upa_id", upaIDValue);
    params = neo4j_map(mapEntries, 1);

    statement = " MATCH (source:AttackGraphNode)-[:SOURCE]->(state:AttackGraphNode)-[:EDGE]->(action:MP) WHERE action.id=$upa_id WITH DISTINCT source,action MATCH (source)-[:EDGE]->(p:ProgramInstruction) RETURN  DISTINCT p.function_name,action.monitor";

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {

        // Function name
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        monitorType = std::string(field);
        monitorType = monitorType.substr(1, monitorType.length() - 2);
        memset(field, 0, 500);
        if (monitorType.compare("ASAN") == 0)
            currMonitor = MonitorType::ASAN;
        else
            currMonitor = MonitorType::UNKNOWN;
        memset(field, 0, 500);

        if (monitorTypeToFunctions.find(currMonitor) == monitorTypeToFunctions.end())
        {
            errs() << "Unknown monitor specified:" << monitorType << "\n";
            continue;
        }
        if (functionsWhiteList.find(functionName) != functionsWhiteList.end())
            continue;
        if (auto func = findFunctionUsingDebugInfo(functionName))
        {
            monitorTypeToFunctions[currMonitor].insert(func);
            functionsToBeSanitized.insert(func);
        }
    }
}
neo4j_close_results(results);

// Step 2 b - Fetch functions containing the unsafe objects (Baggy) obj->GEP

for (auto upaID : monitoringPointIDS)
{
    upaIDValue = neo4j_string(upaID.c_str());
    mapEntries[0] = neo4j_map_entry("upa_id", upaIDValue);
    params = neo4j_map(mapEntries, 1);

    statement = " MATCH (source:AttackGraphNode)-[:SOURCE]->(action:AttackGraphNode) WHERE action.id=$upa_id WITH DISTINCT source,action MATCH (source)-[:EDGE]->(p:ProgramInstruction) RETURN  DISTINCT p.function_name,action.monitor";

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {

        // Function name
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        monitorType = std::string(field);
        monitorType = monitorType.substr(1, monitorType.length() - 2);
        memset(field, 0, 500);
        if (monitorType.compare("BBC") == 0)
            currMonitor = MonitorType::BaggyBounds;
        else
            currMonitor = MonitorType::UNKNOWN;
        memset(field, 0, 500);

        if (monitorTypeToFunctions.find(currMonitor) == monitorTypeToFunctions.end())
        {
            errs() << "Unknown monitor specified:" << monitorType << "\n";
            continue;
        }
        if (functionsWhiteList.find(functionName) != functionsWhiteList.end())
            continue;
        if (auto func = module->getFunction(functionName))
        {
            monitorTypeToFunctions[currMonitor].insert(func);
            functionsToBeSanitized.insert(func);
        }
    }
}
*/
#ifdef DEBUG
    {
        for (auto monitor : monitors)
        {
            errs() << "# Functions including source metadata " << monitorTypeToString(monitor) << ":" << monitorTypeToFunctions[monitor].size() << "\n";
        }
        errs() << "# Overall Functions to be instrumented:" << functionsToBeSanitizedInModule.size() << "\n";
        stop = std::chrono::high_resolution_clock::now();
        duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
        errs() << "Time for fetching functions (sub task only MD functions):" << duration.count() << "\n";
    }
#endif

    neo4j_close_results(results);
    neo4j_close(connection);
}

void PreSanitizationHelper::fetchAndAnnotateOperationsToBeMonitored()
{
    // Step 1 - Find monitoring points
    std::string statement;
    std::string functionName;
    std::string instructionString;
    std::string dbgID;
    std::string errorMessage;
    std::string monitorType;

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    uint64_t numBaggyInst = 0;
    uint64_t numASANInst = 0;
    uint64_t numASANObjs = 0;
    uint64_t numBaggyObjs = 0;

    neo4j_connection_t *connection;
    neo4j_map_entry_t mapEntries[1];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    // if (functionsToBeSanitizedInModule.empty())
    //     return;

    // Metadata to annotate necessary instructions
    MDNode *MD = MDNode::get(module->getContext(), {});

    Instruction *monitoringPoint = nullptr;
    Function *currentFunction = nullptr;
    std::string currentFunctionDBName = "";

    FunctionScanPass *functionScanPass = NULL;

    // Fetch monitoring point for ASAN
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    mapEntries[0] = neo4j_map_entry("program_name", neo4j_string(programName.c_str()));

    params = neo4j_map(mapEntries, 1);

    statement = " MATCH (monitoringPoint:MP)-[:EDGE]->(p:ProgramInstruction) WHERE monitoringPoint.program_name=p.program_name=$program_name AND  EXISTS(monitoringPoint.monitor) RETURN  monitoringPoint.monitor,p.dbgID,p.instruction,p.function_name,monitoringPoint.action_type ORDER BY p.function_name ";

    results = neo4j_run(connection, statement.c_str(), params);
    std::string actionType;
    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First monitor type
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        monitorType = std::string(field);
        monitorType = monitorType.substr(1, monitorType.length() - 2);
        memset(field, 0, 500);

        // Second dbgid
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);

        // Third instruction
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);
        memset(field, 0, 500);

        // Fourth function
        neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        // Action type for ASAN
        neo4j_ntostring(neo4j_result_field(record, 4), field, 500);
        actionType = std::string(field);
        actionType = actionType.substr(1, actionType.length() - 2);
        memset(field, 0, 500);

        if (functionName.compare(currentFunctionDBName) != 0)
        {
            currentFunction = findFunctionUsingDebugInfo(functionName);
            if (currentFunction)
            {
                functionScanPass = &getAnalysis<FunctionScanPass>(*currentFunction);
            }
            currentFunctionDBName = functionName;
        }

        // Find and annotate instruction
        monitoringPoint = nullptr;

        if (currentFunction)
        {

            if (monitorTypeToString(ASAN).compare(monitorType) == 0)
            {
                if (actionType.compare(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE) == 0)
                    monitoringPoint = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Store,
                                                                              instructionString,
                                                                              currentFunction, functionScanPass);
                else if (actionType.compare(UNSAFE_POINTER_READ_STACK_ACTION_TYPE) == 0)
                    monitoringPoint = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Load,
                                                                              instructionString,
                                                                              currentFunction, functionScanPass);

                if (monitoringPoint)
                {
                    numASANInst++;
                    // MD = MDNode::get(monitoringPoint->getContext(), {});
                    monitoringPoint->setMetadata(ASAN_MONITORING_POINT, MD);
                    assert(monitoringPoint->hasMetadata(ASAN_MONITORING_POINT));
                }
                else
                {
                    errorMessage = "**Failed to find check:" + instructionString + ":" + functionName + ":" + dbgID + "\n";
                    errs() << "ASan:" << functionName << "==" << currentFunctionDBName << "\n";
                    errs() << "ASan:" << errorMessage << ":" << currentFunction->getName() << "\n";

                    //                displayErrorAndExit(errorMessage);
                }
            }
            else if (monitorTypeToString(BaggyBounds).compare(monitorType) == 0)
            {
                monitoringPoint = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::GetElementPtr,
                                                                          instructionString,
                                                                          currentFunction, functionScanPass);
                if (monitoringPoint)
                {
                    numBaggyInst++;
                    // MD = MDNode::get(monitoringPoint->getContext(), {});
                    monitoringPoint->setMetadata(BAGGY_MONITORING_POINT, MD);
                    assert(monitoringPoint->hasMetadata(BAGGY_MONITORING_POINT));
                }
                else
                {
                    errorMessage = "Failed to find check:" + instructionString + ":" + functionName + ":" + dbgID + "\n";
                    errs() << "Baggy:" << errorMessage << "\n";

                    // displayErrorAndExit(errorMessage);
                }
            }
        }
    }

    neo4j_close_results(results);

    // Fetch unsafe objects  for ASAN
    mapEntries[0] = neo4j_map_entry("program_name", neo4j_string(programName.c_str()));

    params = neo4j_map(mapEntries, 1);

    statement = " MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(monitoringPoint:MP) WHERE monitoringPoint.program_name=p.program_name=$program_name AND  EXISTS(monitoringPoint.monitor)  WITH DISTINCT p RETURN p.dbgID,p.instruction,p.function_name ORDER BY p.function_name";
    currentFunction = nullptr;
    currentFunctionDBName = "";
    results = neo4j_run(connection, statement.c_str(), params);
    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First dbgid
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);

        // Second instruction
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);
        memset(field, 0, 500);

        // Third function
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        if (functionName.compare(currentFunctionDBName) != 0)
        {
            currentFunction = findFunctionUsingDebugInfo(functionName);
            if (currentFunction)
            {
                functionScanPass = &getAnalysis<FunctionScanPass>(*currentFunction);
                functionScanPass->processFunctionStackData();
            }
            currentFunctionDBName = functionName;
        }

        if (currentFunction)
        {
            // Find and annotate instruction
            monitoringPoint = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Alloca,
                                                                      instructionString,
                                                                      currentFunction, functionScanPass);

            if (monitoringPoint)
            {
                numASANObjs++;
                monitoringPoint->setMetadata(ASAN_STACK_OBJECT, MD);
            }
            else
            {
                errorMessage = "Failed to find stack obj:" + instructionString + ":" + functionName + ":" + dbgID + "\n";
                errs() << "ASAN:" << errorMessage << "\n";
                // displayErrorAndExit(errorMessage);
            }
        }
    }

    neo4j_close_results(results);

    // Fetch unsafe objects for Baggy
    mapEntries[0] = neo4j_map_entry("program_name", neo4j_string(programName.c_str()));

    params = neo4j_map(mapEntries, 1);

    statement = " MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(monitoringPoint:MP) WHERE monitoringPoint.program_name=p.program_name=$program_name AND  EXISTS(monitoringPoint.monitor)  WITH DISTINCT p RETURN p.dbgID,p.instruction,p.function_name ORDER BY p.function_name";
    currentFunction = nullptr;
    currentFunctionDBName = "";
    results = neo4j_run(connection, statement.c_str(), params);
    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // First dbgid
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);

        // Second instruction
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);
        memset(field, 0, 500);

        // Third function
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);

        if (functionName.compare(currentFunctionDBName) != 0)
        {
            currentFunction = findFunctionUsingDebugInfo(functionName);
            if (currentFunction)
            {
                functionScanPass = &getAnalysis<FunctionScanPass>(*currentFunction);
                functionScanPass->processFunctionStackData();
            }
            currentFunctionDBName = functionName;
        }
        if (currentFunction)
        {

            // Find and annotate instruction
            monitoringPoint = findInstructionInFunctionUsingDebugInfo(dbgID, llvm::Instruction::Alloca,
                                                                      instructionString,
                                                                      currentFunction, functionScanPass);

            if (monitoringPoint)
            {
                numBaggyObjs++;
                MD = MDNode::get(monitoringPoint->getContext(), {});
                monitoringPoint->setMetadata(BAGGY_STACK_OBJECT, MD);
            }
            else
            {
                errorMessage = "Failed to find stack obj:" + instructionString + ":" + functionName + ":" + dbgID + "\n";
                errs() << "Baggy:" << errorMessage << "\n";
                //                displayErrorAndExit(errorMessage);
            }
        }
    }

    neo4j_close_results(results);
    neo4j_close(connection);

    if (numASANInst > 0 || numASANObjs > 0)
    {
        errs() << "# Instructions (ASAN):" << numASANInst << "\n";
        errs() << "# MD Instructions (Objs) (ASAN):" << numASANObjs << "\n";
    }
    if (numBaggyInst > 0 || numBaggyObjs > 0)
    {
        errs() << "# Instructions (Baggy):" << numBaggyInst << "\n";
        errs() << "# MD Instructions (Objs) (Baggy):" << numBaggyObjs << "\n";
    }
}

bool PreSanitizationHelper::runOnModule(Module &M)
{
    char *programNameEnv = std::getenv("OPTISAN_PROGRAM_NAME");
    module = &M;

    if (OPTIMIZATION_BASELINE_MODE)
    {
        for (auto &func : M.functions())
        {
            if (func.isIntrinsic() || func.isDeclaration())
                continue;
            if (func.hasFnAttribute(Attribute::OptimizeNone))
                func.removeFnAttr(Attribute::OptimizeNone);
            if (func.hasFnAttribute(Attribute::NoInline))
                func.removeFnAttr(Attribute::NoInline);
        }
        return true;
    }

    if (TEST_MODE)
    {
        for (auto &func : M.functions())
        {
            if (func.isIntrinsic() || func.isDeclaration() || func.hasFnAttribute("no_sanitize"))
                continue;
            func.addFnAttr(Attribute::SanitizeAddress);
        }
        return true;
    }

    for (auto currMonitor : monitors)
    {
        std::set<Function *> functionsToBeMonitored;
        monitorTypeToFunctions[currMonitor] = functionsToBeMonitored;
    }

    if (programNameEnv)
    {
        programName = std::string(programNameEnv);
        errs() << "Program name (env)" << programName << "\n";

        std::string currentFuncDI = "";

        // Record functions present in this module (DI)
        for (auto &func : module->functions())
        {
            DISubprogram *subprogram = func.getSubprogram();
            if (!subprogram)
                continue;

            if (func.isDeclaration() || func.isIntrinsic() || func.empty())
                continue;
            currentFuncDI = subprogram->getFilename().str() + ":" + std::to_string(subprogram->getLine());
            moduleFunctionDIToFunctionMap[currentFuncDI] = &func;
        }
#ifdef DEBUG

        start = std::chrono::high_resolution_clock::now();

#endif

        if (isCurrentModuleRelevant())
        {

            // Identify which functions need to be instrumented and find them
            fetchFunctionsToBeSanitized();
#ifdef DEBUG

            stop = std::chrono::high_resolution_clock::now();
            duration =
                std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
            errs() << "Time for fetching functions:" << duration.count() << "\n";

            start = std::chrono::high_resolution_clock::now();
#endif

            // Identify necessary operations in those functions
            fetchAndAnnotateOperationsToBeMonitored();
#ifdef DEBUG
            {
                stop = std::chrono::high_resolution_clock::now();
                duration =
                    std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
                errs() << "Time for identifying operations:" << duration.count() << "\n";
            }
#endif
        }
    }

    MDNode *MD = MDNode::get(M.getContext(), {});

    for (auto &func : M.functions())
    {
        for (auto currMonitor : monitors)
        {
            auto functionsToMonitor = monitorTypeToFunctions[currMonitor];
            // if (!functionsToMonitor.empty())
            //     errs() << "Monitor functions:" << functionsToMonitor.size() << ":" << monitorTypeToString(currMonitor) << "\n";
            if (functionsToMonitor.find(&func) == functionsToMonitor.end())
            {
                if (currMonitor == MonitorType::BaggyBounds)
                    func.setMetadata(BAGGY_SKIP_FUNCTION, MD);
                else if (currMonitor == MonitorType::ASAN)
                    func.addFnAttr(Attribute::get(module->getContext(), "no_sanitize", "address"));
            }
            else if (currMonitor == MonitorType::ASAN)
            {
                func.addFnAttr(Attribute::SanitizeAddress);
            }
            else if (currMonitor == MonitorType::BaggyBounds)
            {
                continue;
            }
        }
    }


    return true;
}

void PreSanitizationHelper::getAnalysisUsage(AnalysisUsage &AU) const
{
    AU.addRequired<FunctionScanPass>();
    AU.setPreservesCFG();
}

char PreSanitizationHelper::ID = 0;
static RegisterPass<PreSanitizationHelper>
    Y("pre-sanitize", "Guide sanitization at function granularity through  attributes", false, false);
