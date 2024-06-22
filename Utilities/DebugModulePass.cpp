#include "DebugLocIDPass.hh"

cl::opt<bool> getDIForUnsafeMemOperations("mem", cl::desc("DI for unsafe mem operations"), cl::Hidden, cl::init(false));

/**
 * To reactively set dbg based id for interesting nodes (can do at function granularity or the entire program as well)
 */

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

void DebugLocModulePass::findUnsafeFunctions()
{
    std::string statement;
    std::string functionName;
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t actionNodeTypeValue;
    neo4j_value_t programNameValue;
    neo4j_value_t upaTypeValue;
    neo4j_map_entry_t mapEntries[4];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    programNameValue = neo4j_string(programName.c_str());

    if (!getDIForUnsafeMemOperations)
    {
        //  OOB GEPs (All). TODO- Add another option here
        mapEntries[0] = neo4j_map_entry("unsafe_oob_type", neo4j_string(UNSAFE_POINTER_STATE_TYPE));
        mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
        params = neo4j_map(mapEntries, 2);

        // statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND a.state_type=$unsafe_oob_type AND NOT EXISTS(p.dbgID) RETURN DISTINCT p.function_name";

        statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND a.state_type=$unsafe_oob_type  RETURN DISTINCT p.function_name";

        results = neo4j_run(connection, statement.c_str(), params);

        while ((record = neo4j_fetch_next(results)) != NULL)
        {
            // Function name
            neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
            functionName = std::string(field);
            functionName = functionName.substr(1, functionName.length() - 2);
            functionsToAnalyze.insert(functionName);
            memset(field, 0, 500);
        }

        neo4j_close_results(results);

        // Unsafe objects (this should be done in unsafe ptr analyzer?)
        upaTypeValue = neo4j_string(UNSAFE_STACK_OBJECT);
        mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
        mapEntries[1] = neo4j_map_entry("unsafe_object_type", upaTypeValue);
        params = neo4j_map(mapEntries, 2);
        // statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name  AND a.state_type=$unsafe_object_type AND NOT EXISTS(p.dbgID) RETURN DISTINCT p.function_name";
        statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name  AND a.state_type=$unsafe_object_type RETURN DISTINCT p.function_name";

        results = neo4j_run(connection, statement.c_str(), params);

        while ((record = neo4j_fetch_next(results)) != NULL)
        {
            // Function name
            neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
            functionName = std::string(field);
            functionName = functionName.substr(1, functionName.length() - 2);
            functionsToAnalyze.insert(functionName);
            memset(field, 0, 500);
        }

        neo4j_close_results(results);
    }
    else
    {
        // All unsafe operations - (which may be in a different function)

        errs() << "Add all functions with unsafe mem ops and unsafe objects\n";
        actionNodeTypeValue = neo4j_string(ACTION_TYPE);
        upaTypeValue = neo4j_string(UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE);
        mapEntries[0] = neo4j_map_entry("action_type", actionNodeTypeValue);
        mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
        mapEntries[2] = neo4j_map_entry("upa_action_type", upaTypeValue);
        mapEntries[3] = neo4j_map_entry("read_upa_action_type", neo4j_string(UNSAFE_POINTER_READ_STACK_ACTION_TYPE));

        params = neo4j_map(mapEntries, 4);
        statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND a.type=$action_type AND (a.action_type=$upa_action_type OR a.action_type=$read_upa_action_type )  RETURN DISTINCT p.function_name";

        // statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND a.type=$action_type AND (a.action_type=$upa_action_type OR a.action_type=$read_upa_action_type ) AND NOT EXISTS(p.dbgID) RETURN DISTINCT p.function_name";

        results = neo4j_run(connection, statement.c_str(), params);

        while ((record = neo4j_fetch_next(results)) != NULL)
        {
            // Function name
            neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
            functionName = std::string(field);
            functionName = functionName.substr(1, functionName.length() - 2);
            functionsToAnalyze.insert(functionName);
            memset(field, 0, 500);
        }

        neo4j_close_results(results);
    }

    // The  Potential OOB GEPs
    /*  mapEntries[0] = neo4j_map_entry("unsafe_oob_type", neo4j_string(UNSAFE_MAYBE_STACK_OOB_STATE_TYPE));
     mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
     params = neo4j_map(mapEntries, 2);

     statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name AND a.state_type=$unsafe_oob_type RETURN DISTINCT p.function_name";

     results = neo4j_run(connection, statement.c_str(), params);

     while ((record = neo4j_fetch_next(results)) != NULL)
     {
         // Function name
         neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
         functionName = std::string(field);
         functionName = functionName.substr(1, functionName.length() - 2);
         functionsToAnalyze.insert(functionName);
         memset(field, 0, 500);
     }

     neo4j_close_results(results);

    // mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    // params = neo4j_map(mapEntries, 1);
    // statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name WITH DISTINCT p MATCH (p1:Entry) WHERE p1.program_name=p.program_name AND p1.function_name=p.function_name AND NOT EXISTS(p1.dbgID) RETURN DISTINCT p.function_name";
    // // statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name=p.program_name=$program_name  AND a.state_type=$unsafe_object_type RETURN DISTINCT p.function_name";

    // results = neo4j_run(connection, statement.c_str(), params);

    // while ((record = neo4j_fetch_next(results)) != NULL)
    // {
    //     // Function name
    //     neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
    //     functionName = std::string(field);
    //     functionName = functionName.substr(1, functionName.length() - 2);
    //     functionsToAnalyze.insert(functionName);
    //     memset(field, 0, 500);
    // }

    // neo4j_close_results(results);

    */
    neo4j_close(connection);
}

bool DebugLocModulePass::runOnModule(Module &M)
{
    programName = M.getModuleIdentifier();
    programName = programName.substr(0, programName.length() - 3);

    findUnsafeFunctions();
    /*
           for (auto func_name : functionsToAnalyze)
           {
               auto func = M.getFunction(func_name);
               if (func)
               {

                       &getAnalysis<DebugLocIDPass>(*func);

                  // for (auto inst_it = inst_begin(func); inst_it != inst_end(func); inst_it++)
                  // {
                       //if (isa<GetElementPtrInst>(&*inst_it) || isa<StoreInst>(&*inst_it) || isa<LoadInst>(&*inst_it) || isa<CallInst>(&*inst_it))
                       //    findProgramInstructionInPDG(&*inst_it);

                  // }
               }
    }*/

    // errs()<<"# function names found:"<<functionsToAnalyze.size()<<"\n";
    // functionsToAnalyze.insert("ossl_a2ulabel");
    for (auto &funcName : functionsToAnalyze)
    {
        auto func = M.getFunction(funcName);
        if (!func || func->empty() || func->isIntrinsic() || func->isDeclaration())
            continue;

        // if (func->getName().contains("gcov"))
        //     continue;

        &getAnalysis<DebugLocIDPass>(*func);
    }

    return false;
}

std::string
DebugLocModulePass::findProgramInstructionInPDG(Instruction *instruction)
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

void DebugLocModulePass::getAnalysisUsage(AnalysisUsage &AU) const
{
    AU.addRequired<DebugLocIDPass>();
    AU.setPreservesAll();
}

char DebugLocModulePass::ID = 0;
static RegisterPass<DebugLocModulePass>
    X("dbgid", "Generate debug info based unique ids (module) ", false, true);
