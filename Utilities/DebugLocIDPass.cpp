#include "DebugLocIDPass.hh"

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

void DebugLocIDPass::processFunction()
{
    Instruction *instruction = NULL;
    std::string instructionDbgID;
    DILocation *loc = NULL;
    instructionDbgIDMap.clear();

    std::set<Instruction *> dbgAddrInstructions;
    for (auto inst_it = inst_begin(funcBeingAnalyzed); inst_it != inst_end(funcBeingAnalyzed); inst_it++)
    {
        instruction = &*inst_it;

        if (isa<DbgDeclareInst>(instruction))
        {
            dbgAddrInstructions.insert(instruction);
        }
        // TODO- Clean up properly later. Revisit whether visitor is more efficient || isa<AllocaInst>(instruction)
        if (!(isa<StoreInst>(instruction) || isa<LoadInst>(instruction) || isa<MemIntrinsic>(instruction) ||
              isa<GetElementPtrInst>(instruction) || isa<CallInst>(instruction)))
        {
            continue;
        }
        loc = inst_it->getDebugLoc();
        if (!loc || loc->isImplicitCode())
        {
            // errs() << "No dbg info(or corrupt):" << *instruction << "\n";
            continue;
        }
        instructionDbgID = loc->getFilename();
        instructionDbgID =
            instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" + std::to_string(loc->getColumn());
        instructionDbgIDMap[instruction] = instructionDbgID;
        instructionDbgID.clear();
    }

    // Deal with stack objects
    instructionDbgID.clear();

    for (auto dbgInst : dbgAddrInstructions)
    {
        DbgDeclareInst *dbgDeclareInst = dyn_cast<DbgDeclareInst>(dbgInst);
        Instruction *stackVar = dyn_cast<Instruction>(dbgDeclareInst->getAddress());

        loc = dbgDeclareInst->getDebugLoc();
        if (!loc || loc->isImplicitCode() || (!stackVar))
        {
            errs() << "No dbg info(or corrupt):" << *instruction << "\n";
            continue;
        }
        instructionDbgID = loc->getFilename();
        instructionDbgID =
            instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" + std::to_string(loc->getColumn());
        // errs() << "Alloca:" << *stackVar << "\n";
        // errs() << "\t DBGID:" << instructionDbgID << "\n";

        instructionDbgIDMap[stackVar] = instructionDbgID;
        instructionDbgID.clear();
    }
}

void DebugLocIDPass::updateDB()
{
    std::string statement;
    std::string instructionString, functionName;
    std::string dbgID;

    neo4j_connection_t *connection;
    neo4j_value_t instructionValue;
    neo4j_value_t programNameValue;
    neo4j_value_t functionNameValue;
    neo4j_value_t dbgIDValue;
    neo4j_map_entry_t mapEntries[4];
    neo4j_value_t params;
    neo4j_result_stream_t *results;

    llvm::raw_string_ostream rso(instructionString);

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    if (!instructionDbgIDMap.empty())
    {
        // errs() << "\t" << instructionDbgIDMap.size() << "\n";
        // Single transaction for all these queries (Batching)
        statement = "BEGIN;";
        results = neo4j_run(connection, statement.c_str(), neo4j_null);
        if (results == NULL)
        {
            errs() << "ERROR - FAILED TO START TRANSACTION\n";
            neo4j_close(connection);
        }
        else
            neo4j_close_results(results);

        // statement = " MATCH (p:ProgramInstruction) WHERE p.instruction = $instruction AND p.function_name = $function_name AND p.program_name=$program_name  SET p.dbgID=$dbgID";
        statement = " MERGE (p:ProgramInstruction{instruction:$instruction,function_name:$function_name,program_name:$program_name,dbgID:$dbgID}) ON CREATE  SET p.label=randomUUID();";

        programNameValue = neo4j_string(programName.c_str());
        for (auto inst_dbg_it : instructionDbgIDMap)
        {
            rso << *inst_dbg_it.first;
            instructionString = addNecessaryEscapeCharacters(instructionString);
            instructionValue = neo4j_string(instructionString.c_str());
            functionName = inst_dbg_it.first->getFunction()->getName().str();
            functionNameValue = neo4j_string(functionName.c_str());
            dbgIDValue = neo4j_string(inst_dbg_it.second.c_str());
            mapEntries[0] = neo4j_map_entry("instruction", instructionValue);
            mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
            mapEntries[2] = neo4j_map_entry("function_name", functionNameValue);
            mapEntries[3] = neo4j_map_entry("dbgID", dbgIDValue);
            params = neo4j_map(mapEntries, 4);
            results = neo4j_run(connection, statement.c_str(), params);
            if (results == NULL)
            {
                errs() << "Failed to set dbgID for instruction:" << instructionString << "\n";
            }
            neo4j_close_results(results);
            rso.flush();
            instructionString.clear();
        }

        statement = "COMMIT;";
        results = neo4j_run(connection, statement.c_str(), neo4j_null);
        if (results == NULL)
        {
            errs() << "ERROR - FAILED TO START TRANSACTION\n";
            neo4j_close(connection);
            return;
        }
        else
            neo4j_close_results(results);
    }

    //    //Add function dbg id to entry node to deal with name mangling and internal linkage issues
    instructionString = "ENTRY:";
    dbgID.clear();
    DISubprogram *subProgram = funcBeingAnalyzed->getSubprogram();
    if (subProgram)
    {
        dbgID = subProgram->getFilename().str() + ":" + std::to_string(subProgram->getLine());
    }
    if (dbgID.empty())
    {
        errs() << "\t Failed to set func dbg id:" << funcBeingAnalyzed->getName() << "\n";
    }

    statement = " MERGE (p:Entry{function_name:$function_name, program_name:$program_name, dbgID:$dbgID, instruction:$instruction}) ON CREATE SET p.label=randomUUID() RETURN p.label as label";

    instructionValue = neo4j_string(instructionString.c_str());
    programNameValue = neo4j_string(programName.c_str());
    functionName = funcBeingAnalyzed->getName();
    functionNameValue = neo4j_string(functionName.c_str());
    dbgIDValue = neo4j_string(dbgID.c_str());
    mapEntries[0] = neo4j_map_entry("instruction", instructionValue);
    mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[2] = neo4j_map_entry("function_name", functionNameValue);
    mapEntries[3] = neo4j_map_entry("dbgID", dbgIDValue);
    params = neo4j_map(mapEntries, 4);
    results = neo4j_run(connection, statement.c_str(), params);
    if (results == NULL)
    {
        errs() << "Failed to set dbgID for function:" << functionName << "\n";
    }
    neo4j_close_results(results);
    // rso.flush();
    instructionString.clear();
    neo4j_close(connection);
}

bool DebugLocIDPass::doInitialization(Module &m)
{
    programName = m.getModuleIdentifier();
    programName = programName.substr(0, programName.length() - 3);
    errs() << "DBG ID Program name:" << programName << "\n";
    return true;
}

bool DebugLocIDPass::runOnFunction(Function &F)
{
    errs() << "\t Processing function:" << F.getName().str() << "\n";
    funcBeingAnalyzed = &F;
    processFunction();
    updateDB();
    return false;
}

void DebugLocIDPass::getAnalysisUsage(AnalysisUsage &AU) const { AU.setPreservesAll(); }

char DebugLocIDPass::ID = 0;
static RegisterPass<DebugLocIDPass>
    Y("dbgid_func", "Generate debug info based unique ids ", false, true);
