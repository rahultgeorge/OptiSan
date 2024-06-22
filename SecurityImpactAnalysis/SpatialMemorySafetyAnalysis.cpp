/**
 * @file SpatialMemorySafetyAnalysis.cpp
 * @brief Analysis to find spatially unsafe memory operations from VR operations
 * @version 0.1
 * @date 2023-08-15
 *
 */

#include "SpatialMemorySafetyAnalysis.hh"

SpatialMemorySafetyAnalysisWrapper::SpatialMemorySafetyAnalysisWrapper() : ModulePass(ID){};

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

inline int findArgsPosFromCallInst(CallInst *callInst, Instruction *argument, Function *callee)
{
    int argPos = 0;
    if (!argument || !callInst)
        return -1;

    for (int i = 0; i < callInst->getNumArgOperands(); i++)
    {
        auto arg = callInst->getArgOperand(i);
        if (argument == dyn_cast<Instruction>(arg))
        {
            argPos = i;
            errs() << "\t\t\t Arg:" << *arg << "\n";
            break;
        }
    }

    if (argPos >= callee->arg_size())
    {
        errs() << "Failed to correlate with formal arg in callee\n";
        return -1;
    }
    return argPos;
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

inline Value *unwrapPointerOperand(Value *value)
{
    Value *pointerOperand = nullptr;
    if (ExtractValueInst *extractValueInst = dyn_cast<ExtractValueInst>(value))
    {
        // SVF crashes with extract value so
        pointerOperand = extractValueInst->getAggregateOperand();
    }

    else if (BitCastInst *bitcast = dyn_cast<BitCastInst>(pointerOperand))

        pointerOperand = bitcast->getOperand(0);

    return pointerOperand;
}

inline uint64_t getAllocaSizeInBytes(const AllocaInst &AI)
{
    uint64_t ArraySize = 1;
    if (AI.isArrayAllocation())
    {
        const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
        if (!CI)
            return 0;
        ArraySize = CI->getZExtValue();
    }
    Type *Ty = AI.getAllocatedType();
    uint64_t SizeInBytes =
        AI.getModule()->getDataLayout().getTypeAllocSize(Ty);
    return SizeInBytes * ArraySize;
}

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

inline void setDebugID(Instruction *instruction, std::string pdgLabel)
{
    std::string instructionDbgID = "";
    std::string statement;
    neo4j_connection_t *connection;
    neo4j_value_t pdgLabelValue;
    neo4j_value_t dbgIDValue;
    neo4j_map_entry_t mapEntries[2];
    neo4j_value_t params;
    neo4j_result_stream_t *results;
    DILocation *loc = NULL;
    loc = instruction->getDebugLoc();
    if (!loc || loc->isImplicitCode() || pdgLabel.empty())
    {
        // errs() << "No dbg info(or corrupt):" << *instruction << "\n";
        return;
    }
    instructionDbgID = loc->getFilename();
    instructionDbgID =
        instructionDbgID + ":" + std::to_string(loc->getLine()) + ":" + std::to_string(loc->getColumn());

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    statement = " MATCH (p:ProgramInstruction) WHERE p.label=$label  SET p.dbgID=$dbgID";
    pdgLabelValue = neo4j_string(pdgLabel.c_str());
    dbgIDValue = neo4j_string(instructionDbgID.c_str());
    mapEntries[0] = neo4j_map_entry("label", pdgLabelValue);
    mapEntries[1] = neo4j_map_entry("dbgID", dbgIDValue);
    params = neo4j_map(mapEntries, 2);
    results = neo4j_run(connection, statement.c_str(), params);
    if (results == NULL)
    {
        errs() << "Failed to set dbgID for instruction:" << *instruction << "\n";
    }
    neo4j_close_results(results);
    return;
}

std::string SpatialMemorySafetyAnalysisWrapper::stripVersionTag(std::string str)
{
    size_t pos = 0;
    size_t nth = 2;
    while (nth > 0)
    {
        pos = str.find(".", pos + 1);
        if (pos == std::string::npos)
            return str;
        nth--;
    }

    if (pos != std::string::npos)
        return str.substr(0, pos);
    return str;
}

Instruction *SpatialMemorySafetyAnalysisWrapper::findInstructionInFunctionUsingIR(std::string instructionString, Function *function, std::string pdgLabel)
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

    if (!pdgLabel.empty())
        setDebugID(instruction, pdgLabel);

    return nullptr;
}

void SpatialMemorySafetyAnalysisWrapper::getAnalysisUsage(AnalysisUsage &AU) const
{
    // AU.addRequiredTransitive<FunctionSpatialMemorySafetyAnalysis>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<FunctionScanPass>();
    // AU.addRequired<UsableTargetsAnalysis>();
    AU.setPreservesAll();
}

bool SpatialMemorySafetyAnalysisWrapper::isTypeEqual(Type &t1, Type &t2)
{
    if (&t1 == &t2)
        return true;
    // need to compare name for sturct, due to llvm-link duplicate struct types
    if (!t1.isPointerTy() || !t2.isPointerTy())
        return false;

    auto t1_pointed_ty = t1.getPointerElementType();
    auto t2_pointed_ty = t2.getPointerElementType();

    if (!t1_pointed_ty->isStructTy() || !t2_pointed_ty->isStructTy())
        return false;

    if (auto struct_t1_pointed_ty = dyn_cast<StructType>(t1_pointed_ty))
    {
        if (struct_t1_pointed_ty->isLiteral())
            return true;
    }

    if (auto struct_t2_pointed_ty = dyn_cast<StructType>(t2_pointed_ty))
    {
        if (struct_t2_pointed_ty->isLiteral())
            return true;
    }

    auto t1_name = stripVersionTag(t1_pointed_ty->getStructName().str());
    auto t2_name = stripVersionTag(t2_pointed_ty->getStructName().str());

    return (t1_name == t2_name);
}

bool SpatialMemorySafetyAnalysisWrapper::isFuncSignatureMatch(CallInst &ci, llvm::Function &f)
{
    if (f.isVarArg())
        return false;
    auto actual_arg_list_size = ci.getNumArgOperands();
    auto formal_arg_list_size = f.arg_size();
    if (actual_arg_list_size != formal_arg_list_size)
        return false;
    // compare return type
    auto actual_ret_type = ci.getType();
    auto formal_ret_type = f.getReturnType();
    if (!isTypeEqual(*actual_ret_type, *formal_ret_type))
        return false;

    for (unsigned i = 0; i < actual_arg_list_size; i++)
    {
        auto actual_arg = ci.getOperand(i);
        auto formal_arg = f.getArg(i);
        if (!isTypeEqual(*actual_arg->getType(), *formal_arg->getType()))
            return false;
    }
    return true;
}

std::set<Function *> SpatialMemorySafetyAnalysisWrapper::getIndirectCallCandidates(CallInst &ci)
{
    Type *call_func_ty = ci.getFunctionType();
    assert(call_func_ty != nullptr && "cannot find indirect call for null function type!\n");
    std::set<Function *> ind_call_cand;
    for (auto &F : *_module)
    {
        if (F.isDeclaration() || F.empty())
            continue;
        if (isFuncSignatureMatch(ci, F))
            ind_call_cand.insert(&F);
    }
    return ind_call_cand;
}

void SpatialMemorySafetyAnalysisWrapper::analyzeUnsafePointerArithmeticInstructions()
{
    std::string db_node_id;
    bool isUnknownOffset = false;
    bool isDynamicSizedObject = false;
    int numUnknownOffset = 0;
    int numDynamicSize = 0;
    int bothUnknownOffsetAndDynSize = 0;
    for (auto unsafePointerArithmeticInst : _results->getUnsafePointerArithmeticInstructions())
    {
        isUnknownOffset = false;
        isDynamicSizedObject = false;
        db_node_id = unsafePointerArithmeticInstructionsToDBIDMap[unsafePointerArithmeticInst];
        errs() << "" << *unsafePointerArithmeticInst << "\n";
        GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(unsafePointerArithmeticInst);
        if (!gep)
        {
            isUnknownOffset = true;
        }
        else
        {
            isUnknownOffset = !(gep->hasAllConstantIndices());
            if (!isUnknownOffset)
            {
                AllocaInst *alloca = dyn_cast<AllocaInst>(gep->getPointerOperand());
                if (!alloca)
                    isUnknownOffset = true;
            }
        }
        for (auto obj : _results->getUnsafeObjectsForPointerArithmetic(unsafePointerArithmeticInst))
        {
            errs() << "\t" << *obj << "\n";
            if (AllocaInst *alloca = dyn_cast<AllocaInst>(obj))
            {
                if (!getAllocaSizeInBytes(*alloca))
                {
                    isDynamicSizedObject = true;
                    break;
                }
            }
        }
        if (isUnknownOffset && isDynamicSizedObject)
            ++bothUnknownOffsetAndDynSize;
        else
        {
            numUnknownOffset += isUnknownOffset;
            numDynamicSize += isDynamicSizedObject;
        }
    }
    errs() << "# dynamic sized objects (unsafe def):" << numDynamicSize << "\n";
    errs() << "# unknown  offset (unsafe ):" << numUnknownOffset << "\n";
    errs() << "# cases where both:" << bothUnknownOffsetAndDynSize << "\n";
}

void SpatialMemorySafetyAnalysisWrapper::findPotentialUnsafeMemoryAccesses()
{

    _results = MemorySafetyResults::getInstance();

#ifndef USE_VR_RES_FROM_DB
    // // FunctionSpatialMemorySafetyAnalysis *funcMemAnalysis = nullptr;
    // for (auto &func : _module->functions())
    // {
    //     if (func.isDeclaration() || func.isIntrinsic())
    //         continue;
    //     funcMemAnalysis = &getAnalysis<FunctionSpatialMemorySafetyAnalysis>(func);
    // }

#else
    // Fetch all potentially unsafe pointer arithmetic found using VR
    bool functionFound = false;
    std::string statement;
    std::string indexString;
    std::string stateID, instructionString, functionName;
    std::string currFunctionName = "";
    std::string currentFuncDI;
    std::string functionDebugInfo;
    std::string temp_inst, field_string;
    std::string upaActionType;
    std::string dbgID;
    std::string pdgLabel;
    std::set<std::string> unsafePointerArithmeticDBIDs;
    std::set<std::string> potentialMatches;

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t typeValue, stateTypeValue, programNameValue;
    neo4j_map_entry_t mapEntries[3];
    neo4j_result_stream_t *results;
    neo4j_result_t *record;
    neo4j_value_t params;
    llvm::raw_string_ostream rso(temp_inst);
    Function *function = nullptr;
    FunctionScanPass *functionScanPass = nullptr;
    Instruction *unsafePointerArithmetic = NULL;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    typeValue = neo4j_string(STATE_TYPE);
    programNameValue = neo4j_string(programName.c_str());

    mapEntries[0] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[1] = neo4j_map_entry("type", typeValue);

    stateTypeValue = neo4j_string(UNSAFE_POINTER_STATE_TYPE);
    mapEntries[2] = neo4j_map_entry("state_type", stateTypeValue);

    statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction)  WHERE  a.type=$type AND a.program_name=p.program_name=$program_name AND a.state_type=$state_type AND NOT ((a)-[:EDGE]->(:AttackGraphNode))  RETURN  p.instruction, p.function_name, a.id, p.dbgID,p.label ORDER BY p.function_name";

    params = neo4j_map(mapEntries, 3);

    results = neo4j_run(connection, statement.c_str(), params);

    while ((record = neo4j_fetch_next(results)) != NULL)
    {
        // Instruction
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        instructionString = std::string(field);
        instructionString = instructionString.substr(1, instructionString.length() - 2);
        memset(field, 0, 500);
        // Function name
        neo4j_ntostring(neo4j_result_field(record, 1), field, 500);
        functionName = std::string(field);
        functionName = functionName.substr(1, functionName.length() - 2);
        memset(field, 0, 500);
        // State ID
        neo4j_ntostring(neo4j_result_field(record, 2), field, 500);
        stateID = std::string(field);
        stateID = stateID.substr(1, stateID.length() - 2);
        memset(field, 0, 500);
        // DBG ID
        neo4j_ntostring(neo4j_result_field(record, 3), field, 500);
        dbgID = std::string(field);
        dbgID = dbgID.substr(1, dbgID.length() - 2);
        memset(field, 0, 500);

        // PDG label
        neo4j_ntostring(neo4j_result_field(record, 4), field, 500);
        pdgLabel = std::string(field);
        pdgLabel = pdgLabel.substr(1, pdgLabel.length() - 2);
        // ALL UPA's would be unique (Guaranteed by query)
        // instructionString = processStringEscapeCharacters(instructionString);

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

        unsafePointerArithmetic = functionScanPass->findInstructionUsingDBGID(
            dbgID);

        if (!unsafePointerArithmetic)
        {
            potentialMatches = functionScanPass->findInstructionIRUsingDBGID(dbgID);

            if (potentialMatches.empty())
            {
                unsafePointerArithmetic = findInstructionInFunctionUsingIR(instructionString, function, pdgLabel);
            }

            //            errs() << "\t Multiple matching geps need to use IR:" << instructionString << ":" << functionName << ":"
            //                   << potentialMatches.size() <<
            //                   "\n";

            for (auto potentialMatchInstString : potentialMatches)
            {
                if (instructionString.compare(potentialMatchInstString) == 0)
                {
                    // Match
                    // errs() << instructionString << "==" << potentialMatchInstString << "\n";

                    unsafePointerArithmetic = functionScanPass->instructionIRToInstMap[instructionString];
                    break;
                }
                else if (hasConstantGEP(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                {
                    unsafePointerArithmetic = functionScanPass->instructionIRToInstMap[potentialMatchInstString];
                }
                else if (GetElementPtrInst *tempGEP = dyn_cast<GetElementPtrInst>(functionScanPass->instructionIRToInstMap[potentialMatchInstString]))
                {
                    unsafePointerArithmetic = tempGEP;
                }
            }
        }

        if (!unsafePointerArithmetic)
        {
            errs() << "\t Failed to find inst :" << instructionString << ":" << functionName << ":" << dbgID << "\n";
            errs() << "\t\t # DBG ID based IR matches found :" << potentialMatches.size() << "\n";
            /* for (auto potentialMatchInstString : potentialMatches)
            {
                errs() << instructionString << "==" << potentialMatchInstString << "\n";
            } */
            continue;
        }

        _results->addUnsafePointerArithmetic(unsafePointerArithmetic);
        unsafePointerArithmeticInstructionsToDBIDMap[unsafePointerArithmetic] = stateID;
        unsafePointerArithmeticDBIDs.insert(stateID);
    }

    neo4j_close_results(results);
    neo4j_close(connection);

    errs() << "# Unsafe pointer arithmetic ins (from VR in DB):" << unsafePointerArithmeticDBIDs.size() << "\n";
    if (unsafePointerArithmeticDBIDs.empty())
        return;
    neo4j_value_t stateIDValue;
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    mapEntries[0] = neo4j_map_entry("unsafe_object_type", neo4j_string(UNSAFE_STACK_OBJECT));

    // Fetch unsafe objects (functions more specifically)
    // TODO - func scan here as well?
    /*     for (auto unsafePointerArithmeticInst : _results->getUnsafePointerArithmeticInstructions())
        {
            auto unsafeOperationID = unsafePointerArithmeticInstructionsToDBIDMap[unsafePointerArithmeticInst];
            stateIDValue = neo4j_string(unsafeOperationID.c_str());
            mapEntries[1] = neo4j_map_entry("action_id", stateIDValue);
            statement = " MATCH (obj:AttackGraphNode)-[:SOURCE]->(unsafeOperation:AttackGraphNode) WHERE unsafeOperation.id=$action_id AND obj.state_type=$unsafe_object_type WITH DISTINCT obj MATCH (obj:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) RETURN  p.instruction, p.function_name  ORDER BY p.function_name";
            params = neo4j_map(mapEntries, 2);

            results = neo4j_run(connection, statement.c_str(), params);

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

                // ALL UPA's would be unique (Guaranteed by query)
                instructionString = processStringEscapeCharacters(instructionString);
                //            errs() << "\t:" << instructionString << "\n";
                indexString = functionName + instructionString;

                if (cache.find(indexString) == cache.end())
                    cacheFunction(_module->getFunction(functionName));

                // Insert into DS
                if (cache.find(indexString) != cache.end())
                {
                    _results->addStackObjectForUnsafePointerArithmetic(unsafePointerArithmeticInst, cache[indexString]);
                }
                else
                {
                    errs() << "Failed to find object inst:" << instructionString << ":" << functionName << ":"
                           << "\n";
                    exit(1);
                }
            }
        }

            neo4j_close_results(results);
    */

    neo4j_close(connection);

    // analyzeUnsafePointerArithmeticInstructions();

#endif
}

bool SpatialMemorySafetyAnalysisWrapper::runOnModule(Module &M)
{
    _module = &M;
    programName = M.getModuleIdentifier();
    programName = programName.substr(0, programName.length() - 3);
    findPotentialUnsafeMemoryAccesses();
    computePossibleStackUnsafeMemoryAccessesUsingVR();
    // UsableTargetsAnalysis *usableTargetAnalysis = &getAnalysis<UsableTargetsAnalysis>();
    // errs() << "USable targets pass\n";

    return false;
}

/**
 * Computes potential unsafe memory accesses from the unsafe pointer arithmetic instructions
 * Memory errors may lead to more errors
 */
void SpatialMemorySafetyAnalysisWrapper::computePossibleStackUnsafeMemoryAccessesUsingVR()
{

    bool checkForTaintedOperands = false;
    errs() << "\t Computing possible unsafe accesses from the unsafe pointer arithmetic instructions \n";
    for (auto unsafePointerArithmeticInst : _results->getUnsafePointerArithmeticInstructions())
    {

        if (Instruction *getElementPtrInst =
                dyn_cast<Instruction>(unsafePointerArithmeticInst))
        {

            //            errs() << "Unsafe pointer (OOB GEP) (attack state):" << *getElementPtrInst
            //                   << "\n";
            computeUsesOfAddress(
                getElementPtrInst,
                checkForTaintedOperands, true);
        }
        else if (ConstantExpr *expr = dyn_cast<ConstantExpr>(unsafePointerArithmeticInst))
        {
        }
    }
}

/**
 * Find interesting uses of the unsafe address so subsequent reads and
 * writes from/to memory using this address
 * @param unsafeAddress - potential out of bounds address
 * @param checkForTaintedOperands - Checks whether any tainted data is used in
 * any subsequent operations
 * @param isUnsafePtr -
 *  */
void SpatialMemorySafetyAnalysisWrapper::computeUsesOfAddress(
    Instruction *unsafeAddress,
    bool checkForTaintedOperands = false, bool isUnsafePtr = true)
{
    bool isAction;
    std::string actionID;
    std::string unsafePointerStateID;
    std::string pdgLabel;
    std::queue<Value *> workList;
    std::set<Value *> processedValues;
    Function *callee = NULL;
    int argPos = -1;
    workList.push(unsafeAddress);
    Value *currUnsafeInstruction = NULL;
    Instruction *dataOperand = NULL;
    std::set<Instruction *> unsafeAddressPropagation;
    std::map<Instruction *, std::string> propagationActionsToIDMap;

    if (unsafePointerArithmeticInstructionsToDBIDMap.find(unsafeAddress) == unsafePointerArithmeticInstructionsToDBIDMap.end())
        return;
    unsafePointerStateID = unsafePointerArithmeticInstructionsToDBIDMap[unsafeAddress];

    while (!workList.empty())
    {
        currUnsafeInstruction = workList.front();
        //        errs() << "\t Analyzing uses of:" << *currUnsafeInstruction <<
        //        "\n";
        for (User *unsafeUser : currUnsafeInstruction->users())
        {

            // Skip if we've seen this value earlier (loops)
            if (processedValues.find(unsafeUser) != processedValues.end())
            {
                continue;
            }

            // Stores potentially oob address or writes to said address. Propagates (directly) in first case
            if (StoreInst *storeInst = dyn_cast<StoreInst>(unsafeUser))
            {

                // OOB address is propagated to another pointer
                if (storeInst->getValueOperand() == currUnsafeInstruction &&
                    storeInst->getValueOperand()->getType()->isPointerTy())
                {

                    if (allPropagationActionsSeen.find(storeInst) == allPropagationActionsSeen.end())
                    {
                        unsafeAddressPropagation.insert(storeInst);
                        errs() << "\t\t Propagation pointer action:" << *storeInst << "\n";
                        errs() << "\t\t Pointer operand type:"
                               << *storeInst->getPointerOperand()->getType() << "\n";
                        propagationActionsToIDMap[storeInst] = unsafePointerStateID;
                    }
                }

                else if (checkForTaintedOperands)
                {
                    errs() << "\t\t Write  pointer action" << *storeInst << "\n";

                    // Check if tainted data is used

                    dataOperand = dyn_cast<Instruction>(storeInst->getValueOperand());

                    if (dataOperand && taintedOperands.find(dataOperand) !=
                                           taintedOperands.end())
                    {
                        // Connect the tainted operand to the action
                    }
                }
                unsafeStackMemoryAccesses.insert(storeInst);
                // TODO** - Insert into results or db directly here
                actionID = createAttackAction(findProgramInstructionInPDG(storeInst), UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE);
                connectStateAndAction(unsafePointerStateID, actionID);
            }

            // Memory related call actions
            else if (CallInst *callInst = dyn_cast<CallInst>(unsafeUser))
            {
                callee = callInst->getCalledFunction();
                isAction = false;
                std::set<Function *> callCandidates;
                if (callee)
                {
                    callCandidates.insert(callee);
                }
                else
                {
                    callCandidates = getIndirectCallCandidates(*callInst);
                    errs() << "\t Indirect call:" << *callInst << ":" << callCandidates.size() << "\n";
                }
                for (auto callee : callCandidates)
                {
                    auto calleeName = callee->getName();

                    // TODO - Enable a standard way to specify their signatures and therefore standardize checks
                    // TODO - Include lib call read actions
                    if (libraryUPACalls.find(calleeName) != libraryUPACalls.end())
                    {
                        errs() << "\t\t Lib Call inst:" << *callInst << "\n";
                        // sprintf,snprintf,strcat,strncat, strcpy and strncpy all have dest
                        // as the first operand Also one of the source args could be tainted
                        // (We do not check for this right now)
                        if (currUnsafeInstruction ==
                            dyn_cast<Instruction>(callInst->getOperand(0)))
                        {
                            actionID = createAttackAction(findProgramInstructionInPDG(callInst), UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE);
                            connectStateAndAction(unsafePointerStateID, actionID);
                        }
                    }
                    else if (callee->isIntrinsic())
                    {
                        if (calleeName.contains("memmove") ||
                            calleeName.contains("memset") ||
                            calleeName.contains("memcpy"))
                        {
                            errs() << "\t\t LLVM intrinsic lib call inst:" << *callInst
                                   << "\n";
                            // memcpy,memset and memmove all have dest as the first operand
                            // Also one of the source args could be tainted (We do not check
                            // for this right now)
                            if (currUnsafeInstruction ==
                                dyn_cast<Instruction>(callInst->getOperand(0)))
                            {
                                unsafeStackMemoryAccesses.insert(callInst);
                            }
                            else
                                unsafeStackMemoryAccesses.insert(callInst);

                            isAction = true;
                        }

                        if (isAction)
                        {
                            actionID = createAttackAction(findProgramInstructionInPDG(callInst), UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE);
                            connectStateAndAction(unsafePointerStateID, actionID);
                        }
                    }

                    // Do inter proc analysis
                    else
                    {
                        errs() << "\t\t Call Inst:" << *callInst << "\n";
                        argPos = findArgsPosFromCallInst(callInst, dyn_cast<Instruction>(currUnsafeInstruction), callee);
                        if (argPos == -1)
                            continue;

                        // Byval means that a struct is passed without opening it up (ABI reasons) so it is passed by dereferencing the unsafe address. O0 byval has no address taken var so param tree fails.
                        if (callee->getArg(argPos)->hasByValAttr())
                        {
                            errs() << "\t\t BYVAL :  PTR READ Action\n";
                            unsafeStackMemoryAccesses.insert(callInst);
                            actionID = createAttackAction(findProgramInstructionInPDG(callInst), UNSAFE_POINTER_READ_STACK_ACTION_TYPE);
                            connectStateAndAction(unsafePointerStateID, actionID);
                        }
                        else
                        {
                            for (auto argUseIt : findFormalArgAndUses(callee, callee->getArg(argPos)))
                            {
                                // TODO - Think about this check. We could miss cases where addr is casted and passed to another function which could convert it back and dereference it
                                if (argUseIt->getType()->isPointerTy())
                                {
                                    if (processedValues.find(argUseIt) == processedValues.end())
                                        workList.push(argUseIt);
                                }
                            }
                        }
                    }
                }
            }

            // If a value is read from an unsafe address then the
            // value propagates. This def use analysis focuses on the address being
            // used (dereferenced) and propagated
            else if (LoadInst *loadInst = dyn_cast<LoadInst>(unsafeUser))
            {
                // Unsafe address is dereferenced and that is used as an address/ptr so there may be secondary uses
                // TODO - Make this a separate type. Include derived pointers?
                if (loadInst->getType()->isPointerTy())
                {
                    errs() << "\t\t\t Read pointer action where value read is used as an address:" << *loadInst
                           << "\n";
                    // unsafeAddressPropagation.insert(loadInst);
                }
                else
                {
                    errs() << "\t\t\t Unsafe load " << *loadInst << "\n";
                }
                unsafeStackMemoryAccesses.insert(loadInst);
                // TODO**- Insert into results or db directly here
                actionID = createAttackAction(findProgramInstructionInPDG(loadInst), UNSAFE_POINTER_READ_STACK_ACTION_TYPE);
                connectStateAndAction(unsafePointerStateID, actionID);
            }

            // Any other uses such as casts, arithmetic or logical operations, phi
            else
            {
                workList.push(unsafeUser);
            }
        }
        processedValues.insert(currUnsafeInstruction);
        workList.pop();
    }

    // TODO - in cases where OOB address is used in subsequent computations and
    // the dereferences shouldn't we analyze the all subsequent address
    // computation as well

    if (!unsafeAddressPropagation.empty())
    {
        //        errs() << "\t Potential additional propagation actions found:" << propagationActions.size() << "\n";
        propagateUnsafeAddress(unsafeAddressPropagation, propagationActionsToIDMap);
    }
}

// This is not a generic method because when src,dest are not be in the same function, source is an ancestor and dest is a descendent
bool SpatialMemorySafetyAnalysisWrapper::isReachable(Instruction *source,
                                                     Instruction *dest)
{
    BasicBlock *currBlock = source->getParent();
    BasicBlock *destBB = dest->getParent();
    std::queue<BasicBlock *> workList;
    std::set<BasicBlock *> visitedBB;

    if (currBlock->getParent() != destBB->getParent())
    {
        // Unsafe operation (source) is in callee and impacted object use in caller
        for (auto callSite : findCallSites(source->getFunction(), dest->getFunction()))
        {
            workList.push(callSite->getParent());
        }
    }
    else
        workList.push(currBlock);

    while (!workList.empty())
    {
        currBlock = workList.front();
        visitedBB.insert(currBlock);
        if (currBlock == destBB)
            return true;
        if (&(currBlock->getParent()->getEntryBlock()) == currBlock)
            return true;

        auto terminatorInst = currBlock->getTerminator();
        if (terminatorInst)
        {
            for (int succ_no = 0; succ_no < terminatorInst->getNumSuccessors();
                 succ_no++)
            {
                if (visitedBB.find(terminatorInst->getSuccessor(succ_no)) ==
                    visitedBB.end())
                    workList.push(terminatorInst->getSuccessor(succ_no));
            }
            workList.pop();
        }
        else
            break;
    }

    return false;
}

std::set<Instruction *> SpatialMemorySafetyAnalysisWrapper::findCallSites(Function *caller, Function *sinkFunc)
{
    std::set<Instruction *> callSites;
    Function *currentCallee = nullptr;
    std::queue<std::string> workList;
    std::set<Value *> visited;

    workList.push(sinkFunc->getName());
    while (!workList.empty())
    {
        // callSites.empty()
        //        if (workList.empty()) break;
        currentCallee = _module->getFunction(workList.front());
        if (visited.find(currentCallee) != visited.end())
        {
            workList.pop();
            continue;
        }
        for (inst_iterator I = inst_begin(caller), E = inst_end(caller); I != E; ++I)
        {
            if (CallInst *callInst = dyn_cast<CallInst>(&*I))
            {
                if (callInst->getCalledFunction() == currentCallee)
                {
                    callSites.insert(callInst);
                }
            }
        }
        //        if (!callSites.empty()) break;
        // Find every caller of the sink function and try going backwards i.e finding call sites in source to this intermediate function
        for (auto previousCaller : findAllPossiblePreviousCallers(currentCallee))
        {
            if (previousCaller.compare(caller->getName()) != 0)
                workList.push(previousCaller);
        }
        visited.insert(currentCallee);
        workList.pop();
    }
    if (callSites.empty())
    {
        errs() << "Failed to find any call sites (Check for indirect calls)\n";
        // exit(1);
    }
    return callSites;
}

std::set<std::string> SpatialMemorySafetyAnalysisWrapper::findAllPossiblePreviousCallers(Function *callee, int numLevels)
{
    // Find all callers. Again this should be configurable

    std::set<std::string> potentialCallers;

    for (auto user_it : callee->users())
    {
        if (CallInst *CI = dyn_cast<CallInst>(user_it))
        {
            potentialCallers.insert(CI->getFunction()->getName());
        }
    }

    return potentialCallers;
}

// PDG's parameter tree construction step done lazily
std::set<Instruction *> SpatialMemorySafetyAnalysisWrapper::findFormalArgAndUses(Function *callee, Argument *arg)
{
    AllocaInst *arg_alloca_inst = NULL;
    std::set<Instruction *> addr_taken_vars;
    // errs() << "\t\t Formal arg:" << *arg << "\n";

    // TODO - Better way?
    for (inst_iterator I = inst_begin(callee),
                       E = inst_end(callee);
         I != E; ++I)
    {
        if (DbgDeclareInst *dbg_declare_inst = dyn_cast<DbgDeclareInst>(&*I))
        {
            DILocalVariable *di_local_var = dbg_declare_inst->getVariable();
            if (!di_local_var)
                continue;
            if (di_local_var->getArg() == arg->getArgNo() + 1 && !di_local_var->getName().empty() &&
                di_local_var->getScope()->getSubprogram() == callee->getSubprogram())
            {
                if (AllocaInst *ai = dyn_cast<AllocaInst>(dbg_declare_inst->getVariableLocation()))
                {
                    arg_alloca_inst = ai;
                    break;
                }
            }
        }
    }

    if (!arg_alloca_inst)
    {
        errs() << "Failed to find arg alloca\n";
        return addr_taken_vars;
    }

    // Step 2 - Find the uses of the actual arg (uses where it is read from the stack)
    for (auto user : arg_alloca_inst->users())
    {
        if (LoadInst *loadInst = dyn_cast<LoadInst>(user))
            addr_taken_vars.insert(loadInst);
    }
    return addr_taken_vars;
}

Instruction *SpatialMemorySafetyAnalysisWrapper::findDominatingInstruction(std::vector<Instruction *> instructions)
{
    Instruction *dominatingInst = NULL;
    bool dominatesOthers = false;
    Function *func = ((*instructions.begin()))->getFunction();

    // Currently O(n*n) approach
    auto dominatorTree = &getAnalysis<DominatorTreeWrapperPass>(*func).getDomTree();

    for (auto first_inst_it : instructions)
    {
        if (!dominatesOthers)
        {
            dominatingInst = &(*first_inst_it);
            dominatesOthers = true;
        }
        for (auto second_inst_it : instructions)
        {
            if (!dominatorTree->dominates(dominatingInst, &(*second_inst_it)))
            {
                dominatesOthers = false;
                break;
            }
        }
    }

    if (!dominatesOthers)
    {
        errs() << "No inst which dominates others so returning last one\n";
    }
    return dominatingInst;
}

void SpatialMemorySafetyAnalysisWrapper::propagateUnsafeAddress(std::set<Instruction *> propagationActions, std::map<Instruction *, std::string> propagationActionsToIDMap)
{
    std::string pdgLabel;
    std::string actionID;
    std::string oobStateID;
    //    bool canFindUnsafeOperations = false;
    Instruction *oobValue = nullptr;
    Instruction *propagationInst = nullptr;
    std::set<Instruction *> unsafeAddressValues;
    std::queue<Instruction *> workList;

    for (auto propagationAction : propagationActions)
    {
        propagationInst = propagationAction;
        if (allPropagationActionsSeen.find(propagationInst) != allPropagationActionsSeen.end())
            continue;
        allPropagationActionsSeen.insert(propagationInst);

        errs() << "\t Propagation action:" << *propagationInst << "\n";

        oobValue = dyn_cast<Instruction>(propagationInst->getOperand(1));
        if (!oobValue || isa<ConstantExpr>(oobValue))
            continue;
        unsafeAddressValues.clear();
        workList = std::queue<Instruction *>();

        workList.push(oobValue);
        oobStateID = propagationActionsToIDMap[propagationInst];
        while (!workList.empty())
        {
            oobValue = workList.front();

            for (auto user_it : oobValue->users())
            {
                if (Instruction *useInst = dyn_cast<Instruction>(user_it))
                    if (isReachable(propagationInst, useInst))
                    {
                        if (isa<LoadInst>(useInst))
                        {
                            //                            errs() << "\t\t\t Reachable load (oob address read):" << *useInst << "\n";
                            unsafePointerArithmeticInstructionsToDBIDMap[useInst] = oobStateID;
                            unsafeAddressValues.insert(useInst);
                        }
                        else if (StoreInst *storeUse = dyn_cast<StoreInst>(useInst))
                        {
                            if (storeUse->getPointerOperand() == oobValue)
                                continue;
                            errs() << "\t\t\t OOB address propagates so add check:" << *useInst << "\n";

                            // exit(1);
                            // TODO - Need to repeat the process wrt this store
                        }
                        else if (GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(useInst))
                        {
                            errs() << "\t\t\t GEP use:" << *gepInst << "\n";
                            workList.push(gepInst);
                        }
                        else
                        {
                            errs() << "\t\t\t Unknown use:" << *useInst << "\n";
                            workList.push(useInst);
                        }
                    }
            }
            workList.pop();
        }

        for (auto unsafeAddr : unsafeAddressValues)
        {
            errs() << "\t\t Reachable load (oob value accessed):" << *unsafeAddr << "\n";
            computeUsesOfAddress(unsafeAddr, false, true);
        }
    }
}

bool SpatialMemorySafetyAnalysisWrapper::cacheFunction(Function *function)
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
        rso << *inst;
        indexString = functionName + instructionString;
        cache[indexString] = inst;
        rso.flush();
        instructionString.clear();
    }

    return true;
}

std::string SpatialMemorySafetyAnalysisWrapper::createAttackAction(std::string pdgNodeLabel,
                                                                   std::string actionType,
                                                                   std::string actionLabel)
{
    std::string statement;
    std::string actionID = "";
    // Set a hard character limit on any field returned from the query
    char *field = (char *)malloc(sizeof(char) * 500);
    neo4j_connection_t *connection;
    neo4j_value_t nodeLabelValue;
    neo4j_value_t actionTypeValue;
    neo4j_value_t actionNodeTypeValue;
    neo4j_value_t programNameValue;
    neo4j_map_entry_t mapEntries[5];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    if (pdgNodeLabel.empty())
    {
        errs() << "PDG label empty\n";
        return actionID;
    }
    nodeLabelValue = neo4j_string(pdgNodeLabel.c_str());
    actionNodeTypeValue = neo4j_string(ACTION_TYPE);
    actionTypeValue = neo4j_string(actionType.c_str());
    programNameValue = neo4j_string(programName.c_str());

    mapEntries[0] = neo4j_map_entry("node_label", nodeLabelValue);
    mapEntries[1] = neo4j_map_entry("action_node_type", actionNodeTypeValue);
    mapEntries[2] = neo4j_map_entry("action_type", actionTypeValue);
    mapEntries[3] = neo4j_map_entry("program_name", programNameValue);

    statement =
        " MATCH(p:ProgramInstruction) WHERE p.label=$node_label WITH p MERGE "
        "(a:AttackGraphNode{type:$action_node_type, action_type:$action_type, "
        "program_name:$program_name})-[:EDGE]->(p) ON CREATE SET "
        "a.id=randomUUID() RETURN a.id";
    params = neo4j_map(mapEntries, 4);

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    results = neo4j_run(connection, statement.c_str(), params);
    if (results == NULL)
    {
        errs() << "Failed to create attack action\n";
        return actionID;
    }
    // There should only be one record
    if ((record = neo4j_fetch_next(results)) != NULL)
    {
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        actionID = std::string(field);
        actionID = actionID.substr(1, actionID.length() - 2);
    }

    neo4j_close_results(results);
    neo4j_close(connection);
    return actionID;
}

void SpatialMemorySafetyAnalysisWrapper::connectStateAndAction(std::string stateID,
                                                               std::string actionID)
{
    std::string statement;
    neo4j_connection_t *connection;
    neo4j_value_t stateIDValue;
    neo4j_value_t actionIDValue;
    neo4j_map_entry_t mapEntries[2];
    neo4j_value_t params;
    neo4j_result_stream_t *results;

    if (stateID.empty() || actionID.empty())
    {
        errs() << "Need both state id and action\n";
        return;
    }
    stateIDValue = neo4j_string(stateID.c_str());
    actionIDValue = neo4j_string(actionID.c_str());

    mapEntries[0] = neo4j_map_entry("state_id", stateIDValue);
    mapEntries[1] = neo4j_map_entry("action_id", actionIDValue);

    statement =
        "MATCH (state:AttackGraphNode) WHERE state.id=$state_id WITH state" +
        std::string(" MATCH (action:AttackGraphNode) WHERE action.id=$action_id  "
                    "WITH state,action ") +
        "MERGE (state)-[e:EDGE]->(action) RETURN e";

    params = neo4j_map(mapEntries, 2);
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    results = neo4j_run(connection, statement.c_str(), params);
    if (results == NULL)
    {
        errs() << "Failed to connect attack surface and state\n";
    }
    neo4j_close_results(results);
    neo4j_close(connection);
}

std::string
SpatialMemorySafetyAnalysisWrapper::findProgramInstructionInPDG(Instruction *instruction)
{
    std::string statement;
    std::string instructionString;
    std::string pdgLabel = "";
    std::string functionName;
    std::string debugID;
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
    debugID = getDebugID(instruction);
    // errs() << "\t" << debugID << "\n";
    dbgIDValue = neo4j_string(debugID.c_str());

    mapEntries[0] = neo4j_map_entry("instruction", instructionValue);
    mapEntries[1] = neo4j_map_entry("program_name", programNameValue);
    mapEntries[2] = neo4j_map_entry("function_name", functionNameValue);
    mapEntries[3] = neo4j_map_entry("dbgID", dbgIDValue);

    params = neo4j_map(mapEntries, 4);
    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);
    // statement = " MATCH (p:ProgramInstruction) WHERE p.instruction ="
    //             "$instruction AND p.function_name=$function_name AND "
    //             "p.program_name=$program_name  RETURN p.label";

    statement = "MERGE (p:ProgramInstruction{ dbgID:$dbgID, instruction:$instruction, function_name:$function_name, program_name:$program_name}) ON CREATE SET p.label=randomUUID() RETURN p.label ";

    results = neo4j_run(connection, statement.c_str(), params);
    // There should only be one record
    if ((record = neo4j_fetch_next(results)) != NULL)
    {
        neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
        pdgLabel = std::string(field);
        pdgLabel = pdgLabel.substr(1, pdgLabel.length() - 2);
        // errs() << "\t PDG label:" << pdgLabel << "\n";
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

static RegisterPass<SpatialMemorySafetyAnalysisWrapper>
    P("compute-actions",
      "Find potentially unsafe memory accesses", false, true);

char SpatialMemorySafetyAnalysisWrapper::ID = 0;
