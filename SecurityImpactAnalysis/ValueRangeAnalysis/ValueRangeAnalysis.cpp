#include "llvm/ADT/APSInt.h"
#include "llvm/Analysis/ConstantFolding.h"
#include <llvm/Analysis/MemoryBuiltins.h>
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include "ValueRangeAnalysis.hh"
#include <queue>

#define TRANSACTION_SIZE 100
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define BLUE "\033[0;34m"
#define GRAY "\033[1;30m"
#define DETAIL "\033[1;36m"
#define NORMAL "\033[0m"

using namespace llvm;
using std::string;
using std::unique_ptr;
Module *module;
std::string programName;
std::map<llvm::Instruction *, std::string> instructionAddressesToStringsMap;
TargetLibraryInfoWrapperPass *tliPass;
// If we do analyze formal args for a function then we cache it
std::map<Function *, std::set<Value *>> functionToArgCache;
std::map<Value *, std::set<Instruction *>> valueToStackObjects;
// Unsafe ptr art to unsafe stack objects that may be referenced
std::map<Instruction *, std::set<Instruction *>> unsafePtrToUnsafeStackObjects;
// DB related DS
std::map<Instruction *, std::string> unsafePtrToLogicalIDDB;

enum class PossibleRangeValues
{
    unknown,
    constant,
    infinity
};

struct RangeValue
{
    PossibleRangeValues kind;
    llvm::ConstantInt *lvalue, *rvalue;

    RangeValue() : kind(PossibleRangeValues::unknown),
                   lvalue(nullptr),
                   rvalue(nullptr) {}

    bool isUnknown() const
    {
        return kind == PossibleRangeValues::unknown;
    }

    bool isInfinity() const
    {
        return kind == PossibleRangeValues::infinity;
    }

    bool isConstant() const
    {
        return kind == PossibleRangeValues::constant;
    }

    RangeValue
    operator|(const RangeValue &other) const
    {
        RangeValue r;
        if (isUnknown() || other.isUnknown())
        {
            if (isUnknown())
            {
                return other;
            }
            else
            {
                return *this;
            }
        }
        else if (isInfinity() || other.isInfinity())
        {
            r.kind = PossibleRangeValues::infinity;
            return r;
        }
        else
        {
            auto &selfL = lvalue->getValue();
            auto &selfR = rvalue->getValue();
            auto &otherL = (other.lvalue)->getValue();
            auto &otherR = (other.rvalue)->getValue();

            r.kind = PossibleRangeValues::constant;
            if (selfL.slt(otherL))
            {
                r.lvalue = lvalue;
            }
            else
            {
                r.lvalue = other.lvalue;
            }

            if (selfR.sgt(otherR))
            {
                r.rvalue = rvalue;
            }
            else
            {
                r.rvalue = other.rvalue;
            }
            return r;
        }
    }

    bool
    operator==(const RangeValue &other) const
    {
        if (kind == PossibleRangeValues::constant &&
            other.kind == PossibleRangeValues::constant)
        {
            auto &selfL = lvalue->getValue();
            auto &selfR = rvalue->getValue();
            auto &otherL = (other.lvalue)->getValue();
            auto &otherR = (other.rvalue)->getValue();
            return selfL == otherL && selfR == otherR;
        }
        else
        {
            return kind == other.kind;
        }
    }
};

RangeValue makeRange(LLVMContext &context, APInt &left, APInt &right)
{
    RangeValue r;
    r.kind = PossibleRangeValues::constant;
    r.lvalue = ConstantInt::get(context, left);
    r.rvalue = ConstantInt::get(context, right);
    return r;
}

RangeValue infRange()
{
    RangeValue r;
    r.kind = PossibleRangeValues::infinity;
    return r;
}

using RangeState = analysis::AbstractState<RangeValue>;
using RangeResult = analysis::DataflowResult<RangeValue>;

class RangeMeet : public analysis::Meet<RangeValue, RangeMeet>
{
public:
    RangeValue
    meetPair(RangeValue &s1, RangeValue &s2) const
    {
        return s1 | s2;
    }
};

class RangeTransfer
{
public:
    RangeValue getRangeFor(llvm::Value *v, RangeState &state) const
    {
        if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(v))
        {
            RangeValue r;
            r.kind = PossibleRangeValues::constant;
            r.lvalue = r.rvalue = constant;
            return r;
        }
        return state[v];
    }

    RangeValue evaluateBinOP(llvm::BinaryOperator &binOp,
                             RangeState &state) const
    {
        auto *op1 = binOp.getOperand(0);
        auto *op2 = binOp.getOperand(1);
        auto range1 = getRangeFor(op1, state);
        auto range2 = getRangeFor(op2, state);

        if (range1.isConstant() && range2.isConstant())
        {
            //            auto &layout = binOp.getModule()->getDataLayout();
            auto l1 = range1.lvalue->getValue();
            auto r1 = range1.rvalue->getValue();
            auto l2 = range2.lvalue->getValue();
            auto r2 = range2.rvalue->getValue();

            auto &context = (range1.lvalue)->getContext();
            auto opcode = binOp.getOpcode();

            if (opcode == Instruction::Add)
            {
                bool ofl, ofr;
                auto l = l1.sadd_ov(l2, ofl);
                auto r = r1.sadd_ov(r2, ofr);
                if (ofl || ofr)
                {
                    return infRange();
                }
                else
                {
                    return makeRange(context, l, r);
                }
            }
            else if (opcode == Instruction::Sub)
            {
                bool ofl, ofr;
                auto l = l1.ssub_ov(r2, ofl);
                auto r = r1.ssub_ov(l2, ofr);
                if (ofl || ofr)
                {
                    return infRange();
                }
                else
                {
                    return makeRange(context, l, r);
                }
            }
            else if (opcode == Instruction::Mul)
            {
                SmallVector<APInt, 4> candidates;
                bool ofFlags[4];
                candidates.push_back(l1.smul_ov(l2, ofFlags[0]));
                candidates.push_back(l1.smul_ov(r2, ofFlags[1]));
                candidates.push_back(r1.smul_ov(l2, ofFlags[2]));
                candidates.push_back(r1.smul_ov(r2, ofFlags[3]));
                for (auto of : ofFlags)
                {
                    if (of)
                    {
                        return infRange();
                    }
                }
                auto max = candidates[0];
                for (auto &x : candidates)
                {
                    if (x.sgt(max))
                    {
                        max = x;
                    }
                }
                auto min = candidates[0];
                for (auto &x : candidates)
                {
                    if (x.slt(min))
                    {
                        min = x;
                    }
                }
                return makeRange(context, min, max);
            }
            else if (opcode == Instruction::SDiv)
            {
                if (l2.isNegative() && r2.isStrictlyPositive())
                {
                    auto abs1 = l1.abs();
                    auto abs2 = r1.abs();
                    auto abs = abs1.sgt(abs2) ? abs1 : abs2;
                    APInt l(abs);
                    l.flipAllBits();
                    ++l;
                    return makeRange(context, l, abs);
                }
                else
                {
                    SmallVector<APInt, 4> candidates;
                    bool ofFlags[4];
                    candidates.push_back(l1.sdiv_ov(l2, ofFlags[0]));
                    candidates.push_back(l1.sdiv_ov(r2, ofFlags[1]));
                    candidates.push_back(r1.sdiv_ov(l2, ofFlags[2]));
                    candidates.push_back(r1.sdiv_ov(r2, ofFlags[3]));
                    for (auto of : ofFlags)
                    {
                        if (of)
                        {
                            return infRange();
                        }
                    }
                    auto max = candidates[0];
                    for (auto &x : candidates)
                    {
                        if (x.sgt(max))
                        {
                            max = x;
                        }
                    }
                    auto min = candidates[0];
                    for (auto &x : candidates)
                    {
                        if (x.slt(min))
                        {
                            min = x;
                        }
                    }
                    return makeRange(context, min, max);
                }
            }
            else if (opcode == Instruction::UDiv)
            {
                auto l = r1.udiv(l2);
                auto r = l1.udiv(r2);
                return makeRange(context, l, r);
            }
            else
            {
                // todo: fill in
                return infRange();
            }
        }
        else if (range1.isInfinity() || range2.isInfinity())
        {
            RangeValue r;
            r.kind = PossibleRangeValues::infinity;
            return r;
        }
        else
        {
            RangeValue r;
            return r;
        }
    }

    RangeValue evaluateCast(llvm::CastInst &castOp, RangeState &state) const
    {
        auto *op = castOp.getOperand(0);
        auto value = getRangeFor(op, state);

        if (value.isConstant())
        {
            auto &layout = castOp.getModule()->getDataLayout();
            auto x = ConstantFoldCastOperand(castOp.getOpcode(), value.lvalue,
                                             castOp.getDestTy(), layout);
            auto y = ConstantFoldCastOperand(castOp.getOpcode(), value.rvalue,
                                             castOp.getDestTy(), layout);
            if (llvm::isa<llvm::ConstantExpr>(x) || llvm::isa<llvm::ConstantExpr>(y))
            {
                return infRange();
            }
            else
            {
                RangeValue r;
                auto *cix = dyn_cast<ConstantInt>(x);
                auto *ciy = dyn_cast<ConstantInt>(y);
                r.kind = PossibleRangeValues::constant;
                r.lvalue = cix;
                r.rvalue = ciy;
                return r;
            }
        }
        else
        {
            RangeValue r;
            r.kind = value.kind;
            return r;
        }
    }

    void
    operator()(llvm::Value &i, RangeState &state)
    {
        if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(&i))
        {
            RangeValue r;
            r.kind = PossibleRangeValues::constant;
            r.lvalue = r.rvalue = constant;
            state[&i] = r;
        }
        else if (auto *binOp = llvm::dyn_cast<llvm::BinaryOperator>(&i))
        {
            state[binOp] = evaluateBinOP(*binOp, state);
        }
        else if (auto *castOp = llvm::dyn_cast<llvm::CastInst>(&i))
        {
            state[castOp] = evaluateCast(*castOp, state);
        }
        else
        {
            state[&i].kind = PossibleRangeValues::infinity;
        }
    }
};

void printRange(RangeValue &rangeValue)
{
    if (rangeValue.isInfinity())
    {
        errs() << "-inf:inf"
               << "\n";
    }
    else if (rangeValue.isUnknown())
    {
        errs() << "unknown"
               << "\n";
    }
    else
    {
        errs() << rangeValue.lvalue->getValue() << ":" << rangeValue.rvalue->getValue();
    }
}

void debugPrint(RangeResult &rangeStates)
{
    RangeState state;
    for (auto &valueStatePair : rangeStates)
    {
        auto *inst = llvm::dyn_cast<llvm::GetElementPtrInst>(valueStatePair.first);
        if (!inst)
        {
            continue;
        }
        state = analysis::getIncomingState(rangeStates, *inst);
    }

    for (auto &valueStatePair : rangeStates)
    {
        auto *inst = llvm::dyn_cast<llvm::Instruction>(valueStatePair.first);
        if (!inst)
        {
            continue;
        }
        errs() << *inst << '\n';
        auto range = state[inst];
        printRange(range);
        errs() << "==================\n";
    }
}

bool queryAliasing(Value *v1, Value *v2)
{
    if (!v1 || !v2)
        return false;
    if (!v1->getType()->isPointerTy() || !v2->getType()->isPointerTy())
    {
        errs() << "Not a Pointer!" << '\n';
        return false;
    }
    // check bit cast
    if (BitCastInst *bci = dyn_cast<BitCastInst>(v1))
    {
        if (bci->getOperand(0) == v2)
            return true;
    }
    // handle load instruction
    if (LoadInst *li = dyn_cast<LoadInst>(v1))
    {

        auto load_addr = li->getPointerOperand();
        for (auto user : load_addr->users())
        {
            if (isa<LoadInst>(user))
            {
                if (user == v2)
                    return true;
            }
            if (StoreInst *si = dyn_cast<StoreInst>(user))
            {

                if (si->getPointerOperand() == load_addr)
                {

                    if (si->getValueOperand() == v2)
                        return true;
                }
            }
        }
    }
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

std::string
findProgramInstructionInPDG(Instruction *instruction)
{
    std::string statement;
    std::string instructionString;
    std::string pdgLabel = "";
    std::string functionName;
    std::string instructionDbgID = "";
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

    if (!instruction)
        return "";

    if (instructionAddressesToStringsMap.find(instruction) != instructionAddressesToStringsMap.end())
    {
        instructionString = instructionAddressesToStringsMap[instruction];
    }
    else
    {
        rso << *(instruction);
    }

    functionName = instruction->getFunction()->getName();
    std::size_t found = functionName.find("_nesCheck");
    if (found != std::string::npos)
        functionName = functionName.substr(0, found);
    instructionDbgID = getDebugID(instruction);
    instructionValue = neo4j_string(instructionString.c_str());
    functionNameValue = neo4j_string(functionName.c_str());
    programNameValue = neo4j_string(programName.c_str());
    dbgIDValue = neo4j_string(instructionDbgID.c_str());

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
        errs() << "Failed to obtain record:" << instructionString << ":" << functionName << ":" << programName << "\n";

    neo4j_close_results(results);
    neo4j_close(connection);
    return pdgLabel;
}

bool saveUnsafePointerArithmeticInstsFoundInDB(std::set<llvm::Instruction *> unsafeStackPtrs)
{

    std::string statement;
    std::string instruction_string;
    std::string function_name = "NULL";
    std::string instructionDbgID = "";
    std::string logicalDBNodeID;
    std::string pdg_label;
    // Set a hard character limit on any field returned from any query (DB schema ensures remains in bounds)
    char *field = (char *)malloc(sizeof(char) * 500);
    int unsafePointerNumber = 1;
    bool isIRModified = false;
    Instruction *instruction = nullptr;
    llvm::raw_string_ostream rso(instruction_string);

    neo4j_connection_t *connection;
    neo4j_value_t nodeTypeValue;
    neo4j_value_t pdgLabelValue;
    neo4j_value_t stateTypeValue, labelValue;
    neo4j_map_entry_t mapEntries[7];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    if (unsafeStackPtrs.empty())
        return true;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    for (auto unsafePtrInst : unsafeStackPtrs)
    {
        instruction_string.clear();
        statement.clear();
        rso.flush();
        isIRModified = false;
        instruction = &*(unsafePtrInst);
        // Find the original instruction string
        if (instructionAddressesToStringsMap.find(instruction) != instructionAddressesToStringsMap.end())
            instruction_string = instructionAddressesToStringsMap[instruction];
        // Modified  IR
        else
        {
            rso << *(instruction);
            isIRModified = true;
            errs()
                << "Unsafe Ptr Artihmetic:Might be a new instruction string (not present earlier) so check count of states created:"
                << *instruction << "\n";
        }
        // Function will remain the same
        if (instruction->getFunction())
        {

            function_name = instruction->getFunction()->getName().str();
            std::size_t found = function_name.find("_nesCheck");
            if (found != std::string::npos)
                function_name = function_name.substr(0, found);
        }
        else
        {
            errs() << "\t Failed to find function:"
                   << "\n";
            return false;
        }

        instructionDbgID = getDebugID(instruction);
        pdg_label = findProgramInstructionInPDG(instruction);

        /*     // BEGIN
            if (unsafePointerNumber == 1)
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
            } */

        errs() << "Function name: " << function_name << "\n";
        // errs() << "Instruction and dbg id: " << *instruction << ":" << instructionDbgID << "\n";

        // TODO - Deal with this pointer kind and label etc
        nodeTypeValue = neo4j_string(STATE_TYPE);
        pdgLabelValue = neo4j_string(pdg_label.c_str());
        stateTypeValue = neo4j_string(UNSAFE_POINTER_STATE_TYPE);
        labelValue = neo4j_string(UNSAFE_POINTER_STACK_STATE_LABEL);

        mapEntries[0] = neo4j_map_entry("node_type", nodeTypeValue);
        mapEntries[1] = neo4j_map_entry("state_type", stateTypeValue);
        mapEntries[2] = neo4j_map_entry("pdg_label", pdgLabelValue);
        mapEntries[3] = neo4j_map_entry("label", labelValue);

        // statement = "MERGE (p:ProgramInstruction{dbgID:$dbgID, instruction:$instruction, function_name:$function_name, program_name:$program_name}) ON CREATE SET p.label=randomUUID() WITH p ";

        statement = "MATCH (p:ProgramInstruction) WHERE p.label=$pdg_label WITH p";

        statement += " CREATE (node:AttackGraphNode{id:randomUUID(),type:$node_type,label:$label,program_name:p.program_name,state_type:$state_type})-[:EDGE]->(p)  RETURN node.id";

        params = neo4j_map(mapEntries, 4);

        results = neo4j_run(connection, statement.c_str(), params);
        while ((record = neo4j_fetch_next(results)) != NULL)
        {
            //  ag ID
            neo4j_ntostring(neo4j_result_field(record, 0), field, 500);
            logicalDBNodeID = std::string(field);
            logicalDBNodeID = logicalDBNodeID.substr(1, logicalDBNodeID.length() - 2);
            unsafePtrToLogicalIDDB[unsafePtrInst] = logicalDBNodeID;
        }
        neo4j_close_results(results);
        instructionDbgID.clear();
        logicalDBNodeID.clear();
        /*   // Commit
          if (unsafePointerNumber == TRANSACTION_SIZE)
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
              unsafePointerNumber = 0;
          } */
        unsafePointerNumber++;
    }

    /*   // Commit any open transaction with < TRANSACTION_SIZE queries
      if (unsafePointerNumber < TRANSACTION_SIZE)
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
      } */

    neo4j_close(connection);
    return true;
}

void saveUnsafeStackObjectsInDB()
{
    // Step 1 - Fetch all OOB states (GEP)
    std::string statement;
    std::string unsafePtrArithmeticLogicalID;
    std::string pdg_label;
    std::string unsafeObjectAGID;

    // Set a hard character limit on any field returned from any query
    char *field = (char *)malloc(sizeof(char) * 500);

    neo4j_connection_t *connection;
    neo4j_value_t programNameValue;
    neo4j_value_t stateTypeValue;

    neo4j_map_entry_t mapEntries[2];
    neo4j_value_t params;
    neo4j_result_t *record;
    neo4j_result_stream_t *results;

    //  - Update DB
    neo4j_map_entry_t secondQueryMapEntries[3];
    neo4j_value_t unsafeObjectStateTypeValue;
    neo4j_value_t unsafeObjectIDValue;

    // To avoid creating duplicate nodes for unsafe stack objects
    std::map<std::string, std::string> pdgLabelToAttackGraphNodeID;
    programNameValue = neo4j_string(programName.c_str());
    stateTypeValue = neo4j_string(STATE_TYPE);
    unsafeObjectStateTypeValue = neo4j_string(UNSAFE_STACK_OBJECT);

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    for (auto mapIt : unsafePtrToUnsafeStackObjects)
    {
        for (auto source_it : mapIt.second)
        {
            pdg_label = findProgramInstructionInPDG(source_it);
            unsafeObjectAGID.clear();
            // TODO - Insert hook to create pdg node for stack object (if needed)
            if (pdgLabelToAttackGraphNodeID.find(pdg_label) == pdgLabelToAttackGraphNodeID.end())
            {
                // Create the new AG node for the unsafe object
                errs() << "\t Creating logical node for unsafe obj " << *source_it << "\n";

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
            unsafePtrArithmeticLogicalID = unsafePtrToLogicalIDDB[mapIt.first];
            secondQueryMapEntries[1] = neo4j_map_entry("oob_state_id", neo4j_string(unsafePtrArithmeticLogicalID.c_str()));

            statement = "MATCH (unsafeObject:AttackGraphNode) WHERE unsafeObject.id=$unsafe_object_id  WITH unsafeObject MATCH (oobState:AttackGraphNode) WHERE oobState.id=$oob_state_id  MERGE (unsafeObject)-[e:SOURCE]->(oobState)";

            params = neo4j_map(secondQueryMapEntries, 2);
            results = neo4j_run(connection, statement.c_str(), params);
            neo4j_close_results(results);
        }
    }
    neo4j_close(connection);
}

bool createMayBeStackGEPAttackStates(std::set<llvm::Instruction *> unsafeStackPtrs)
{
    std::string statement;
    std::string pdg_label;
    std::string debugID;
    std::string instruction_string;
    std::string function_name = "NULL";
    int unsafePointerNumber = 1;
    bool isNewInstruction = false;
    Instruction *instruction = nullptr;
    llvm::raw_string_ostream rso(instruction_string);

    neo4j_connection_t *connection;
    neo4j_value_t labelValue, nodeTypeValue, instructionValue, functionNameValue, programNameValue;
    neo4j_value_t stateTypeValue;
    neo4j_value_t pdgLabelValue;
    neo4j_map_entry_t mapEntries[7];
    neo4j_value_t params;
    neo4j_result_stream_t *results;

    connection = neo4j_connect(URI, NULL, NEO4J_INSECURE);

    for (auto unsafePtrInst : unsafeStackPtrs)
    {
        instruction_string.clear();
        statement.clear();
        rso.flush();
        isNewInstruction = false;
        instruction = &*(unsafePtrInst);
        // Find the original instruction string
        if (instructionAddressesToStringsMap.find(instruction) != instructionAddressesToStringsMap.end())
            instruction_string = instructionAddressesToStringsMap[instruction];
        // New instruction due to changes to the IR
        else
        {
            rso << *(instruction);
            isNewInstruction = true;
            errs()
                << "May:Might be a new instruction string (not present earlier) so check count of states created:"
                << *instruction << "\n";
        }
        // Function will remain the same
        if (instruction->getFunction())
        {

            function_name = instruction->getFunction()->getName().str();
            std::size_t found = function_name.find("_nesCheck");
            if (found != std::string::npos)
                function_name = function_name.substr(0, found);
        }
        else
        {
            errs() << "\t Failed to find function:"
                   << "\n";
            return false;
        }
        // BEGIN
        if (unsafePointerNumber == 1)
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

        debugID = getDebugID(instruction);
        pdg_label = findProgramInstructionInPDG(instruction);

        errs() << "Function name: " << function_name << "\n";
        // errs() << "PDG Label: " << pdg_label << "\n";

        labelValue = neo4j_string(UNSAFE_POINTER_STACK_STATE_LABEL);
        nodeTypeValue = neo4j_string(STATE_TYPE);
        stateTypeValue = neo4j_string(UNSAFE_MAYBE_STACK_OOB_STATE_TYPE);
        pdgLabelValue = neo4j_string(pdg_label.c_str());

        mapEntries[0] = neo4j_map_entry("pdg_label", pdgLabelValue);
        mapEntries[1] = neo4j_map_entry("node_type", nodeTypeValue);
        mapEntries[2] = neo4j_map_entry("state_type", stateTypeValue);
        mapEntries[3] = neo4j_map_entry("label", labelValue);

        statement = "MATCH (p:ProgramInstruction) WHERE p.label=$pdg_label WITH p";
        statement += " CREATE (node:AttackGraphNode{id:randomUUID(),type:$node_type,label:$label,program_name:p.program_name,state_type:$state_type})-[:EDGE]->(p)  RETURN node";

        params = neo4j_map(mapEntries, 4);

        results = neo4j_run(connection, statement.c_str(), params);
        if (results == NULL)
        {
            errs() << "ERROR - FAILED TO INSERT NODE\n";
            neo4j_close(connection);
            return false;
        }
        neo4j_close_results(results);

        // Commit
        if (unsafePointerNumber == TRANSACTION_SIZE)
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
            unsafePointerNumber = 0;
        }
        unsafePointerNumber++;
    }

    // Commit any open transaction with < TRANSACTION_SIZE queries
    if (unsafePointerNumber < TRANSACTION_SIZE)
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

Argument *findArgument(Value *argOrGV)
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

void identifyFormalArguments(Function *function)
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

void findStackDataSource(GetElementPtrInst *oobGEP, std::set<Instruction *> &stackSources)
{
    if (!oobGEP)
        return;
    auto addressTakenVariable = oobGEP->getPointerOperand();
    Function *currFunc = oobGEP->getFunction();
    std::queue<Value *> workList;
    std::set<Value *> valuesSeen;
    Argument *argument = nullptr;

    workList.push(addressTakenVariable);
    errs() << "GEP:" << *oobGEP << "\n";
    errs() << "\t Address taken var:" << *addressTakenVariable << "\n";

    if (valueToStackObjects.find(oobGEP) != valueToStackObjects.end())
    {
        errs() << "\t Cache hit\n";
        stackSources = valueToStackObjects[oobGEP];
    }

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
                        auto storedValueOperand = storeInst->getOperand(0);
                        errs() << "\t\t Store:" << *storeInst << ":" << storedValueOperand << "\n";
                        workList.push(storedValueOperand);
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
        else if (GlobalVariable *gv = dyn_cast<GlobalVariable>(curr))
        {
            errs() << "\t GV:" << gv->getName() << "\n";
            //            if (gv->getType()->isPointerTy())
            //                for (auto user_it: gv->users()) {
            //                    //This is an over approximation
            //                    if (StoreInst *storeInst = dyn_cast<StoreInst>(user_it)) {
            ////                    errs() << "\t Store:" << *storeInst << "\n";
            ////                    errs() << "\t Store:" << *storeInst->getOperand(0) << "\n";
            //                        workList.push(storeInst->getOperand(0));
            //                    }
            //                }
        }
        valuesSeen.insert(curr);
        workList.pop();
    }

    // valueToStackObjects[oobGEP] = stackSources;
    errs() << "# Stack sources found:" << stackSources.size() << "\n";

    // return stackSources;
}

void pruneUnsafeGEPSFound(std::set<Instruction *> unsafeGEPs)
{
    std::string instruction_string, function_name = "NULL";
    llvm::raw_string_ostream rso(instruction_string);
    GetElementPtrInst *gepInst = nullptr;
    int noOperands = -1;
    int i = 1;
    int unsafeStackGEPCount = 0;
    bool isUnsafeStackGEP = false;
    bool mayPointToStack = false;
    const TargetLibraryInfo *TLI = nullptr;
    std::set<Instruction *> unsafeStackObjectGEPs;
    // These GEPs may point to stack or heap or BSS (SVF
    std::set<Instruction *> mayBeUnsafeStackObjectGEPs;
    std::set<Instruction *> unsafeStackObjectsFound;

    SVF::NodeID nodeId;
    alias::PTAWrapper &ptaw = alias::PTAWrapper::getInstance();
    SVF::PointsTo pointsToInfo;

    if (!ptaw.hasPTASetup())
    {
        errs() << "Points to info not computed\n";
        return;
    }

    errs() << unsafeGEPs.size() << "\n";
    for (auto it : unsafeGEPs)
    {
        // errs() << BLUE << "Checking whether unsafe pointer is on the stack " << NORMAL << "\n";
        isUnsafeStackGEP = true;
        unsafeStackObjectsFound.clear();
        gepInst = dyn_cast<GetElementPtrInst>(&*it);
        errs() << i << ".Instruction " << *gepInst << "\n";
        noOperands = gepInst->getNumOperands();
        errs() << "\t # operands:" << noOperands << "\n";
        TLI = &tliPass->getTLI(*(gepInst->getFunction()));

        errs() << "\t Pointer Operand "
               << " -" << *(gepInst->getPointerOperand()) << "\n";

        // This means if no points to info available we are over approximating to say it does point to stack
        mayPointToStack = false;
        // Step 1 - Check if still points to the stack (if the above check succeeded)
        if (!(ptaw._ander_pta->getPAG()->hasValueNode(gepInst)) &&
            !(ptaw._ander_pta->getPAG()->hasValueNode(gepInst->getPointerOperand())))
        {
            errs() << BLUE << "No SVF node so check if can find out using CCured's value range analysis" << NORMAL
                   << "\n";
            isUnsafeStackGEP = false;
            mayPointToStack = true;
        }
        else if (ptaw._ander_pta->getPAG()->hasValueNode(gepInst) || ptaw._ander_pta->getPAG()->hasValueNode(gepInst->getPointerOperand()))
        {

            if (isa<ExtractValueInst>(gepInst->getPointerOperand()) && ptaw._ander_pta->getPAG()->hasValueNode(gepInst))
            {
                // SVF crashes with extract value so
                nodeId = ptaw._ander_pta->getPAG()->getValueNode(gepInst);
            }

            else
                nodeId = ptaw._ander_pta->getPAG()->getValueNode(gepInst->getPointerOperand());

            pointsToInfo = ptaw._ander_pta->getPts(nodeId);
            if (pointsToInfo.empty())
            {
                errs() << RED << "\t Points to info unavailable! " << NORMAL << "\n";
                mayPointToStack = true;
                isUnsafeStackGEP = false;
            }

            // Iterate through the objects
            for (auto memObjID = pointsToInfo.begin();
                 memObjID != pointsToInfo.end(); memObjID++)
            {

                auto *targetObj = ptaw._ander_pta->getPAG()->getObject(*memObjID);

                // If any element in the points to set is not on the stack (Conservative)
                if (targetObj->isStack())
                {
                    auto stackObj = dyn_cast<Instruction>(targetObj->getRefVal());
                    mayPointToStack = true;
                    if (stackObj)
                    {
                        // errs() << "\t" << *stackObj << "\n";
                        unsafeStackObjectsFound.insert(const_cast<Instruction *>(stackObj));
                    }
                }
            }

            // errs() << BLUE << "It is an unsafe stack pointer! " << NORMAL << "\n";
            isUnsafeStackGEP = isUnsafeStackGEP && (!unsafeStackObjectsFound.empty());
            unsafeStackGEPCount = unsafeStackGEPCount + isUnsafeStackGEP;
        }
        // Only if it points to stack
        if (!unsafeStackObjectsFound.empty())
        {
            unsafeStackObjectGEPs.insert(gepInst);
            unsafePtrToUnsafeStackObjects[gepInst] = unsafeStackObjectsFound;
        }
        // May point to stack either SVF doesn't have ref, or incorrect, or no points to info
        else if (mayPointToStack)
        {
            errs() << "\t\t"
                   << "**** May point to stack (unable to find any obj - SVF) or points to info unavailable ******\n";
            findStackDataSource(gepInst, unsafeStackObjectsFound);
            if (!unsafeStackObjectsFound.empty())
            {
                unsafeStackObjectGEPs.insert(gepInst);
                unsafePtrToUnsafeStackObjects[gepInst] = unsafeStackObjectsFound;
            }
            else
                mayBeUnsafeStackObjectGEPs.insert(gepInst);
            errs() << "\t\t (Unsafe stack objects found) with DFA-" << unsafeStackObjectsFound.size() << "\n";
        }

        errs() << "\t (Is it an unsafe stack gep)-" << isUnsafeStackGEP << "\n";
        errs() << "\t (Unsafe stack objects found)-" << unsafeStackObjectsFound.size() << "\n";

        ++i;
    }

    errs() << NORMAL << "\n";
    errs() << BLUE << "# Unsafe Stack Object GEPs found by value range: " << RED << unsafeStackObjectGEPs.size()
           << NORMAL
           << "\n";
    errs() << BLUE << "# May be Unsafe Stack Object GEPs found by value range: " << RED
           << mayBeUnsafeStackObjectGEPs.size()
           << NORMAL
           << "\n";
    errs() << NORMAL << "\n";

    assert(saveUnsafePointerArithmeticInstsFoundInDB(unsafeStackObjectGEPs));
    saveUnsafeStackObjectsInDB();
    // if (!mayBeUnsafeStackObjectGEPs.empty())
    assert(createMayBeStackGEPAttackStates(mayBeUnsafeStackObjectGEPs));
}

void valueRangeAnalysis(Module *M, std::set<Value *> stackSeqPointerSet, std::map<llvm::Instruction *, std::string> irMap,
                        alias::PTAWrapper &ptaw)
{
    std::set<llvm::Instruction *> unsafePtr;
    // main_nesCheck, toplev_main
    auto *mainFunction = M->getFunction("main_nesCheck");
    if (!mainFunction)
    {
        llvm::report_fatal_error("Unable to find main function.");
    }

    module = M;
    instructionAddressesToStringsMap = irMap;

    programName = module->getModuleIdentifier();
    programName = programName.substr(0, programName.length() - 3);

    using Value = RangeValue;
    using Transfer = RangeTransfer;
    using Meet = RangeMeet;
    using Analysis = analysis::ForwardDataflowAnalysis<Value, Transfer, Meet>;
    Analysis analysis{*M, mainFunction};
    auto results = analysis.computeForwardDataflow();
    errs() << "Computed Value Range results: " << results.size() << '\n';
    for (auto &[ctxt, contextResults] : results)
    {
        for (auto &[function, rangeStates] : contextResults)
        {
            for (auto &valueStatePair : rangeStates)
            {
                auto *inst = llvm::dyn_cast<llvm::GetElementPtrInst>(valueStatePair.first);
                if (!inst)
                {
                    continue;
                }
                auto &state = analysis::getIncomingState(rangeStates, *inst);
                Type *type = cast<PointerType>(
                                 cast<GetElementPtrInst>(inst)->getPointerOperandType())
                                 ->getElementType();
                auto arrayTy = dyn_cast_or_null<ArrayType>(type);
                auto structTy = dyn_cast_or_null<StructType>(type);

                // This is classified as safe using PDG and context sensitive analysis since we don't have that version of dataguard we
                if (!arrayTy && !structTy)
                {
                    /*  errs() << "\nThis is a pointer to type: " << *type << '\n';
                     // print context
                     for (Instruction *c_instr : ctxt)
                     {
                         if ((c_instr) && (c_instr->getDebugLoc()))
                         {
                             errs() << "Call Site: ";
                             errs() << *c_instr << '\n';
                             // TODO: Call site rewrited by NesCheck, print instruction instead
                             // c_instr->getDebugLoc().print(errs());
                             // errs() << "\n";
                         }
                     }
                     if (inst->getDebugLoc())
                     {
                         errs() << "Definition Site: ";
                         inst->getDebugLoc().print(errs());
                         errs() << ", ";
                     }
                     // print fn name
                     errs() << "In Func: " << function->getName().str() << ", ";
                     // print line
                     if (inst->getDebugLoc())
                         errs() << "At Line: " << inst->getDebugLoc().getLine() << '\n';
                     else
                         errs() << "Dbg info corrupted!\n";
                     errs() << "Classify this pointer as unsafe!\n"; */
                    unsafePtr.insert(inst);
                }

                if (arrayTy)
                {
                    errs() << '\n';
                    auto size = arrayTy->getNumElements();
                    auto elmtTy = arrayTy->getElementType();
                    auto &layout = M->getDataLayout();
                    auto numBytes = layout.getTypeAllocSize(arrayTy);
                    auto elmtBytes = layout.getTypeAllocSize(elmtTy);
                    llvm::Value *index;
                    if (inst->getNumOperands() > 2)
                    {
                        index = inst->getOperand(2);
                    }
                    else
                    {
                        index = inst->getOperand(1);
                    }
                    auto constant = dyn_cast<ConstantInt>(index);
                    if (constant)
                    {
                        if (!constant->isNegative() && !constant->uge(size))
                        {
                            /* // print context
                            bool first = true;
                            for (Instruction *c_instr : ctxt)
                            {
                                if ((c_instr) && (c_instr->getDebugLoc()))
                                {
                                    if (first)
                                    {
                                        first = false;
                                        errs() << "Direct Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                    else
                                    {
                                        errs() << "Indirect Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                }
                            }
                            // print file name
                            if (inst->getDebugLoc())
                            {
                                errs() << "Definition Site: ";
                                inst->getDebugLoc().print(errs());
                                errs() << ", ";
                            }
                            // print fn name
                            errs() << "In Func: " << function->getName().str() << ", ";
                            // print line
                            if (inst->getDebugLoc())
                                errs() << "At Line: " << inst->getDebugLoc().getLine() << '\n';
                            else
                                errs() << "Dbg info corrupted!\n";
                            // print buf bytes
                            errs() << "Declared Size: " << numBytes << ", ";
                            // print indices
                            errs() << "Access Range: " << (int64_t)constant->getValue().getLimitedValue() * elmtBytes
                                   << '\n'; */
                            if (numBytes >= ((int64_t)constant->getValue().getLimitedValue() * elmtBytes))
                            {
                                // errs() << "Classify this array as safe!\n";
                                continue;
                            }
                            else
                            {
                                // errs() << "Classify this array as unsafe!\n";
                                unsafePtr.insert(inst);
                            }
                        }
                    }
                    else
                    {
                        auto &rangeValue = state[index];
                        if (rangeValue.isUnknown() ||
                            rangeValue.isInfinity() ||
                            rangeValue.lvalue->isNegative() ||
                            rangeValue.rvalue->uge(size))
                        {
                            /* // print context
                            bool first = true;
                            for (Instruction *c_instr : ctxt)
                            {
                                if ((c_instr) && (c_instr->getDebugLoc()))
                                {
                                    if (first)
                                    {
                                        first = false;
                                        errs() << "Direct Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                    else
                                    {
                                        errs() << "Indirect Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                }
                            }
                            // print file name
                            if (inst->getDebugLoc())
                            {
                                errs() << "Definition Site: ";
                                inst->getDebugLoc().print(errs());
                                errs() << ", ";
                            }
                            // print fn name
                            errs() << "In Func: " << function->getName().str() << ", ";
                            // print line
                            if (inst->getDebugLoc())
                                errs() << "At Line: " << inst->getDebugLoc().getLine() << '\n';
                            else
                                errs() << "Dbg info corrupted!\n";
                            // print buf bytes
                            errs() << "Declared Size: " << numBytes << ", "; */
                            if (rangeValue.isInfinity() || rangeValue.isUnknown())
                            {
                                // errs()
                                //     << "Access Range cannot be determined since GEP has non-constant offset operand!\n";
                                // errs() << "Classify this array as unsafe!\n";
                                unsafePtr.insert(inst);
                            }
                            else
                            {
                                auto l = (int64_t)rangeValue.lvalue->getLimitedValue();
                                auto r = (int64_t)rangeValue.rvalue->getLimitedValue();
                                if (l < 0 || r < 0)
                                {
                                    // errs() << "Access Range is negative! Could be an unconditional bug!\n";
                                    // errs() << "Classify this array as unsafe!\n";
                                    unsafePtr.insert(inst);
                                }
                                // errs() << "Classify this array as safe!\n";
                                // errs() << l * (int64_t)elmtBytes << ':' << r * (int64_t)elmtBytes << '\n';
                            }
                        }
                    }
                }

                else if (structTy)
                {
                    // errs() << '\n';
                    auto size = structTy->getNumElements();
                    auto &layout = M->getDataLayout();
                    auto numBytes = layout.getTypeAllocSize(structTy);
                    llvm::Value *index;
                    if (inst->getNumOperands() > 2)
                    {
                        index = inst->getOperand(2);
                    }
                    else
                    {
                        index = inst->getOperand(1);
                    }
                    const llvm::StructLayout *structureLayout = layout.getStructLayout(structTy);
                    auto constant = dyn_cast<ConstantInt>(index);
                    if (constant)
                    {
                        auto intIndex = constant->getValue().getLimitedValue();
                        if (intIndex < size)
                        {
                            auto offset = structureLayout->getElementOffset(intIndex);
                            if (!constant->isNegative() && !constant->uge(size))
                            {
                                /*  // print context
                                 bool first = true;
                                 for (Instruction *c_instr : ctxt)
                                 {
                                     if ((c_instr) && (c_instr->getDebugLoc()))
                                     {
                                         if (first)
                                         {
                                             first = false;
                                             errs() << "Direct Use Site: ";
                                             c_instr->getDebugLoc().print(errs());
                                             errs() << "\n";
                                         }
                                         else
                                         {
                                             errs() << "Indirect Use Site: ";
                                             c_instr->getDebugLoc().print(errs());
                                             errs() << "\n";
                                         }
                                     }
                                 }
                                 // print file name
                                 if (inst->getDebugLoc())
                                 {
                                     errs() << "Definition Site: ";
                                     inst->getDebugLoc().print(errs());
                                     errs() << ", ";
                                 }
                                 // print fn name
                                 errs() << "In Func: " << function->getName().str() << ", ";
                                 // print line
                                 if (inst->getDebugLoc())
                                     errs() << "At Line: " << inst->getDebugLoc().getLine() << '\n';
                                 else
                                     errs() << "Dbg info corrupted!\n";
                                 // print buf bytes
                                 errs() << "Declared Size: " << numBytes << ", ";
                                 errs() << "Access Range: " << offset << '\n'; */
                                if (numBytes >= offset)
                                {
                                    // errs() << "Classify this structure as safe!\n";
                                }
                                else
                                {
                                    // errs() << "Classify this structure as unsafe!\n";
                                    unsafePtr.insert(inst);
                                }
                            }
                        }
                        else
                        {
                            /* errs() << '\n'
                                   << "Offset corrupted!" << '\n';
                            bool first = true;
                            for (Instruction *c_instr : ctxt)
                            {
                                if ((c_instr) && (c_instr->getDebugLoc()))
                                {
                                    if (first)
                                    {
                                        first = false;
                                        errs() << "Direct Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                    else
                                    {
                                        errs() << "Indirect Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                }
                            }
                            if (inst->getDebugLoc())
                            {
                                errs() << "Definition Site: ";
                                inst->getDebugLoc().print(errs());
                                errs() << ", ";
                            }
                            // print fn name
                            errs() << "In Func: " << function->getName().str() << ", ";
                            // print line
                            if (inst->getDebugLoc())
                                errs() << "At Line: " << inst->getDebugLoc().getLine() << '\n';
                            else
                                errs() << "Dbg info corrupted!\n";
                            // print buf bytes
                            errs() << "Declared Size: " << numBytes << ", ";
                            errs() << "Access Range is corrupted since the index is corrupted!\n";
                            errs() << "Classify this structure as unsafe!\n"; */
                            unsafePtr.insert(inst);
                        }
                    }
                    else
                    {
                        auto &rangeValue = state[index];
                        if (rangeValue.isUnknown() ||
                            rangeValue.isInfinity() ||
                            rangeValue.lvalue->isNegative() ||
                            rangeValue.rvalue->uge(size))
                        {
                            /* // print context
                            bool first = true;
                            for (Instruction *c_instr : ctxt)
                            {
                                if ((c_instr) && (c_instr->getDebugLoc()))
                                {
                                    if (first)
                                    {
                                        first = false;
                                        errs() << "Direct Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                    else
                                    {
                                        errs() << "Indirect Use Site: ";
                                        c_instr->getDebugLoc().print(errs());
                                        errs() << "\n";
                                    }
                                }
                            }
                            // print file name
                            if (inst->getDebugLoc())
                            {
                                errs() << "Definition Site: ";
                                inst->getDebugLoc().print(errs());
                                errs() << ", ";
                            }
                            // print fn name
                            errs() << "In Func: " << function->getName().str() << ", ";
                            // print line
                            if (inst->getDebugLoc())
                                errs() << "At Line: " << inst->getDebugLoc().getLine() << '\n';
                            else
                                errs() << "Dbg info corrupted!\n";
                            // print buf bytes
                            errs() << "Declared Size: " << numBytes << ", "; */
                            if (rangeValue.isInfinity() || rangeValue.isUnknown())
                            {
                                // errs() << "Access Range cannot be determined "
                                //        << "since GEP has non-constant offset operand!\n";
                                // errs() << "Classify this structure as unsafe!\n";
                                unsafePtr.insert(inst);
                            }
                        }
                    }
                }
            }
        }
    }

    std::set<llvm::Instruction *> intersectionUnsafePtr;
    errs() << "CCured analysis found unsafe stack objects: " << stackSeqPointerSet.size() << " unsafe pointers!\n";
    errs() << "Value range analysis found: " << unsafePtr.size() << " unsafe pointers!\n";

    GetElementPtrInst *gepInst = nullptr;

    // Set up TLI
    const TargetLibraryInfo *TLI = NULL;
    legacy::PassManager passManager;
    tliPass = new TargetLibraryInfoWrapperPass();
    passManager.add(tliPass);
    passManager.run(*module);

    for (auto it : unsafePtr)
    {

        gepInst = dyn_cast<GetElementPtrInst>(&*it);
        if (gepInst)
        {
            llvm::Value *pointerOperand = gepInst->getPointerOperand();
            if (stackSeqPointerSet.find(gepInst->getPointerOperand()) != stackSeqPointerSet.end())
            {
                // errs() << "\t OOB GEP" << *gepInst << "\n";
                // errs() << "\t Pointer Operand "
                //        << " -" << *(gepInst->getPointerOperand()) << "\n";

                intersectionUnsafePtr.insert(&*gepInst);
            }
            else
            {
                // errs() << BLUE << "Checking if  OOB GEPs point to the stack (maybe through a global ptr)" << NORMAL
                //        << "\n";
                intersectionUnsafePtr.insert(&*gepInst);
            }
        }
    }
    errs() << "\t After intersection with CCured (and including global ptr) before 2nd points to pruning:"
           << intersectionUnsafePtr.size() << "\n";

    // Change - We prune here using points to then save results i.e. unsafe object, unsafe ptr arithmetic in the db.
    pruneUnsafeGEPSFound(intersectionUnsafePtr);
}
