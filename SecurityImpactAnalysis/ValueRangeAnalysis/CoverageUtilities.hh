

#ifndef SMART_MONITOR_COVERAGE_UTILITIES_HH
#define SMART_MONITOR_COVERAGE_UTILITIES_HH
// Coverage related
#include "GCOV.h"
#include <regex>
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
error "Missing the <filesystem> header."
#endif

#define WORKLOAD_TYPE "ref"

bool readCoverageData(std::string programName, std::string monitorName);

uint64_t getFunctionExecutionCount(Function *);

uint64_t getExecutionCount(Instruction *instruction);

#endif // SMART_MONITOR_COVERAGE_UTILITIES_HH
