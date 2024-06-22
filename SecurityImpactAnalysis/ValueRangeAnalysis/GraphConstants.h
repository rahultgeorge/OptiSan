//
// Created by Rahul Titus George on 4/20/21.
// TODO - Common interface for framework

#ifndef GRAPH_CONSTANTS_H
#define GRAPH_CONSTANTS_H
//Single header file that contains all constants related to the graph and neo4j


// For formatting purposes (taken from Nescheck)
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define BLUE "\033[0;34m"
#define GRAY "\033[1;30m"
#define DETAIL "\033[1;36m"
#define NORMAL "\033[0m"

//Graph query constants
#define URI  "neo4j://neo4j:secret@localhost:7687"
#define NEO4J_ID_FUNCTION  "randomUUID()"

//TODO - Standardize these labels across the pdg pass and other passes (Also simplify them?)

// PDG Relationship labels
#define DEF_USE_EDGE_TYPE "DEF_USE"
#define DATA_ALIAS_EDGE_TYPE "D_ALIAS"
#define PARAMETER_EDGE_TYPE "PARAMETER"
#define RAW_EDGE_TYPE "RAW"
#define GLOBAL_EDGE_TYPE "GLOBAL_DEP"
#define CALL_EDGE_TYPE "CALL"
#define CONTROL_EDGE_TYPE "CONTROL"
#define RET_EDGE_TYPE "RET"
#define DEFAULT_EDGE_TYPE "EDGE"


#define FORMAL_IN_ARG "FORMAL_IN"
#define ACTUAL_IN_ARG "ACTUAL_IN"


// Basic node types (Make this INT or a char)
#define SURFACE_TYPE "AttackSurface"
#define STATE_TYPE "AttackState"
#define ACTION_TYPE "AttackAction"

//UPA  edge - Pointer effects
#define DATA_EDGE_LABEL "New data edge(Unsafe stack pointer action)"

//Attack State types
#define SYS_CALL_ATTACK_STATE_TYPE  "0"
//Unsafe use (OOB)
#define UNSAFE_POINTER_STATE_TYPE  "1"
#define TAINTED_OPERAND_STATE_TYPE  "2"
#define DERIVED_UNSAFE_POINTER_STATE_TYPE  "3"
// New state type for an impacted pointer on the stack (that is can be modified/overwritten)
#define IMPACTED_STACK_POINTER "4"
// New state type for impacted data object on the stack
#define IMPACTED_STACK_OBJECT "5"
//Unsafe object (Actual object found by Dataguard)
#define UNSAFE_STACK_OBJECT "6"
// Unsafe GEP (May be stack) (Hacky for now)
#define UNSAFE_MAYBE_STACK_OOB_STATE_TYPE  "7"

//Unsafe pointer state may be noncontiguous
#define VARIABLE_INDEX "0"
#define LOOP_TAINTED "1"

//Attack Action types
#define SYS_CALL_ATTACK_ACTION_TYPE  "0"
#define UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE  "1"
#define UNSAFE_POINTER_READ_STACK_ACTION_TYPE  "2"
//TODO- Define more accurate types later (SPECIFICALLY THE PMI)
#define UNSAFE_POINTER_WRITE_NON_STACK_ACTION_TYPE  "3"
#define UNSAFE_POINTER_READ_NON_STACK_ACTION_TYPE  "4"
// OOB address is assigned to another ptr
#define UNSAFE_POINTER_PROPAGATION_STACK_ACTION_TYPE "5"
#define UNSAFE_POINTER_PROPAGATION_NON_STACK_ACTION_TYPE  "6"
// Memory uses of impacted pointer (Will create and refine these types later)
#define IMPACTED_POINTER_WRITE_ACTION_TYPE "7"
#define IMPACTED_POINTER_READ_ACTION_TYPE "8"
// Impacted/corrupt address is assigned to some other pr
#define IMPACTED_POINTER_PROPAGATION_ACTION_TYPE "9"
// Uses where corrupt value is used inside the function
#define IMPACTED_DATA_OBJECT_LOCAL_ACTION_TYPE "10"
// Uses which may outlive the function i.e corrupt value leaves the function eg global var, return val 
#define IMPACTED_DATA_OBJECT_NON_LOCAL_ACTION_TYPE "11"


// Constant Labels
#define UNSAFE_POINTER_STACK_STATE_LABEL "Stack Unsafe pointer"
#define UNSAFE_POINTER_NON_STACK_STATE_LABEL  "Non stack unsafe pointer"

/*
std::set<std::string> sensitiveSystemCalls = {"open", "openat", "openat2", "open64", "fopen", "creat", "fopen64",
                                              "scanf", "__isoc99_scanf",
                                              "getenv", "gets", "fgets", "fscanf", "sscanf", "__isoc99_fscanf",
                                              "__isoc99_sscanf",
                                              "socket", "socketpair",
                                              "read", "fread",
                                              "write", "fwrite",
                                              "link", "symlink", "unlink",
                                              "chmod", "fchmod", "fchmodat", "chown", "fchown",
                                              "recv", "recvfrom", "recvmsg",
                                              "send", "sendto", "sendmsg",
                                              "mprotect",
                                              "mmap", "munmap",
                                              "malloc", "free",
                                              "setenv", "setuid", "setgid",
                                              "execv", "execve", "fork", "clone"};

// Certain libc library calls  such as sprintf write to strings (aka buffers) and these might be UPAS
//TODO - Include summaries of micro lib c in our analysis

std::set<std::string> libraryUPACalls = {"strcat", "strncat", "strcpy", "sprintf", "snprintf"};

//Include https://releases.llvm.org/1.5/docs/LangRef.html#intrinsics - memcpy,memset,memmove
std::set<std::string> llvmIntrinsicLibraryCalls = {
        "memmove", "memset",
        "memcpy"};
*/
// If true this means
#define IGNORE_SURFACES 1


#endif //GRAPHCONSTANTS_H



