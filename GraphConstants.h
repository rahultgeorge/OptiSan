//
// Created by Rahul Titus George on 4/20/21.
//

#ifndef GRAPHCONSTANTS_H
#define GRAPHCONSTANTS_H
//Single header file that contains all constants related to the graph and neo4j
#include <set>
//Graph query constants
#define URI  "neo4j://neo4j:secret@localhost:7687"
#define NEO4J_ID_FUNCTION  "randomUUID()"

// Basic node types
#define SURFACE_TYPE "AttackSurface"
#define STATE_TYPE "AttackState"
#define ACTION_TYPE "AttackAction"

//UPA  edge - Pointer effects
#define DATA_EDGE_LABEL "New data edge(Unsafe stack pointer action)"

//Attack State types
#define SYS_CALL_ATTACK_STATE_TYPE  "0"
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

//Attack Action types
#define SYS_CALL_ATTACK_ACTION_TYPE  "0"
#define UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE  "1"
#define UNSAFE_POINTER_READ_STACK_ACTION_TYPE  "2"
//TODO- Define more accurate types later
#define UNSAFE_POINTER_WRITE_NON_STACK_ACTION_TYPE  "3"
#define UNSAFE_POINTER_READ_NON_STACK_ACTION_TYPE  "4"
//Pointer arithmetic
#define UNSAFE_POINTER_MANIPULATION_STACK_ACTION_TYPE "5"
#define UNSAFE_POINTER_MANIPULATION_NON_STACK_ACTION_TYPE  "6"

// Constant Labels
#define UNSAFE_POINTER_STACK_STATE_LABEL "Stack Unsafe pointer"
#define UNSAFE_POINTER_NON_STACK_STATE_LABEL  "Non stack unsafe pointer"
#define SYS_CALL_ARG_STATE_LABEL  "Tainted arg (arg to sys call)"
#define TAINTED_OPERAND_STATE_LABEL  "Tainted operand (unsafe write)"

#define UNSAFE_POINTER_WRITE_ACTION_LABEL  "uwrite"
#define UNSAFE_POINTER_READ_ACTION_LABEL "uread"


#endif //GRAPHCONSTANTS_H


