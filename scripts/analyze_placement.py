
"""
   Simple script to characterize current placement for program
"""

from neo4j import GraphDatabase
import sys
from monitoring_constants_and_ds import MonitorType,MonitorOperations

from monitoring_constants_and_ds import UNSAFE_POINTER_STATE_TYPE,UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE,UNSAFE_POINTER_READ_STACK_ACTION_TYPE,UNSAFE_STACK_OBJECT

from monitoring_constants_and_ds import IMPACTED_STACK_POINTER,IMPACTED_STACK_OBJECT

from monitoring_constants_and_ds import ASAN_ACCURACY
import time


ESTIMATE_COST_TO_SANITIZE_ALL=True

program_name = None


unsafe_op_to_targets = {}
targets_to_unsafe_op = {}
all_unsafe_operations = set()
all_targets=set()
profit_per_unsafe_operation = {}
free_unsafe_operations=set()


def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(uri, auth=("neo4j", "secret"), encrypted=False)
    return driver



def get_unsafe_operations_target_info():
    global unsafe_op_to_targets
    global targets_to_unsafe_op
    global all_unsafe_operations
    global all_targets


    # Fetch unsafe ops with targets
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( target.state_type=$target_obj  OR target.state_type=$target_ptr)  RETURN node.id as id,target.id as target ORDER BY node.id",
            program_name=program_name, target_obj=IMPACTED_STACK_OBJECT,target_ptr=IMPACTED_STACK_POINTER)

        for record in result:
            node_id = str(record["id"])
            if node_id not in unsafe_op_to_targets:
                unsafe_op_to_targets[node_id] = set()
            all_unsafe_operations.add(node_id)    
            target_id = str(record["target"])
            all_targets.add(target_id)
            unsafe_op_to_targets[node_id].add(target_id)
            if target_id not in targets_to_unsafe_op:
                    targets_to_unsafe_op[target_id] = set()

            targets_to_unsafe_op[target_id].add(node_id)
          
    print("# Unsafe operations:",len(all_unsafe_operations))
    print("# Targets :",len(all_targets))




def compute_free_targets_protected():
    return 0
    global profit_per_unsafe_operation
    tentative_free_unsafe_operations=set()
    num_free_unsafe_operations=0
    md_operations_freq_count={}

    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type) AND mp.count_ref=$zero  RETURN node.id as id,target.id as target ORDER BY node.id",
            program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE,zero="0")

        for record in result:
            node_id = str(record["id"])
            tentative_free_unsafe_operations.add(node_id)
    print("# unsafe ops with free checks:",tentative_free_unsafe_operations)        



def get_protection_of_computed_placement():
    global profit_per_unsafe_operation
    global all_targets
 
    asan_unsafe_op=set()
    baggy_unsafe_op=set()
    start=time.time()

    get_unsafe_operations_target_info()
    end=time.time()
    print("Time taken to read unsafe op, target info:",end-start)
    num_targets=len(all_targets)

    # for unsafe_op in unsafe_op_to_targets:
    #     profit = 0.0
    #     for target in unsafe_op_to_targets[unsafe_op]:
    #         profit = profit+(1/len(targets_to_unsafe_op[target]))
    #     profit_per_unsafe_operation[unsafe_op] = profit

 
    free_protection = compute_free_targets_protected()
    # ASAN OPs
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name  AND  node.monitor=$ASAN RETURN DISTINCT node.id as ID ORDER BY node.id",
            program_name=program_name,ASAN="ASAN")

        for record in result:
            node_id=str(record["ID"])
            asan_unsafe_op.add(node_id)

    # Baggy covered unsafe operation        
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP)-[:EDGE]->(upa:AttackGraphNode) WHERE  node.program_name=$program_name  AND  node.monitor=$BAGGY RETURN DISTINCT upa.id as ID ORDER BY upa.id",
            program_name=program_name,BAGGY="BBC")

        for record in result:
            node_id=str(record["ID"])
            baggy_unsafe_op.add(node_id)

    print("# ASAN unsafe op",len(asan_unsafe_op))
    print("# Baggy unsafe ops",len(baggy_unsafe_op))

    # Effective meaning w accuracy and includes partially protected
    targets_effective_protection=0
    targets_fully_protected_effectively=0
    targets_fully_protected=0
    targets_w_any_protection=0
    for target in all_targets:
  
        num_unsafe_ops_for_target=len(targets_to_unsafe_op[target])
        effective_target_protection =0 
        target_protection =0 
        for unsafe_op in targets_to_unsafe_op[target]:
            if unsafe_op  in baggy_unsafe_op:
                effective_target_protection = effective_target_protection +   1
                target_protection =target_protection + 1      
            elif unsafe_op in asan_unsafe_op:
                effective_target_protection = effective_target_protection +   ASAN_ACCURACY
                target_protection =target_protection + 1                  
        if effective_target_protection>0:
            targets_w_any_protection=targets_w_any_protection+1
        effective_target_protection =  effective_target_protection/ num_unsafe_ops_for_target

        target_protection =int( target_protection/ num_unsafe_ops_for_target)    
        targets_effective_protection=targets_effective_protection+effective_target_protection
        if effective_target_protection==1:         
            targets_fully_protected_effectively=targets_fully_protected_effectively+1
        if target_protection==1:
            targets_fully_protected=targets_fully_protected+1              


    # FInd all unsafe targets
    # with driver.session() as session:
    #     result = session.run(
    #         "MATCH (obj:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE obj.program_name=$program_name AND obj.state_type=$unsafe_stack_object  WITH DISTINCT p MATCH (target:AttackGraphNode)-[:EDGE]->(p) WHERE   ( target.state_type=$stack_object  OR target.state_type=$stack_ptr)  RETURN target.id as target ",
    #         program_name=program_name, unsafe_stack_object="6",stack_object=IMPACTED_STACK_POINTER, stack_ptr=IMPACTED_STACK_OBJECT)

    #     for record in result:
    
    #         target_id = str(record["target"])
    #         unsafe_targets.add(target_id)

    num_unsafe_operations=len(all_unsafe_operations)
    num_unsafe_operations_covered=len(asan_unsafe_op)+len(baggy_unsafe_op)

    print("# Unsafe ops",num_unsafe_operations )
    print("\\%\\ unsafe ops covered", (num_unsafe_operations_covered/num_unsafe_operations)*100)
  

    num_non_free_targets=(num_targets-free_protection)

    print("# Targets", num_targets)
    print("# Eff non free Targets", num_non_free_targets)

    print("Targets with any protection",
          targets_w_any_protection,(targets_w_any_protection)*100/num_non_free_targets)

    
    total_protection_non_free=targets_effective_protection-free_protection
    print("Effective protection (includes partial)",
          total_protection_non_free,(total_protection_non_free)*100/num_non_free_targets)

    
    print("Effective targets full protected #, (%) of targets w any protection",
          targets_fully_protected_effectively,(targets_fully_protected_effectively)*100/num_non_free_targets)

    print("Targets full covered  #, (%) of targets w any protection",
          targets_fully_protected,(targets_fully_protected)*100/num_non_free_targets)

    
    return 0




if __name__ == "__main__":
    driver = get_db_driver()
    program_name = str(sys.argv[1])

    get_protection_of_computed_placement()

     
            

    





