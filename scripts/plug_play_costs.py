"""
     Script to compute various estimates for given placement using metadata and check estimates 
     Max cost estimation MD is off. we estimate per func but apply per obj using per func estimate (fixed)

"""

from neo4j import GraphDatabase
import sys
from monitoring_constants_and_ds import get_cost_estimates,MonitorType,MonitorOperations

from monitoring_constants_and_ds import UNSAFE_POINTER_STATE_TYPE,UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE,UNSAFE_POINTER_READ_STACK_ACTION_TYPE,UNSAFE_STACK_OBJECT

from monitoring_constants_and_ds import IMPACTED_STACK_POINTER,IMPACTED_STACK_OBJECT

from monitoring_constants_and_ds import ENTRY_NODE,ENTRY_NODE_LABEL, exec_times_ref
import os
import numpy as np
import pickle
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures


ESTIMATE_COST_TO_SANITIZE_ALL=False

program_name = None


unsafe_op_to_targets = {}
targets_to_unsafe_op = {}
all_unsafe_operations = set()
func_freq_cache={}

  


def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(uri, auth=("neo4j", "secret"), encrypted=False)
    return driver


def test_freq_info():
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name   RETURN node.id as id, node.count_train as freq ORDER BY node.id",
            program_name=program_name)

        for record in result:
            node_id = str(record["id"])
            freq = int(record["freq"])
            # print(freq)
    return

def get_all_asan_check_monitoring_points():
    monitor_to_total_freq_count = {}
    monitor_to_total_freq_count[MonitorType.BBC] = 0
    monitor_to_total_freq_count[MonitorType.ASAN] = 0

    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name AND (node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id,node.count_ref as freq ORDER BY node.id",
            program_name=program_name,upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            if record["freq"]:    
                freq = int(record["freq"])
            else:
                freq=0
            # print(monitor_type,freq)
            
            monitor_to_total_freq_count[MonitorType.ASAN] = monitor_to_total_freq_count[MonitorType.ASAN] + freq
    print("ALL checks:",monitor_to_total_freq_count)
    return monitor_to_total_freq_count

def get_all_check_monitoring_points():
    monitor_to_total_check_freq_count = {}
    monitor_to_total_check_freq_count[MonitorType.BBC] = 0
    monitor_to_total_check_freq_count[MonitorType.ASAN] = 0
    asan_check_ids=set()

    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name AND (node.action_type=$upa_type OR node.action_type=$read_upa_type)  RETURN node.id as id,node.count_ref as freq ORDER BY node.id",
            program_name=program_name,upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            if record["freq"]:    
                freq = int(record["freq"])
            else:
                freq=0
            node_id=str(record["id"])
            asan_check_ids.add(node_id)
            # print(monitor_type,freq)
            
            monitor_to_total_check_freq_count[MonitorType.ASAN] = monitor_to_total_check_freq_count[MonitorType.ASAN] + freq


    # Fetch all and filter out ASAN checks
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name  RETURN node.id as id, node.count_ref as freq ORDER BY node.id",
            program_name=program_name)

        for record in result:
            node_id=str(record["id"])
            if record["freq"]:    
                freq = int(record["freq"])
            else:
                freq=0
            if node_id not in asan_check_ids:
                  monitor_to_total_check_freq_count[MonitorType.BBC] = monitor_to_total_check_freq_count[MonitorType.BBC] + freq

    print("ALL checks:",monitor_to_total_check_freq_count)

    return monitor_to_total_check_freq_count    

def get_selected_monitoring_points():
    monitor_to_total_freq_count = {}
    monitor_to_total_freq_count[MonitorType.BBC] = 0
    monitor_to_total_freq_count[MonitorType.ASAN] = 0

    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name  AND EXISTS (node.monitor) RETURN node.id as id, node.monitor as monitorType,node.count_ref as freq ORDER BY node.id",
            program_name=program_name)

        for record in result:
            node_id=str(record["id"])
            monitor_type = str(record["monitorType"])
            if record["freq"]:    
                freq = int(record["freq"])
            else:
                freq=0
            # print(monitor_type,freq)
            if monitor_type == "ASAN":
                monitor_to_total_freq_count[MonitorType.ASAN] = monitor_to_total_freq_count[MonitorType.ASAN] + freq
            elif monitor_type=="BBC":
                  monitor_to_total_freq_count[MonitorType.BBC] = monitor_to_total_freq_count[MonitorType.BBC] + freq
              
    print("Selected placement Checks:",monitor_to_total_freq_count)
    return monitor_to_total_freq_count


def find_all_metadata_functions():
    # monitor_to_object_md_freq_count= {MonitorType.BBC: 0, MonitorType.ASAN: 0}
    monitor_type_to_function = { MonitorType.ASAN: set()}
    monitor_to_function_md_freq_count = { MonitorType.ASAN: 0}
    function_to_objects_cnt={}

    # Step 1 - Fetch MP functions
    with driver.session() as session:

        # Fetch functions that def need source data
        result = session.run(
            "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(a:MP) WHERE "
            "a.program_name=p.program_name=$program_name AND (a.action_type=$unsafe_write OR a.action_type=$unsafe_read)  RETURN  obj.id as objID, p.function_name as functionName ",
            program_name=program_name,unsafe_write=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE,unsafe_read=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)
        for record in result:
            # print(record)
            function_name = str(record["functionName"])
            monitor_type_to_function[MonitorType.ASAN].add(function_name)
            if function_name not in function_to_objects_cnt:
                function_to_objects_cnt[function_name]=0
            function_to_objects_cnt[function_name]=function_to_objects_cnt[function_name]+1
       
        # print("Function to objects:",function_to_objects_cnt)
        for monitor_type in monitor_type_to_function.keys():
            for func in monitor_type_to_function[monitor_type]:
                freq=0

                if func not in func_freq_cache:
                    result = session.run(
                        "MATCH (p:Entry) WHERE "
                        "p.program_name=$program_name AND p.function_name=$function_name  RETURN  p.count_ref as freq",
                        program_name=program_name, function_name=func, entry=ENTRY_NODE)
                    for record in result:
                        if record["freq"]:
                            freq = int(record["freq"])
                        # print("\t",func,freq)
                      
                    func_freq_cache[func]=freq

                    # if func not in func_freq_cache:
                    #     result = session.run(
                    #     "MATCH (p:ProgramInstruction) WHERE "
                    #     "p.program_name=$program_name AND p.function_name=$function_name AND p.instruction CONTAINS "
                    #     "$entry SET p:Entry RETURN  p.count_ref as freq",
                    #     program_name=program_name, function_name=func, entry=ENTRY_NODE)
                    #     for record in result:
                    #         if record["freq"]:
                    #             freq = int(record["freq"])
                    #         # print("\t",func,freq)
                        
                    #         func_freq_cache[func]=freq

                monitor_to_function_md_freq_count[monitor_type] = monitor_to_function_md_freq_count[
                                                                          monitor_type] + (func_freq_cache[func])

     
                                                                        
    monitor_to_function_md_freq_count[MonitorType.BBC]=monitor_to_function_md_freq_count[MonitorType.ASAN]
    print("ALL MD:",monitor_to_function_md_freq_count)
    return monitor_to_function_md_freq_count, None


def find_metadata_functions():
    monitor_to_object_md_freq_count= { MonitorType.ASAN: 0}
    monitor_type_to_function = { MonitorType.ASAN: set(),MonitorType.BBC:set()}
    monitor_to_function_md_freq_count = { MonitorType.ASAN: 0,MonitorType.BBC:0}
    objects_to_function={}
    function_to_objects_cnt={}
    global func_freq_cache

    # Step 1 - Fetch metadata objects and  functions

    with driver.session() as session:
        # Fetch functions that def need source data (ASAN)
        result = session.run(
            "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(a:MP) WHERE "
            "a.program_name=p.program_name=$program_name AND a.monitor=$asan RETURN  obj.id as objID, p.function_name as functionName, a.monitor as monitorType ",
            program_name=program_name,asan="ASAN")
        for record in result:
            object_id = str(record["objID"])
            monitor_type = str(record["monitorType"])
            # print(record)
            function_name = str(record["functionName"])
            objects_to_function[object_id]=function_name
            if function_name not in function_to_objects_cnt:
                function_to_objects_cnt[function_name]=0
            function_to_objects_cnt[function_name]=function_to_objects_cnt[function_name]+1
            assert monitor_type == "ASAN"
            monitor_type_to_function[MonitorType.ASAN].add(function_name)

        # Fetch functions that def need source data (Baggy)

        result = session.run(
            "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(a:MP) WHERE "
            "a.program_name=p.program_name=$program_name AND a.monitor=$baggy RETURN  obj.id as objID, p.function_name as functionName, a.monitor as monitorType ",
            program_name=program_name,baggy="BBC")
        for record in result:
            object_id = str(record["objID"])
            monitor_type = str(record["monitorType"])
            # print(record)
            function_name = str(record["functionName"])
            objects_to_function[object_id]=function_name
            assert monitor_type == "BBC"
            monitor_type_to_function[MonitorType.BBC].add(function_name)

        # print("Function to unsafe objects:",function_to_objects_cnt)
        for monitor_type in monitor_type_to_function.keys():
            for func in monitor_type_to_function[monitor_type]:
                freq=0
                if func not in func_freq_cache:
                    result = session.run(
                        "MATCH (p:Entry) WHERE "
                        "p.program_name=$program_name AND p.function_name=$function_name AND p.instruction CONTAINS "
                        "$entry RETURN  p.count_ref as freq",
                        program_name=program_name, function_name=func, entry=ENTRY_NODE)
                    for record in result:
                        if record["freq"]:
                            freq = int(record["freq"])
                        # print("\t",func,freq)
                    func_freq_cache[func]=freq
                monitor_to_function_md_freq_count[monitor_type] = monitor_to_function_md_freq_count[
                                                                          monitor_type] + (func_freq_cache[func])        
    # Obj count 
    # for obj in objects_to_function:
    #     func=objects_to_function[obj]
    #     freq=func_freq_cache[func]
    #     monitor_to_object_md_freq_count[MonitorType.ASAN] = monitor_to_object_md_freq_count[
    #                                                                 MonitorType.ASAN] + func_freq_cache[func]
    #     print(obj,":",freq)

    # print("Asan MD Function freq:",monitor_to_function_md_freq_count[MonitorType.ASAN])
    # print("Baggy MD Function freq:",monitor_to_function_md_freq_count[MonitorType.BBC])
                                                                    
    print("Selected placement MD:",monitor_to_function_md_freq_count)
    return monitor_to_function_md_freq_count, monitor_to_object_md_freq_count


def find_free_metadata_functions():
    monitor_type_to_function = { MonitorType.ASAN: set()}
    monitor_to_function_md_freq_count = { MonitorType.ASAN: 0}
    global func_freq_cache

    # Perlbench hack
    obj_to_checks={}

    # Step 1 - Fetch MP functions

    with driver.session() as session:

        result = session.run(
            "MATCH (a:MP)-[:EDGE]->(p:ProgramInstruction) WHERE "
            "a.program_name=p.program_name=$program_name AND   ToInteger(a.count_ref)=0 RETURN  DISTINCT p.function_name as functionName ",
            program_name=program_name,asan="ASAN")
        for record in result:
            # monitor_type = str(record["monitorType"])
            # print(record)
            function_name = str(record["functionName"])
            # assert monitor_type == "ASAN"
            # if monitor_type == "BBC":
            #     monitor_type_to_function[MonitorType.BBC].add(function_name)
            # elif monitor_type == "ASAN":
            # monitor_type_to_function[MonitorType.ASAN].add(function_name)

        # Fetch functions that def need source data (ASAN)
        result = session.run(
            "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(a:MP) WHERE "
            "a.program_name=p.program_name=$program_name AND ToInteger(a.count_ref)=0 RETURN  DISTINCT p.function_name as functionName,a.id as mpID",
            program_name=program_name,asan="ASAN")
        for record in result:
            # monitor_type = str(record["monitorType"])
            # print(record)
            function_name = str(record["functionName"])
            mpID=str(record["mpID"])
            # assert monitor_type == "ASAN"
            monitor_type_to_function[MonitorType.ASAN].add(function_name)
            if function_name not in obj_to_checks:
                obj_to_checks[function_name]=set()
            obj_to_checks[function_name].add(mpID)
        print(len(monitor_type_to_function[MonitorType.ASAN]),"==",len(obj_to_checks.keys()))
        for func in monitor_type_to_function[MonitorType.ASAN]:
            
            freq=0
            result = session.run(
                "MATCH (p:Entry) WHERE "
                "p.program_name=$program_name AND p.function_name=$function_name AND p.instruction CONTAINS "
                "$entry RETURN  p.count_ref as freq",
                program_name=program_name, function_name=func, entry=ENTRY_NODE)
            for record in result:
                
                if record["freq"]:
                    freq = int(record["freq"])
                if not freq:
                    obj_to_checks.pop(func)
                # print("\t",func,freq)


    

                
        # Obj count 
        # TODO - Before we switch to this clean up schema (make db go vroom)
        # Clean up
        total_p=0
        for obj in obj_to_checks:
            total_p=total_p+len(obj_to_checks[obj])
            print("# checks",len(obj_to_checks[obj]))
            continue
            for check in obj_to_checks[obj]:
                print("Removing as mp",check)
                result = session.run(
                        "MATCH (mp:MP) WHERE mp.id=$mp_id REMOVE mp:MP RETURN labels(mp) as label",
                        mp_id=check)
                for record in result:
                    print(record["label"])

        print(total_p)
                    

  
                                                                    
    print(monitor_to_function_md_freq_count)
    return monitor_to_function_md_freq_count, None

def estimate_check_costs(all=False):
    asan_check_costs = 0
    baggy_check_costs=0
    if all:
        monitor_to_total_freq_count = get_all_check_monitoring_points()
    else:
        monitor_to_total_freq_count = get_selected_monitoring_points()

    asan_check_cost=get_cost_estimates(program_name,MonitorOperations.Checks,MonitorType.ASAN)
    baggy_check_cost=get_cost_estimates(program_name,MonitorOperations.Checks,MonitorType.BBC)


    print("ASAN Check Operation COST", asan_check_cost)
    print("BBC Check Operation COST", baggy_check_cost)
  
    for monitor_type in monitor_to_total_freq_count:
        if monitor_type == MonitorType.ASAN:
            asan_check_costs =  (monitor_to_total_freq_count[ MonitorType.ASAN] * asan_check_cost)
        elif monitor_type==MonitorType.BBC:
            baggy_check_costs =  (monitor_to_total_freq_count[ MonitorType.BBC] * baggy_check_cost)


    print("Total ASAN Check COSTs", asan_check_costs)
    print("Total BBC Check COSTs", baggy_check_costs)
    print()
    if all:
        return asan_check_costs, baggy_check_costs
    return asan_check_costs+baggy_check_costs


def save_budget_runtime_overhead_map(data, filename):
    with open(filename, 'wb') as f:
        pickle.dump(data, f)

def load_budget_runtime_overhead_map(filename, desired_value=None):
    loaded_data={}
    if os.path.isfile(filename):
        with open(filename, 'rb') as f:
            loaded_data = pickle.load(f)
    if desired_value and loaded_data:
        # print("All data points:",loaded_data)
        input_budgets=list(loaded_data.keys())
        runtime_overheads=list(loaded_data.values())
        glb=None
        lub=None
        for pos in range(len(runtime_overheads)):
            runtime_overhead=runtime_overheads[pos]
            diff=runtime_overhead-desired_value
            if diff>0:
                if not lub or runtime_overhead<runtime_overheads[lub] :
                    # print(diff,pos,runtime_overhead)
                    lub=pos
            elif diff<0:
                if not glb or runtime_overhead>runtime_overheads[glb]:
                    # print(diff,pos,runtime_overhead)
                    glb=pos
        print("GLB and LUB:",glb,lub)            
        if glb is not None and lub is not None:
            print("LUB:",runtime_overheads[lub])
            print("GLB:",runtime_overheads[glb])
            loaded_data.clear()
            loaded_data[input_budgets[lub]]=runtime_overheads[lub]
            loaded_data[input_budgets[glb]]=runtime_overheads[glb]

        # for input_budget in loaded_data:
        #     if loaded_data[input_budget]        
    return loaded_data


def estimate_metadata_costs(all=False):
    asan_md_costs = 0
    baggy_md_costs=0
    if all:
        monitor_to_total_freq_count,_= find_all_metadata_functions()
    else:
        monitor_to_total_freq_count,monitor_obj_to_freq_count = find_metadata_functions()


    asan_md_cost=get_cost_estimates(program_name,MonitorOperations.Metadata,MonitorType.ASAN)
    baggy_md_cost=get_cost_estimates(program_name,MonitorOperations.Metadata,MonitorType.BBC)

    print("ASAN MD Operation Cost :",asan_md_cost)
    print("BAGGY MD Operation Cost :",baggy_md_cost)
    # MD Costs are based purely on MD instructions and func freq no discrepancy wrt location
    for monitor_type in monitor_to_total_freq_count:
        if monitor_type==MonitorType.BBC:
            baggy_md_costs =  (monitor_to_total_freq_count[MonitorType.BBC] * baggy_md_cost)
        elif monitor_type==MonitorType.ASAN: 
            asan_md_costs =  (monitor_to_total_freq_count[MonitorType.ASAN] * asan_md_cost)
      
    print("Total ASan MD COSTs", asan_md_costs)
    print("Total Baggy MD COSTs", baggy_md_costs)
    print()
    if all:
        return asan_md_costs,baggy_md_costs
    return asan_md_costs+baggy_md_costs

def get_protection_of_computed_placement():

    global unsafe_op_to_targets
    global targets_to_unsafe_op
    global all_unsafe_operations
    profit_per_unsafe_operation = {}
    unsafe_operations_freq_count={}
    unsafe_op_to_md={}
    md_operations_freq_count={}

    reachable_targets = set()
    unsafe_targets=set()
    covered_targets=set()
    partially_covered_targets=set()

    asan_unsafe_op=set()
    baggy_unsafe_op=set()

    # Now UPAs with reachable uses
    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id as id,target.id as target,node.count_ref as count ORDER BY node.id",
            program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            node_id = str(record["id"])
            if node_id not in unsafe_op_to_targets:
                unsafe_op_to_targets[node_id] = set()
            target_id = str(record["target"])
            reachable_targets.add(target_id)
            unsafe_op_to_targets[node_id].add(target_id)
            if not record["count"]:
                freq=0
            else:
                freq = int(record["count"])
            unsafe_operations_freq_count[node_id] = freq
            if node_id not in unsafe_op_to_md:
                unsafe_op_to_md[node_id]=set()

    # Targets to unsafe op 
    for target in reachable_targets:
        with driver.session() as session:
            result = session.run(
                "MATCH (target:AttackGraphNode)<-[:EDGE]-(node:AttackGraphNode) WHERE  target.id=$target_id AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN target.id as id,node.id as node ORDER BY target.id",
                target_id=target, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

            for record in result:
                target_id = str(record["id"])
                if target_id not in targets_to_unsafe_op:
                    targets_to_unsafe_op[target_id] = set()

                node_id = str(record["node"])
                targets_to_unsafe_op[target_id].add(node_id)
    
    num_targets = len(reachable_targets)


    # Now MD as a monitoring point for all  unsafe operations
    md_to_func={}
    for unsafe_operation in unsafe_op_to_md:
        with driver.session() as session:
            result = session.run(
                "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(node:AttackGraphNode) WHERE  node.id=$node_id RETURN DISTINCT obj.id as objectID,p.function_name as functionName",
                node_id=unsafe_operation)

            for record in result:
                obj_id = str(record["objectID"])
                function_name = str(record["functionName"])
                md_to_func[obj_id]=function_name
                unsafe_op_to_md[unsafe_operation].add(obj_id)
                # all_md_points.add(obj_id)


        for object_id in unsafe_op_to_md[unsafe_operation]:
            if object_id not in md_operations_freq_count:
                function_name=md_to_func[object_id]
                with driver.session() as session:
                    result = session.run(
                        "MATCH (func:Entry) WHERE func.function_name=$function_name AND func.program_name=$program_name RETURN func.count_ref as count",
                        program_name=program_name, function_name=function_name)

                    for record in result:
                        if record["count"]:
                            freq = int(record["count"])
                        else:
                            freq=0
                        md_operations_freq_count[object_id]=freq                

    for unsafe_op in unsafe_op_to_targets:
        profit = 0.0
        for target in unsafe_op_to_targets[unsafe_op]:
            profit = profit+(1/len(targets_to_unsafe_op[target]))
        profit_per_unsafe_operation[unsafe_op] = profit

    free_protection=0
    free_unsafe_operations=set()
    num_free_unsafe_operations=0
    for unsafe_operation in unsafe_op_to_targets:
        freq = unsafe_operations_freq_count[unsafe_operation]
        if not freq :
            md_free=True
            for md in unsafe_op_to_md[unsafe_operation]:
                if md_operations_freq_count[md]:
                    md_free=False
                    break
            # print("Testing for free:",unsafe_operation)
            if md_free:
                num_free_unsafe_operations=num_free_unsafe_operations+1
                free_protection=free_protection+profit_per_unsafe_operation[unsafe_operation]
                free_unsafe_operations.add(unsafe_operation)

    # ASAN OPs
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name  AND  node.monitor=$ASAN RETURN DISTINCT node.id as ID ORDER BY node.id",
            program_name=program_name,ASAN="ASAN")

        for record in result:
            node_id=str(record["ID"])
            asan_unsafe_op.add(node_id)
            # profit=profit+(profit_per_unsafe_operation[node_id])

    # Baggy covered unsafe operation        
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP)-[:EDGE]->(upa:AttackGraphNode) WHERE  node.program_name=$program_name  AND  node.monitor=$BAGGY RETURN DISTINCT upa.id as ID ORDER BY upa.id",
            program_name=program_name,BAGGY="BBC")

        for record in result:
            node_id=str(record["ID"])
            baggy_unsafe_op.add(node_id)

    print("# ASAN upa",len(asan_unsafe_op))
    print("# Baggy upa",len(baggy_unsafe_op))

    # Find all covered targets 
    partial_target_protection_dict={}
    protection_including_partial_targets=0
    for target in reachable_targets:
        all_baggy=True
        num_asan_covered=0
        num_baggy_covered=0
        for unsafe_op in targets_to_unsafe_op[target]:
            if unsafe_op not in baggy_unsafe_op:
                all_baggy=False
                # break
            if unsafe_op in asan_unsafe_op:
                num_asan_covered=num_asan_covered+1
            if unsafe_op in baggy_unsafe_op:
                num_baggy_covered=num_baggy_covered+1
            
        if all_baggy:
            covered_targets.add(target)
        elif (num_asan_covered+num_baggy_covered):
            partially_covered_targets.add(target)
            prot=(num_baggy_covered/len(targets_to_unsafe_op[target]))+(num_asan_covered*0.9/len(targets_to_unsafe_op[target]))
            partial_target_protection_dict[target]=prot
            protection_including_partial_targets=protection_including_partial_targets+prot


    # FInd all unsafe targets
    with driver.session() as session:
        result = session.run(
            "MATCH (obj:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE obj.program_name=$program_name AND obj.state_type=$unsafe_stack_object  WITH DISTINCT p MATCH (target:AttackGraphNode)-[:EDGE]->(p) WHERE   ( target.state_type=$stack_object  OR target.state_type=$stack_ptr)  RETURN target.id as target ",
            program_name=program_name, unsafe_stack_object="6",stack_object=IMPACTED_STACK_POINTER, stack_ptr=IMPACTED_STACK_OBJECT)

        for record in result:
    
            target_id = str(record["target"])
            unsafe_targets.add(target_id)

    
    # # Find all covered targets (even if partial)
    # with driver.session() as session:
    #     result = session.run(
    #         "MATCH (gep:AttackGraphNode)-[:EDGE]->(upa:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  target.program_name=$program_name AND upa.type=$action_type AND ( EXISTS(upa.monitor)  OR EXISTS(gep.monitor) )  RETURN DISTINCT target.id as target ",
    #         program_name=program_name,action_type="AttackAction")

    #     for record in result:
    
    #         target_id = str(record["target"])
    #         # if target_id in reachable_targets:
    #         covered_targets.add(target_id)

    num_non_free_targets=(num_targets-free_protection)
    print("# Targets", num_targets)
    print("# Eff non free Targets", num_non_free_targets)
    print("# Spatially unsafe targets",
          len(unsafe_targets))
    print("# Covered  targets (comlete) and # partially covered",
          len(covered_targets),len(partially_covered_targets))
    total_protection_non_free=protection_including_partial_targets+len(covered_targets)-free_protection
    print("Protection including partially covered targets",
          total_protection_non_free,(total_protection_non_free)*100/num_non_free_targets)

    num_targets_not_completely_protected=num_targets-len(covered_targets)
    num_targets_no_protection=num_targets_not_completely_protected-len(partially_covered_targets)
    print("# targets unsafe (including partial ones)",
          num_targets_not_completely_protected,num_targets_not_completely_protected*100/num_non_free_targets)
    
    print("# targets not protected at all",
          num_targets_no_protection,num_targets_no_protection*100/num_non_free_targets)
    
    # num_eff_not_protected=num_non_free_targets-protection_including_partial_targets
    # print("Effective # targets not covered and %",
    #       num_eff_not_protected,num_eff_not_protected/num_non_free_targets)
    # Lower bound on how many of the uncovered targets will be still be uncovered after safe stack
    num_uncovered_targets_unsafe=0
    for target in reachable_targets:
        if target not in covered_targets:
            if target in unsafe_targets:
                if target in partially_covered_targets:
                    num_uncovered_targets_unsafe=num_uncovered_targets_unsafe+(1-partial_target_protection_dict[target])
                else:
                    num_uncovered_targets_unsafe=num_uncovered_targets_unsafe+1
    print("Unprotected accurate (by considering partial)",num_uncovered_targets_unsafe)
    print("At least \% of unsafe targets (including partial) unsafe after placement and safe stack",num_uncovered_targets_unsafe*100/num_non_free_targets)


    # num_uncovered_targets_unsafe=0
    # for target in reachable_targets:
    #     if target not in covered_targets and target not in partially_covered_targets:
    #         if target in unsafe_targets:
    #             num_uncovered_targets_unsafe=num_uncovered_targets_unsafe+1

    # print("At least \% of targets are not protected at all after placement and safe stack",num_uncovered_targets_unsafe*100/num_non_free_targets)


    # print("Objective value:",profit)
    return 0

def fetch_safety_data(tx):
    result = tx.run(
            "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id as id,target.id as target ORDER BY node.id",
            program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)
    print("\t Finished querying")
    return list(result.to_eager_result())

def find_cases_where_asan_is_more_expensive():
    name=program_name
    free_unsafe_operations=set()
    upa_to_asan_mp = dict()
    upa_to_baggy_mp = dict()
    frequency_dict = {}
    asan_freqs = []
    baggy_freqs = []
    unsafe_op_to_targets={}
    unsafe_op_to_md={}
    num_unsafe_ops_where_asan_is_more_expensive=0
    num_unsafe_ops_where_baggy_is_more_expensive=0
    avg_diff_magnitude_asan=0
    avg_diff_magnitude_baggy=0
    should_fix=True
    unsafe_op_for_which_bbc_is_better=set()

    print("Fetching safety info")
    # driver.query()
    with driver.session() as session:
        # result=session.execute_read(fetch_safety_data)
        result = session.run(
            "MATCH (node:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id as id ORDER BY node.id",
            program_name=name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)
        result=result.data()    
        print("\t Finished querying")
        for record in result:
            node_id = str(record["id"])
            if node_id not in unsafe_op_to_targets:
                unsafe_op_to_targets[node_id] = set()
            # target_id = str(record["target"])
            # unsafe_op_to_targets[node_id].add(target_id)
    print("Done fetching safety info")

    # Now MD as a monitoring point for all  unsafe operations
    md_to_func={}
    md_operations_freq_count={}
    for unsafe_operation in unsafe_op_to_targets:
        if unsafe_operation not in unsafe_op_to_md:
            unsafe_op_to_md[unsafe_operation] = set()
        with driver.session() as session:
            result = session.run(
                "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(node:AttackGraphNode) WHERE  node.id=$node_id RETURN DISTINCT obj.id as objectID,p.function_name as functionName",
                node_id=unsafe_operation)

            for record in result:
                obj_id = str(record["objectID"])
                function_name = str(record["functionName"])
                md_to_func[obj_id]=function_name
                unsafe_op_to_md[unsafe_operation].add(obj_id)
                # all_md_points.add(obj_id)
        

        for object_id in unsafe_op_to_md[unsafe_operation]:
            if object_id not in md_operations_freq_count:
                function_name=md_to_func[object_id]
                with driver.session() as session:
                    result = session.run(
                        "MATCH (func:Entry) WHERE func.function_name=$function_name AND func.program_name=$program_name RETURN func.count_ref as count",
                        program_name=program_name, function_name=function_name)

                    for record in result:
                        if record["count"]:
                            freq = int(record["count"])
                        else:
                            freq=0
                        md_operations_freq_count[object_id]=freq 

    num_unsafe_ops_where_asan_is_more_expensive=0
    baggy_funcs=set()
    for unsafe_op in unsafe_op_to_targets:
        upa_to_asan_mp[unsafe_op] = set()
        upa_to_baggy_mp[unsafe_op] = set()
        asan_freq = 0
        baggy_freq = 0
        num_baggy_mps=0
        num_asan_mps=0
        same_func=False
        baggy_funcs.clear()

        # ASAN MPs
        with driver.session() as session:
            result = session.run(
                "MATCH (p:ProgramInstruction)<-[:EDGE]-(mp:MP) WHERE  mp.id=$upa_id   RETURN DISTINCT mp.id as id, mp.count_ref as count,p.instruction as inst, p.function_name as func", upa_id=unsafe_op
            )

            for record in result:
                asan_mp_id = str(record["id"])
                freq = int(record["count"])
                asan_func=str(record["func"])
                asan_inst_string=str(record["inst"])

                frequency_dict[asan_mp_id] = freq
                upa_to_asan_mp[unsafe_op].add(unsafe_op)
                asan_freq = asan_freq+freq
                num_asan_mps=num_asan_mps+1

        # BAGGY MPs
        
        with driver.session() as session:
            result = session.run(
                "MATCH (p:ProgramInstruction)<-[:EDGE]-(mp:MP)-[:EDGE]->(upa:AttackGraphNode) WHERE  upa.id=$upa_id  RETURN DISTINCT mp.id as id, mp.count_ref as count,p.instruction as inst, p.function_name as func", upa_id=unsafe_op)

            for record in result:
                baggy_mp_id = str(record["id"])
                freq = int(record["count"])
                baggy_func=str(record["func"])
                baggy_funcs.add(baggy_func)
                frequency_dict[baggy_mp_id] = freq
                upa_to_baggy_mp[unsafe_op].add(baggy_mp_id)
                baggy_freq = baggy_freq+freq
                num_baggy_mps=num_baggy_mps+1
                # print(baggy_mp_id,unsafe_op)
                if baggy_func==asan_func:
                    baggy_inst_string=str(record["inst"])

      

        if asan_freq>baggy_freq  and asan_func in baggy_funcs and  asan_inst_string[asan_inst_string.index("!dbg"):]==baggy_inst_string[baggy_inst_string.index("!dbg"):]:
            # if baggy_freq>asan_freq:
            print("\t Fix ",asan_freq,"==",baggy_freq," func:",asan_func)
            print("\t Baggy inst:",baggy_inst_string)
            print("\t ASAN inst:",asan_inst_string)
            if asan_inst_string[asan_inst_string.index("!dbg"):]==baggy_inst_string[baggy_inst_string.index("!dbg"):]:
                actual_count=asan_freq
                print("\t\t Would fix")
                # FIx it(if confirmed)
                if should_fix:
                    with driver.session() as session:
                        for mp_id in [baggy_mp_id,asan_mp_id]:
                            result = session.run(
                                "MATCH (mp:MP) WHERE  mp.id=$upa_id SET mp.count_ref=$count", upa_id=mp_id,count=actual_count)

        elif asan_freq > baggy_freq:
            avg_diff_magnitude_asan=avg_diff_magnitude_asan+(asan_freq-baggy_freq)
            # print("Profit of inter proc ASAN expensive case:",profit_per_unsafe_operation[unsafe_op])
            # print("\t Baggy inst:",baggy_inst_string,":",baggy_func)
            # print("\t ASAN inst:",asan_inst_string,":",asan_func)
            # if not baggy_freq or asan_freq/baggy_freq>=2:
                # print("\t",unsafe_op)
                # print("\t ASAN MPs:",num_asan_mps," Baggy MPs:",num_baggy_mps)
            # print(asan_freq,baggy_freq)
            # print("\t ",num_baggy_mps,num_asan_mps)
            num_unsafe_ops_where_asan_is_more_expensive=num_unsafe_ops_where_asan_is_more_expensive+1
            unsafe_op_for_which_bbc_is_better.add(unsafe_op)
        elif baggy_freq>asan_freq:
            # print("\t Baggy MPs:",num_baggy_mps," ASAN MPs:",num_asan_mps)
        
            num_unsafe_ops_where_baggy_is_more_expensive=num_unsafe_ops_where_baggy_is_more_expensive+1
            avg_diff_magnitude_baggy=avg_diff_magnitude_baggy+(baggy_freq-asan_freq)
        
        asan_freqs.append(asan_freq)
        baggy_freqs.append(baggy_freq)
        # print("\n")

    for unsafe_operation in unsafe_op_to_targets:
        freq = 0
        for mp in upa_to_asan_mp[unsafe_operation]:
            freq=freq+frequency_dict[mp]
        baggy_freq=0
        for mp in upa_to_baggy_mp[unsafe_operation]:
            baggy_freq=baggy_freq+frequency_dict[mp]
        if (not freq) or (not baggy_freq):
            md_free=True
            for md in unsafe_op_to_md[unsafe_operation]:
                if md_operations_freq_count[md]:
                    md_free=False
                    break
            # print("Testing for free:",unsafe_operation)
            if md_free:
                # print(unsafe_operation,freq,baggy_freq,md_free,len(unsafe_op_to_md[unsafe_operation]))
                free_unsafe_operations.add(unsafe_operation)

        
    # num_baggy_covers_more=read_monitoring_points_info(name)
    print("# Unsafe ops:",len(unsafe_op_to_targets))
    print("#  free Unsafe ops:",len(free_unsafe_operations))
    num_non_free=(len(unsafe_op_to_targets)-len(free_unsafe_operations))
    # print("ASAN MP Freq:", np.mean(asan_freqs))
    # print("Baggy MP Freq:", np.mean(baggy_freqs))
    print("# non free",num_non_free)
    print("# Cases where ASAN may be more expensive:",num_unsafe_ops_where_asan_is_more_expensive,(num_unsafe_ops_where_asan_is_more_expensive/num_non_free)*100)
    
    budget_difference=0
    asan_check_cost=get_cost_estimates(program_name,MonitorOperations.Checks,MonitorType.ASAN)
    asan_md_cost=get_cost_estimates(program_name,MonitorOperations.Metadata,MonitorType.ASAN)

    baggy_check_cost=get_cost_estimates(program_name,MonitorOperations.Checks,MonitorType.BBC)
    baggy_md_cost=get_cost_estimates(program_name,MonitorOperations.Metadata,MonitorType.BBC)

  



    actual_num_cases_wasan_more_expensive=0
    is_converged=False
    baggy_mds_covered=set()
    unsafe_op_for_which_bbc_is_better.clear()
    while not is_converged:
        is_converged=True
        for unsafe_op in unsafe_op_to_targets:
            if unsafe_op in unsafe_op_for_which_bbc_is_better:
                continue

            asan_c_freq=0
            baggy_c_freq=0
            asan_md_freq=0
            baggy_md_freq=0
            for mp in upa_to_asan_mp[unsafe_op]:
                asan_c_freq=asan_c_freq+frequency_dict[mp]
            
            for mp in upa_to_baggy_mp[unsafe_op]:
                baggy_c_freq=baggy_c_freq+frequency_dict[mp]

            for mp in unsafe_op_to_md[unsafe_op]:
                if mp not in baggy_mds_covered:
                    baggy_md_freq=baggy_md_freq+md_operations_freq_count[mp]   
                asan_md_freq=asan_md_freq+md_operations_freq_count[mp]

            diff=(asan_check_cost*asan_c_freq)-(baggy_check_cost*baggy_c_freq)+(asan_md_cost*asan_md_freq)-(baggy_md_cost*baggy_md_freq)
            # print("\t",asan_c_freq,baggy_c_freq,md_freq)
            if diff>0:
                actual_num_cases_wasan_more_expensive=actual_num_cases_wasan_more_expensive+1
                budget_difference=budget_difference+diff
                # print(unsafe_op,diff,actual_num_cases_wasan_more_expensive)
                for mp in upa_to_baggy_mp[unsafe_op]:
                    baggy_mds_covered.add(mp)
                is_converged=False
                unsafe_op_for_which_bbc_is_better.add(unsafe_op)
        print("Iterating",is_converged)

                 
    print("# Cases where ASAN is more expensive:",actual_num_cases_wasan_more_expensive,(actual_num_cases_wasan_more_expensive/num_non_free)*100)

    print("Estimated budget difference by using Baggy instead of asan for the expensive cases (s)",budget_difference)

    print("Estimated budget difference by using Baggy instead of asan for the expensive cases (%)",budget_difference*100/exec_times_ref[program_name])
    # print("# Cases where Baggy is more expensive:",num_unsafe_ops_where_baggy_is_more_expensive,avg_diff_magnitude_baggy)
    # if should_fix:
    #     generate_coverage_file(name)
    return 

"""
    This is the main script to 
    Initial solution 0 and then we set some check budget/cost level feeds to solver.
    We estimate cost for that sol here if fails reduce 
"""
if __name__ == "__main__":
    driver = get_db_driver()
    program_name = str(sys.argv[1])


    # Estimate cost to cover all using ASAN, Baggy
    if ESTIMATE_COST_TO_SANITIZE_ALL:
        # find_cases_where_asan_is_more_expensive()
        max_asan_check_cost,max_bbc_check_cost=estimate_check_costs(True)
        max_asan_md_cost,max_bbc_md_cost = estimate_metadata_costs(True)
        print("Max ASAN cost (s):",(max_asan_check_cost+max_asan_md_cost))
        print("Max ASAN cost to sanitize (%):",(max_asan_check_cost+max_asan_md_cost)*100/exec_times_ref[program_name])
        print("Max BBC cost (s):",(max_bbc_check_cost+max_bbc_md_cost))
        print("Max BBC cost to sanitize (%):",(max_bbc_check_cost+max_bbc_md_cost)*100/exec_times_ref[program_name])
        # exit(1)

    # Iterative budget refinement to get desired runtime overhead
    else:
        desired_budget=float(input("Enter desired budget (s)"))
        desired_budget_perc=(desired_budget/exec_times_ref[program_name])*100
        # Step 1 - Check if any placement already then use that ratio 
        current_overhead_perc=0
        # current_check_cost=estimate_check_costs()
        # if current_check_cost:
        #     current_md_cost=estimate_metadata_costs()
        #     current_overhead=current_check_cost+current_md_cost
        #     current_overhead_perc=(current_overhead/exec_times_ref[program_name])*100
        #     print("Estimated overhead for current placement (s)",current_overhead)
        #     print("Estimated overhead for current placement (%)",current_overhead_perc)
        current_overhead=float(input("Enter input budget (s)"))
        budget_runtime_overhead_map=load_budget_runtime_overhead_map(program_name+".pk1",desired_budget)
        if current_overhead:
            observed_runtime_overhead=float(input("Enter observed runtime overhead (s)"))
            if current_overhead not in budget_runtime_overhead_map or budget_runtime_overhead_map[current_overhead]!=observed_runtime_overhead:
                budget_runtime_overhead_map[current_overhead]=observed_runtime_overhead
                save_budget_runtime_overhead_map(budget_runtime_overhead_map,program_name+".pk1")
        print("Budget:",budget_runtime_overhead_map)
        # Here use Polynomial regression to predict the input budget required to obtain the desired overhead
        model = LinearRegression()
        estimated_budgets=np.array(list(budget_runtime_overhead_map.keys()))
        runtime_overheads=np.array(list(budget_runtime_overhead_map.values()))
        
        poly_feature = PolynomialFeatures(degree=2,include_bias=True)
        poly_estimated_overheads=poly_feature.fit_transform(estimated_budgets.reshape(-1,1))
        linear_estimated_overheads=estimated_budgets.reshape(-1,1)

        model.fit(linear_estimated_overheads,runtime_overheads)
        required_overhead=np.array([desired_budget])
        slope=np.array(model.coef_)
        intercept=model.intercept_
        print("Coeff:",slope)
        print("Intercept:",intercept)
        # intercept=0
        slope=np.append(slope,intercept-desired_budget)
        # p= [slope, intercept - desired_budget]
        print("Polynomial for desired runtime budget:",slope)
        predicted_budget=np.roots(slope)
        # predicted_budget_two=np.polynomial.polynomial.polyroots(slope)
        # predicted_budget = model.predict(required_overhead.reshape(-1,1))
        print("Predicted budget:",predicted_budget)
        
     
            

    





