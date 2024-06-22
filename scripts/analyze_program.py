"""
    Simple script to analyze a few things about the unsafe operations
    1. Unsafe op -> targets avg mapping
    2. 'Heat map' of the MPs - how many hotter than the avg frequency of the MPs
"""

from neo4j import GraphDatabase
from enum import Enum
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sb
import scipy.stats as stats
from sklearn import preprocessing
import math
from monitoring_constants_and_ds import UNSAFE_POINTER_STATE_TYPE,UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, UNSAFE_POINTER_READ_STACK_ACTION_TYPE, UNSAFE_STACK_OBJECT
from monitoring_constants_and_ds import  IMPACTED_STACK_POINTER, IMPACTED_STACK_OBJECT, ENTRY_NODE
from monitoring_constants_and_ds import  MonitorType, MonitorOperations
from monitoring_constants_and_ds import exec_times_ref, get_cost_estimates, ASAN_ACCURACY


ANALYZE_OPTISAN_PLACEMENT_ONLY=True

ANALYZE_FREQUENCY_ONLY=False

program_name = None


profit_per_unsafe_operation = {}
unsafe_operations_freq_count ={}
# Unsafe operation to total freq of all operations needed for the unsafe operation
unsafe_operation_total_operations_freq_count={}
md_operations_freq_count={}
unsafe_op_to_md={}
func_to_objs={}
objs_to_func={}
func_freq_cache={}
unsafe_op_to_targets = {}
targets_to_unsafe_op = {}
unsafe_operation_to_cost={}


global_asan_freq_dist=None
all_unsafe_operations=set()
candea_op_covered=set()
optisan_asan_op_covered=set()
# used only when collecting both
optisan_baggy_op_covered=set()
budget=0
free_unsafe_operations=set()
free_protection=0

program_asan_check_cost_estimate=None
program_asan_md_cost_estimate=None
frequency_data_frame=None




def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(
        uri, auth=("neo4j", "secret"), encrypted=False)
    return driver


def find_unsafe_op_target_mapping_info():
    global profit_per_unsafe_operation
    profit_per_unsafe_operation.clear()
    unsafe_op_to_targets = dict()
    targets_to_unsafe_op = dict()
    avg_unsafe_op_target_count = 0
    reachable_targets = set()
    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id as id,target.id as target ORDER BY node.id",
            program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE,read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            node_id = str(record["id"])
            if node_id not in unsafe_op_to_targets:
                unsafe_op_to_targets[node_id] = set()

            target_id = str(record["target"])
            reachable_targets.add(target_id)
            unsafe_op_to_targets[node_id].add(target_id)

    for unsafe_op in unsafe_op_to_targets:
        avg_unsafe_op_target_count = avg_unsafe_op_target_count + \
            len(unsafe_op_to_targets[unsafe_op])

    avg_unsafe_op_target_count=avg_unsafe_op_target_count/len(unsafe_op_to_targets.keys())
    print("Avg num of targets per unsafe operation:", avg_unsafe_op_target_count)

    for target in reachable_targets:
        with driver.session() as session:
            result = session.run(
                "MATCH (target:AttackGraphNode)<-[:EDGE]-(node:AttackGraphNode) WHERE  target.id=$target_id AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN target.id as id,node.id as node ORDER BY target.id",
                target_id=target, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE,read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

            for record in result:
                target_id = str(record["id"])
                if target_id not in targets_to_unsafe_op:
                    targets_to_unsafe_op[target_id] = set()

                node_id = str(record["node"])
                targets_to_unsafe_op[target_id].add(node_id)

    avg_target_to_unsafe_op_count = 0

    for target in targets_to_unsafe_op:
        for unsafe_op in targets_to_unsafe_op[target]:
            avg_target_to_unsafe_op_count=avg_target_to_unsafe_op_count+1
    avg_target_to_unsafe_op_count=avg_target_to_unsafe_op_count/len(targets_to_unsafe_op.keys())
    print("AVG num of unsafe operations per target:",avg_target_to_unsafe_op_count)



    # Now let's do some frequency analysis
    upa_to_asan_mp = dict()
    upa_to_baggy_mp = dict()
    frequency_dict = {}
    asan_freqs = []
    baggy_freqs = []
    for unsafe_op in unsafe_op_to_targets:
        upa_to_asan_mp[unsafe_op] = set()
        upa_to_baggy_mp[unsafe_op] = set()
        asan_freq = 0
        baggy_freq = 0
        # BAGGY
        with driver.session() as session:
            result = session.run(
                "MATCH (mp:MP)-[:EDGE]->(upa:AttackGraphNode) WHERE  upa.id=$upa_id RETURN DISTINCT mp.id as id, mp.count_ref as count", upa_id=unsafe_op
            )

            for record in result:
                mp_id = str(record["id"])
                freq = int(record["count"])
                frequency_dict[mp_id] = freq
                upa_to_baggy_mp[unsafe_op].add(mp_id)
                baggy_freq = baggy_freq+freq
        # ASAN
        with driver.session() as session:
            result = session.run(
                "MATCH (mp:MP) WHERE  mp.id=$upa_id RETURN DISTINCT mp.id as id, mp.count_ref as count", upa_id=unsafe_op
            )

            for record in result:
                mp_id = str(record["id"])
                freq = int(record["count"])
                frequency_dict[mp_id] = freq
                upa_to_asan_mp[unsafe_op].add(unsafe_op)
                asan_freq = asan_freq+freq


        asan_freqs.append(asan_freq)
        baggy_freqs.append(baggy_freq)
        # print("\n")

    # print("ASAN MP Freq:", np.mean(asan_freqs))
    # print("Baggy MP Freq:", np.mean(baggy_freqs))

    # print("MAX ASAN MP Freq:", max(asan_freqs))
    # print("MAX Baggy MP Freq:", max(baggy_freqs))

    frequency_unsafe_op_asan = []
    frequency_unsafe_op_baggy = []

    for unsafe_op in unsafe_op_to_targets:
        asan_freq = 0
        baggy_freq = 0
        profit = 0
        # print(unsafe_op)
        for mp in upa_to_asan_mp[unsafe_op]:
            asan_freq = asan_freq+frequency_dict[mp]
        for mp in upa_to_baggy_mp[unsafe_op]:
            baggy_freq = baggy_freq+frequency_dict[mp]
        for target in unsafe_op_to_targets[unsafe_op]:
            profit = profit+(1/len(targets_to_unsafe_op[target]))
        profit_per_unsafe_operation[unsafe_op]=profit
        # print("\t Profit:",profit)
        # print("\t Freq:",asan_freq)
        frequency_unsafe_op_asan.append(asan_freq)
        frequency_unsafe_op_baggy.append(baggy_freq)

    # print(len(profit_per_unsafe_operation))
    print("Avg max profit per unsafe operation",np.mean(list(profit_per_unsafe_operation.values())))
    print("Std max profit per unsafe operation",
          np.std(list(profit_per_unsafe_operation.values())))
    print("Var of profit per unsafe operation",
            np.var(list(profit_per_unsafe_operation.values())))





    return


def read_frequency_and_estimate_costs(name):

    global unsafe_operations_freq_count
    global all_unsafe_operations
    global unsafe_op_to_md
    global md_operations_freq_count
    global budget
    global unsafe_operation_total_operations_freq_count
    global free_unsafe_operations
    global program_asan_check_cost_estimate 
    global program_asan_md_cost_estimate
    global unsafe_operation_to_cost

    program_asan_check_cost_estimate=get_cost_estimates(name,MonitorOperations.Checks,MonitorType.ASAN)
    program_asan_md_cost_estimate=get_cost_estimates(name,MonitorOperations.Metadata,MonitorType.ASAN)


    with driver.session() as session:        
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name AND node.type=$action_type RETURN node.id as id ORDER BY node.id",
            program_name=name, action_type="AttackAction")

        for record in result:
            node_id = str(record["id"])
            all_unsafe_operations.add(node_id)
            unsafe_operation_total_operations_freq_count[node_id]=0

    # ASAN Checks Freq
    with driver.session() as session:
        result = session.run(
            "MATCH (mp:MP)-[:EDGE]->(:AttackGraphNode) WHERE  mp.type=$action_type AND mp.program_name=$name RETURN DISTINCT mp.id as id, mp.count_ref as count", action_type="AttackAction",name=name)
        for record in result:
            mp_id = str(record["id"])
            freq = int(record["count"])
            unsafe_operations_freq_count[mp_id]=freq
            unsafe_operation_to_cost[mp_id]=(freq*program_asan_check_cost_estimate)
            unsafe_operation_total_operations_freq_count[mp_id]=freq
            unsafe_op_to_md[mp_id]=set()

    # Mapping  all unsafe operations to md
    with driver.session() as session:
        result = session.run(
            "MATCH (obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(mp:MP) WHERE  mp.type=$action_type AND mp.program_name=$name RETURN DISTINCT obj.id as objID, mp.id as mpID", action_type="AttackAction",name=name)

        for record in result:
            obj_id= str(record["objID"])
            mp_id= str(record["mpID"])     
            unsafe_op_to_md[mp_id].add(obj_id)


    print("# Total unsafe ops (with targets):",len(all_unsafe_operations),"==",len(unsafe_operation_total_operations_freq_count),"==",len(unsafe_op_to_md))


    # MD Freq
    with driver.session() as session:
        result = session.run(
            "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode) WHERE  obj.state_type=$object_type AND obj.program_name=$name  RETURN DISTINCT obj.id as objID, p.function_name as function", object_type=UNSAFE_STACK_OBJECT,name=name)

        for record in result:
            obj_id= str(record["objID"])
            function_name=str(record["function"])
            # print(obj_id)
            if function_name not in func_to_objs:
                func_to_objs[function_name]=set()
            func_to_objs[function_name].add(obj_id)
            objs_to_func[obj_id]=function_name
            if function_name not in func_freq_cache:
                result = session.run(
                        "MATCH (p:Entry) WHERE "
                        "p.program_name=$program_name AND p.function_name=$function_name  RETURN  p.count_ref as freq",
                        program_name=program_name, function_name=function_name, entry=ENTRY_NODE)
                for record in result:
                    freq=0
                    if record["freq"]:
                        freq = int(record["freq"])
                func_freq_cache[function_name]=freq

            md_operations_freq_count[obj_id]=func_freq_cache[function_name]




    for unsafe_op in unsafe_operations_freq_count:
        if unsafe_op in unsafe_op_to_md:
            for md_obj in unsafe_op_to_md[unsafe_op]:
                md_freq=md_operations_freq_count[md_obj]
                # unsafe_operation_to_cost[unsafe_op]=unsafe_operation_to_cost[unsafe_op]+(freq*program_asan_md_cost_estimate)
                unsafe_operation_total_operations_freq_count[unsafe_op]=unsafe_operation_total_operations_freq_count[unsafe_op]+md_freq
      

    for unsafe_operation in unsafe_operations_freq_count:
        freq = unsafe_operations_freq_count[unsafe_operation]
        if not freq :
            md_free=True
            if unsafe_operation in unsafe_op_to_md:
                for md in unsafe_op_to_md[unsafe_operation]:
                    if md_operations_freq_count[md]:
                        md_free=False
                        break
            # print("Testing for free:",unsafe_operation)
            if md_free:
                # num_free_unsafe_operations=num_free_unsafe_operations+1
                free_unsafe_operations.add(unsafe_operation)
                # print("FREE:",unsafe_operation)

    for unsafe_op in all_unsafe_operations:
        if unsafe_op not in unsafe_operation_to_cost:

            # ASAN Check freq (cost)
            with driver.session() as session:
                result = session.run(
                "MATCH (mp:AttackGraphNode) WHERE  mp.id=$node_id  RETURN mp.count_ref as count", node_id=unsafe_op,name=name)
                
                for record in result:
                    freq = int(record["count"])
                    unsafe_operation_to_cost[unsafe_op]=(freq*program_asan_check_cost_estimate)

            # if ANALYZE_OPTISAN_PLACEMENT_ONLY:
            #     # Baggy Checks Freq
            #     with driver.session() as session:
            #         result = session.run(
            #             "MATCH (mp:AttackGraphNode)-[:EDGE]->(unsafeOp:AttackGraphNode) WHERE unsafeOp.id=$node_id  RETURN  mp.count_ref as count", node_id=unsafe_op,name=name)

            #         for record in result:
            #             freq = int(record["count"])
            #             unsafe_operation_to_cost[unsafe_op]=min( unsafe_operation_to_cost[unsafe_op],(freq*baggy_check_cost))



    return 


def analyze_frequency_for_both(name=None):
    if not name:
        name=program_name
    global free_unsafe_operations
    # read_frequency_and_estimate_costs(name)
    upa_to_asan_mp = dict()
    upa_to_baggy_mp = dict()
    frequency_dict = {}
    asan_freqs = []
    baggy_freqs = []
    unsafe_op_to_targets={}
    num_unsafe_ops_where_asan_is_more_expensive=0
    num_unsafe_ops_where_baggy_is_more_expensive=0
    avg_diff_magnitude_asan=0
    avg_diff_magnitude_baggy=0
    should_fix=False


    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND (target.state_type=$target_obj OR target.state_type=$target_ptr) RETURN DISTINCT node.id as id ",
            program_name=name, target_obj=IMPACTED_STACK_OBJECT,target_ptr=IMPACTED_STACK_POINTER)

        for record in result:
            node_id = str(record["id"])
            if node_id not in unsafe_op_to_targets:
                unsafe_op_to_targets[node_id] = set()

    print("# unsafe ops found:",len(unsafe_op_to_targets))
    num_unsafe_ops_where_asan_is_more_expensive=0
    for unsafe_op in unsafe_op_to_targets:
        upa_to_asan_mp[unsafe_op] = set()
        upa_to_baggy_mp[unsafe_op] = set()
        asan_freq = 0
        baggy_freq = 0
        num_baggy_mps=0
        num_asan_mps=0
        same_func=False
        # BAGGY AND EXISTS(mp.monitor)
        with driver.session() as session:
            result = session.run(
                "MATCH (p:ProgramInstruction)<-[:EDGE]-(mp:MP)-[:EDGE]->(upa:AttackGraphNode) WHERE  upa.id=$upa_id  RETURN DISTINCT mp.id as id, mp.count_ref as count,p.instruction as inst, p.function_name as func", upa_id=unsafe_op
            )

            for record in result:
                baggy_mp_id = str(record["id"])
                freq = int(record["count"])
                baggy_func=str(record["func"])
                frequency_dict[baggy_mp_id] = freq
                upa_to_baggy_mp[unsafe_op].add(baggy_mp_id)
                baggy_freq = baggy_freq+freq
                num_baggy_mps=num_baggy_mps+1
                baggy_inst_string=str(record["inst"])
        # ASAN
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


        if asan_freq!=baggy_freq and num_baggy_mps==1 and asan_func==baggy_func:
            if baggy_freq>asan_freq:
                print("\t Fix ",asan_freq,"==",baggy_freq," func:",asan_func)
                print("\t Baggy inst:",baggy_inst_string)
                print("\t ASAN inst:",asan_inst_string)
            actual_count=asan_freq
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
        elif baggy_freq>asan_freq:
            # print("\t Baggy MPs:",num_baggy_mps," ASAN MPs:",num_asan_mps)
        
            num_unsafe_ops_where_baggy_is_more_expensive=num_unsafe_ops_where_baggy_is_more_expensive+1
            avg_diff_magnitude_baggy=avg_diff_magnitude_baggy+(baggy_freq-asan_freq)
        
        asan_freqs.append(asan_freq)
        baggy_freqs.append(baggy_freq)
        # print("\n")
        
    # num_baggy_covers_more=read_monitoring_points_info(name)

    num_non_free=(len(unsafe_op_to_targets)-len(free_unsafe_operations))
    print("ASAN MP Freq:", np.mean(asan_freqs))
    print("Baggy MP Freq:", np.mean(baggy_freqs))
    print("# non free",num_non_free)
    print("# Cases where ASAN is more expensive:",num_unsafe_ops_where_asan_is_more_expensive,num_unsafe_ops_where_asan_is_more_expensive/num_non_free)
    # print("# Cases where Baggy is more expensive:",num_unsafe_ops_where_baggy_is_more_expensive,avg_diff_magnitude_baggy)
    # if should_fix:
    #     generate_coverage_file(name)
    exit(1)

def find_unsafe_operations_gain_distribution(name):
    global profit_per_unsafe_operation
    global unsafe_op_to_targets
    global targets_to_unsafe_op
    local_profit_per_unsafe={}
    reachable_targets = set()
    print("Analyzing profit/gain (usable targets) of unsafe operations")
    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND node.type=$action_type RETURN node.id as id,target.id as target ORDER BY node.id",
            program_name=name, action_type="AttackAction")

        for record in result:
            node_id = str(record["id"])
            if (not ANALYZE_OPTISAN_PLACEMENT_ONLY) or node_id in all_unsafe_operations:
                if node_id not in unsafe_op_to_targets:
                    unsafe_op_to_targets[node_id] = set()
                target_id = str(record["target"])
                reachable_targets.add(target_id)
                unsafe_op_to_targets[node_id].add(target_id)
                if target_id not in targets_to_unsafe_op:
                    targets_to_unsafe_op[target_id] = set()
                targets_to_unsafe_op[target_id].add(node_id)


    for unsafe_op in unsafe_op_to_targets:
        profit=0
        for target in unsafe_op_to_targets[unsafe_op]:
            profit = profit+(1/len(targets_to_unsafe_op[target]))
        profit_per_unsafe_operation[unsafe_op]=profit
        local_profit_per_unsafe[unsafe_op]=len(unsafe_op_to_targets[unsafe_op])
        # print("\t Profit:",profit)
        # print("\t Freq:",asan_freq)
  

    if not ANALYZE_OPTISAN_PLACEMENT_ONLY:
        profit_values=list(profit_per_unsafe_operation.values())
        print("Total prof:",sum(profit_values))
        print("Profit/potential security impact/importance variance:",np.var(profit_values))
        all_profit_values=profit_values
        sorted_profit=sorted(all_profit_values,reverse=True)
        total_profit_sum=sum(all_profit_values)
        current_sum=0
        for pos in range(len(all_profit_values)-1,0,-1):
            current_sum=current_sum+sorted_profit[pos]
            if current_sum>=(0.80*total_profit_sum):
                break
        print("# Total sum:",total_profit_sum,current_sum)
        print("High impact ",round((len(all_profit_values)-pos)*100/(len(all_profit_values)),2)," \%\ unsafe operations account for 80\%")
        exit(1)
    return local_profit_per_unsafe



def read_frequency_and_estimate_costs_for_unsafe_ops(name,high_impact_unsafe_ops):

    global program_asan_check_cost_estimate 
    global program_asan_md_cost_estimate
    global unsafe_op_to_md
    global func_to_objs
    global objs_to_func
    program_asan_check_cost_estimate=get_cost_estimates(name,MonitorOperations.Checks,MonitorType.ASAN)
    program_asan_md_cost_estimate=get_cost_estimates(name,MonitorOperations.Metadata,MonitorType.ASAN)

    check_costs=0
    unsafe_op_to_check_cost={}
    with driver.session() as session:
   
        
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name AND node.type=$action_type RETURN node.id as id,node.count_ref as cnt ORDER BY node.id",
            program_name=name, action_type="AttackAction")

        for record in result:
            node_id = str(record["id"])
            if node_id in high_impact_unsafe_ops:
                unsafe_op_to_check_cost[node_id]=0
                if record["cnt"]:
                    check_freq=int(record["cnt"])
                else:
                    check_freq=0    
                op_check_cost=program_asan_check_cost_estimate*check_freq
                unsafe_op_to_check_cost[node_id]=op_check_cost
                check_costs=check_costs+op_check_cost  


    # Mapping  all unsafe operations to md
    all_relevant_md_objs=set()
    for unsafe_op in high_impact_unsafe_ops:
        with driver.session() as session:
            result = session.run(
                "MATCH (obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(mp:MP) WHERE  mp.id=$unsafe_op_id  RETURN DISTINCT obj.id as objID", unsafe_op_id=unsafe_op)

            for record in result:
                obj_id= str(record["objID"])
                if unsafe_op not in unsafe_op_to_md:
                    unsafe_op_to_md[unsafe_op]=set()
                unsafe_op_to_md[unsafe_op].add(obj_id)
                all_relevant_md_objs.add(obj_id)

    # # MD Costs
    md_functions_seen=set()

    md_cost=0
    with driver.session() as session:
        result = session.run(
            "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode) WHERE  obj.state_type=$object_type AND obj.program_name=$name  RETURN DISTINCT obj.id as objID, p.function_name as function", object_type=UNSAFE_STACK_OBJECT,name=name)

        function_name=None
        for record in result:
            obj_id= str(record["objID"])
            function_name=str(record["function"])
            if obj_id in all_relevant_md_objs:
                if function_name not in func_to_objs:
                    func_to_objs[function_name]=set()
                func_to_objs[function_name].add(obj_id)
                objs_to_func[obj_id]=function_name
                if function_name not in md_functions_seen:
                    md_functions_seen.add(function_name)
                    if function_name not in func_freq_cache:
                        result = session.run(
                                "MATCH (p:Entry) WHERE "
                                "p.program_name=$program_name AND p.function_name=$function_name  RETURN  p.count_ref as freq",
                                program_name=program_name, function_name=function_name, entry=ENTRY_NODE)
                        for record in result:
                            freq=0
                            if record["freq"]:
                                freq = int(record["freq"])
                            func_freq_cache[function_name]=freq

                    md_cost=md_cost+(func_freq_cache[function_name]*program_asan_md_cost_estimate)



    unsafe_to_total_cost={}
    obj_ids_seen=set()
    sorted_costs=list(unsafe_to_total_cost.values())

    for unsafe_op in unsafe_op_to_check_cost:
        unsafe_to_total_cost[unsafe_op]=unsafe_op_to_check_cost[unsafe_op]
        unsafe_op_md_cost=0
        for obj_id in unsafe_op_to_md[unsafe_op]:
            if obj_id not in obj_ids_seen:
                obj_ids_seen.add(obj_id)
                curr_func_name=objs_to_func[obj_id]
                unsafe_op_md_cost=unsafe_op_md_cost+(func_freq_cache[curr_func_name]*program_asan_md_cost_estimate/len(func_to_objs[curr_func_name]))
        if not unsafe_op_md_cost:
            print("unsafe op:",unsafe_op,":",unsafe_op_md_cost)
        unsafe_to_total_cost[unsafe_op]=unsafe_to_total_cost[unsafe_op]+unsafe_op_md_cost

    print("# unsafe operations given:",len(high_impact_unsafe_ops),"==",len(unsafe_op_to_check_cost))
    print("# corresponding MD Objects:",len(all_relevant_md_objs))
    print("# corresponding MD functions:",len(md_functions_seen))


    print("Check cost(s):",check_costs,"==",sum(list(unsafe_op_to_check_cost.values())))
    print("MD cost(s):",md_cost)
    total_cost=check_costs+md_cost
    sorted_costs=list(unsafe_to_total_cost.values())
    print("Total cost(s):",total_cost,"==",sum(sorted_costs))
    sorted_costs=sorted(sorted_costs,reverse=True)
    current_cost=0
    total_hottest_cost=0
    num_high_cost_unsafe_ops=0
    for pos in range(0,len(sorted_costs)):
        current_cost=sorted_costs[pos]
        if current_cost>=(0.40*total_cost):
            print(current_cost,">",0.40*total_cost)
            num_high_cost_unsafe_ops=num_high_cost_unsafe_ops+1
        if pos<=3:
            total_hottest_cost=total_hottest_cost+current_cost
            print(current_cost)
    print("# High  cost cases:",num_high_cost_unsafe_ops,total_hottest_cost/total_cost)




    return 


def find_unsafe_operations_usable_targets_distribution(name):

    targets_per_unsafe_op={}
    print("Analyzing impact (usable targets) distribution of unsafe operations")
    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND (target.state_type=$target_obj OR target.state_type=$target_ptr) RETURN node.id as id, COUNT(DISTINCT target.id) as cnt ORDER BY node.id",
            program_name=name, target_obj=IMPACTED_STACK_OBJECT,target_ptr=IMPACTED_STACK_POINTER)

        for record in result:
            node_id = str(record["id"])
            target_cnt = int(record["cnt"])
            targets_per_unsafe_op[node_id] = target_cnt
    
    num_unsafe_operations=0
    num_all_targets=0
    with driver.session() as session:
        result = session.run(
            "MATCH (target:AttackGraphNode) WHERE  target.program_name=$program_name AND (target.state_type=$target_obj OR target.state_type=$target_ptr) AND (target)<-[:EDGE]-(:AttackGraphNode) RETURN   COUNT(DISTINCT target.id) as cnt ",
            program_name=name, target_obj=IMPACTED_STACK_OBJECT,target_ptr=IMPACTED_STACK_POINTER)

        for record in result:
            num_all_targets = int(record["cnt"])
           

    print("# All targets :",num_all_targets)
    unsafe_op_ids=list(targets_per_unsafe_op.keys())
    reachable_targets_values=list(targets_per_unsafe_op.values())
    print("Usable targets reachable from unsafe ops variance:",np.var(reachable_targets_values))


    sorted_reachable_target_values=sorted(reachable_targets_values,reverse=True)

    current_targets_reached=0
    high_impact_unsafe_ops=[]
    num_high_impact_unsafe_ops=0
    for pos in range(0,len(sorted_reachable_target_values)):
        current_targets_reached=sorted_reachable_target_values[pos]
        if current_targets_reached>=(0.70*num_all_targets):
            unsafe_op_id=unsafe_op_ids[reachable_targets_values.index(sorted_reachable_target_values[pos])]
            high_impact_unsafe_ops.append(unsafe_op_id)
            # print(unsafe_op_id,":",sorted_reachable_target_values[pos])
            num_high_impact_unsafe_ops=num_high_impact_unsafe_ops+1
            
    print("# Total targets:",num_all_targets,current_targets_reached)
    print("# high impact unsafe operations, unsafe operations",num_high_impact_unsafe_ops,len(targets_per_unsafe_op))
    print("High target reach ",round((num_high_impact_unsafe_ops)*100/(len(reachable_targets_values)),2)," \%\ unsafe operations can affect  70\%\ usable targets")
    read_frequency_and_estimate_costs_for_unsafe_ops(name,high_impact_unsafe_ops)
    exit(0)


def get_candea_placement(budget):
    global all_unsafe_operations
    global targets_to_unsafe_op
    global unsafe_operations_freq_count
    global unsafe_operation_total_operations_freq_count
    global profit_per_unsafe_operation
    global free_unsafe_operations
    global program_name
    global program_asan_check_cost_estimate, program_asan_md_cost_estimate
    global candea_op_covered
    global func_to_objs
    global objs_to_func

    unsafe_operations_sorted = list(all_unsafe_operations)

    unsafe_operations_sorted = sorted(
        unsafe_operations_sorted, key=lambda x: unsafe_operation_total_operations_freq_count[x])
  
    # Open up the aggregated gain (aggreation wrt unsafe operations. aggreation wrt uses later)
    num_unsafe_ops_wout_uses_covered =0
    current_total_cost = 0
    total_md_cost=0
    num_candea_ops_covered = 0
    candea_objective_value = 0
    unsafe_operations_covered=set()    
    md_operations_covered=set()
    md_functions_seen=set()


    for unsafe_operation in unsafe_operations_sorted:
        freq = unsafe_operations_freq_count[unsafe_operation]
        current_total_cost = current_total_cost + (freq * program_asan_check_cost_estimate)
        new_md_operation_costs=0
        accrues_md_cost=False
        # print(unsafe_operation,len(unsafe_op_to_md[unsafe_operation]))
        for md in unsafe_op_to_md[unsafe_operation]:
            curr_md_function=objs_to_func[md]
            if md not in md_operations_covered  :
                if curr_md_function not in md_functions_seen:
                    md_functions_seen.add(curr_md_function)
                    current_md_operation_cost=(md_operations_freq_count[md] * program_asan_md_cost_estimate)
                    # current_md_operation_cost=current_md_operation_cost/(func_to_objs[objs_to_func[md]])
                    new_md_operation_costs+=current_md_operation_cost
                    md_operations_covered.add(md)
                    accrues_md_cost=True

        if accrues_md_cost:
            total_md_cost = total_md_cost + new_md_operation_costs
            current_total_cost=current_total_cost+new_md_operation_costs
        # print(" MD Cost:",total_md_cost,len(md_operations_covered))
        if (unsafe_operation not in free_unsafe_operations) and current_total_cost>=budget:
            current_total_cost=current_total_cost-(freq * program_asan_check_cost_estimate)
            print("\t Backtracked check cost",freq * program_asan_check_cost_estimate)
            if accrues_md_cost:
                print("\t Backtracked MD cost",new_md_operation_costs)
                current_total_cost-=new_md_operation_costs
                total_md_cost = total_md_cost - new_md_operation_costs
            break
        if not profit_per_unsafe_operation[unsafe_operation]:
            # if freq:
            num_unsafe_ops_wout_uses_covered=num_unsafe_ops_wout_uses_covered+1

                # print("\t Unsafe op:", unsafe_operation)
                # print("\t Freq:", freq)
                # print("\t Profit:", profit_per_unsafe_operation[unsafe_operation])
     
        unsafe_operations_covered.add(unsafe_operation)
        candea_op_covered.add(unsafe_operation)
        if unsafe_operation not in free_unsafe_operations:
            num_candea_ops_covered = num_candea_ops_covered+1



    # print("\t # Num of unsafe ops  without uses covered:",num_unsafe_ops_wout_uses_covered)
    for unsafe_operation in unsafe_operations_covered:
        candea_objective_value = candea_objective_value + (profit_per_unsafe_operation[unsafe_operation]*ASAN_ACCURACY)
        # print(unsafe_operation,profit_per_unsafe_operation[unsafe_operation])
        

    # for target_id in targets_to_unsafe_op:
    #     target_val=0
    #     for unsafe_operation in targets_to_unsafe_op[target_id]:
    #         if unsafe_operation in unsafe_operations_covered:
    #             target_val=target_val+1
    #     candea_objective_value = candea_objective_value + (target_val/len(targets_to_unsafe_op[target_id]))


    print("\t # Targets protected:",candea_objective_value,candea_objective_value)
    print("\t # OPs covered:",num_candea_ops_covered)
    print("\t MD Cost(s):",total_md_cost)
    print("\t Check Cost(s):",current_total_cost-total_md_cost)
    # print("\t # Num of non free unsafe ops  without uses covered:",num_unsafe_ops_wout_uses_covered)
    print("\t Budget used and budget given:",current_total_cost,budget)
    print("\n\n")
    # print("\t Budget used and budget given:",current_cost,budget)

    return candea_objective_value, num_candea_ops_covered


def get_computed_placement():

    global profit_per_unsafe_operation
    global all_unsafe_operations
    global optisan_asan_op_covered
    global unsafe_operation_to_cost
    global budget 

    profit=0
    covered_ops=set()
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name  AND node.monitor=$ASAN   RETURN node.id as ID ORDER BY node.id",
            program_name=program_name,ASAN="ASAN")

        for record in result:
            node_id=str(record["ID"])
            optisan_asan_op_covered.add(node_id)
            if node_id in profit_per_unsafe_operation:
                profit=profit+(profit_per_unsafe_operation[node_id]*0.90)
                
    if ANALYZE_OPTISAN_PLACEMENT_ONLY:
        with driver.session() as session:
            result = session.run(
                "MATCH (node:MP)-[:EDGE]->(unsafeOp:AttackGraphNode) WHERE  node.program_name=$program_name  AND node.monitor=$BBC   RETURN DISTINCT(unsafeOp.id) as ID ORDER BY unsafeOp.id",
                program_name=program_name,BBC="BBC")

            for record in result:
                node_id=str(record["ID"])
                optisan_baggy_op_covered.add(node_id)
                if node_id in profit_per_unsafe_operation :
                    profit=profit+(profit_per_unsafe_operation[node_id])            
 
    #3%
    budget=0.0709*exec_times_ref[program_name]

    print("Optisan placement objective value:",profit)
    print("# Free unsafe operations:",len(free_unsafe_operations))
    print("Unsafe op asan-",len(optisan_asan_op_covered),". Unsafe op baggy-",len(optisan_baggy_op_covered))
    print("Placement budget:",budget)
    get_candea_placement(budget)

 



def read_monitoring_points_info(name):
    unsafe_operations=set()
    unsafe_op_to_baggy_mps={}
    # Fetch unsafe operations
    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type) RETURN node.id as id ORDER BY node.id",
            program_name=name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            node_id = str(record["id"])
            unsafe_operations.add(node_id)
    # Fetch Baggy MPs where one mp (or more) covers more than one unsafe operation
    num_ops_where_baggy_cheaper=0
    with driver.session() as session:
        result = session.run(
            "MATCH (mp:MP)-[:EDGE]->(node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN mp.id as mpID,COUNT(DISTINCT node) as count ORDER BY mp.id",
            program_name=name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            mp_id = str(record["mpID"])
            num_ops=int(record["count"])
            if num_ops > 1:
                num_ops_where_baggy_cheaper=num_ops_where_baggy_cheaper+1

    print("\%\ baggy cheaper:",(num_ops_where_baggy_cheaper/len(unsafe_operations)*100))

    return num_ops_where_baggy_cheaper


def plot_targets_fully_protected():
    budgets=[25,50,75]
    targets_full_dict={}
    targets_full_dict["458.sjeng"]=[26.86,64.09,78.91]
    targets_full_dict["400.perlbench"]=[98.13,98.15,99.62]
    targets_full_dict["625.x264_s"]=[82.28,82.28,87.23]
    targets_full_dict["511.povray_r"]=[6.71,15.48,18.33]
    targets_full_dict["httpd"]=[52.54,52.72,100]
    targets_full_dict["xmllint"]=[31.90,32.02,100]
    targets_full_data_frame=pd.DataFrame()
    targets_full_data_frame['Cost (%)']=budgets
    for nam in targets_full_dict:
        targets_full_data_frame[nam]=targets_full_dict[nam] 

    sb.lineplot(data=pd.melt(targets_full_data_frame,['Cost (%)']),x='Cost (%)',y='value',hue="variable",dashes=True,legend='brief')
    plt.legend(markerscale=2)
    plt.grid(True, linestyle='-')
    plt.xticks(budgets)
    plt.ylabel("Targets Full(%)",fontsize="16")
    plt.xlabel("Full Protection Budget (%)",fontsize="16")
    plt.savefig('targets_full_plot.pdf', dpi=400)
    plt.close()
    exit(0)
    return 
    


if __name__ == "__main__":
    driver = get_db_driver()
    program_name = str(sys.argv[1])
    analyze_frequency_for_both(program_name)
    # plot_targets_fully_protected()
    sb.set(style="white")

    # frequency_data_frame=pd.DataFrame()
    #https://www.kaggle.com/code/alexisbcook/scaling-and-normalization


    # scaler = preprocessing.MaxAbsScaler()

    # scaler = preprocessing.RobustScaler(with_centering=False)

    # scaler = preprocessing.MinMaxScaler()

    scaler = preprocessing.MinMaxScaler(feature_range=(1,10))
    # scaler = preprocessing.StandardScaler()

    all_frequency_dists={}
    cost_values_list=[]
    unsafe_op_list =[]
    frequency_data_frame=pd.DataFrame()
    profit_dist_dict={}

    # Take current budget sjeng 6%

    for name in [program_name]:

        print("Analyzing program: ",name)
        program_name=name
        analyze_frequency_for_both(program_name)
    
        cost_values_list.clear()
        unsafe_op_list.clear()
        profit_per_unsafe_operation.clear()
        unsafe_operations_freq_count.clear()
        all_unsafe_operations.clear()
        candea_op_covered.clear()
        optisan_asan_op_covered.clear()
   

        # print("FREQ FOUND FOR:",len(global_asan_freq_dist))

        read_frequency_and_estimate_costs(name)
        profit_dist_dict=find_unsafe_operations_gain_distribution(name)

        for unsafe_operation in free_unsafe_operations:
            free_protection=free_protection+profit_per_unsafe_operation[unsafe_operation]
        print("# Free unsafe operations:",len(free_unsafe_operations))

        print("# Free protection:",free_protection)
        if ANALYZE_OPTISAN_PLACEMENT_ONLY:
            get_computed_placement()
        category="Status"
        unsafe_op_category=[]
        palette={}
        markers={}

        # 4 status - both, optisan only, asap and neither
        print("Profit dict:",len(profit_dist_dict),"== Unsafe op cost dict",len(unsafe_operation_to_cost))

        if ANALYZE_OPTISAN_PLACEMENT_ONLY:
            # for unsafe_op in profit_dist_dict:
            #     if unsafe_op in free_unsafe_operations:
            #         continue
            #     cost_values_list.append(unsafe_operation_to_cost[unsafe_op])
            #     unsafe_op_list.append(profit_dist_dict[unsafe_op])
            #     if unsafe_op in optisan_baggy_op_covered:
            #         unsafe_op_category.append("Baggy")
            #         palette["Baggy"]='skyblue'
            #         markers["Baggy"]="X"
            #     elif unsafe_op in optisan_asan_op_covered:
            #         unsafe_op_category.append("ASan")
            #         palette["ASan"]='darkgreen'
            #         markers["ASan"]="o"
            #     else:
            #         unsafe_op_category.append("Unprotected")
            #         palette["Unprotected"]='maroon'
            #         markers["Unprotected"]="."
            # frequency_data_frame[category]=unsafe_op_category

            # frequency_data_frame["alpha"]=np.where(frequency_data_frame[category]=="Unprotected",0.3,1.0)

            for unsafe_op in all_unsafe_operations:
                if unsafe_op in free_unsafe_operations:
                    continue
                cost_values_list.append(unsafe_operation_to_cost[unsafe_op])
                unsafe_op_list.append(profit_dist_dict[unsafe_op])
                if unsafe_op in optisan_asan_op_covered and unsafe_op in candea_op_covered:
                    unsafe_op_category.append("BOTH")
                    palette["BOTH"]='skyblue'
                    markers["BOTH"]="o"
                elif unsafe_op in optisan_asan_op_covered:
                    unsafe_op_category.append("OptiSan")
                    palette["OptiSan"]='darkgreen'
                    markers["OptiSan"]="X"
                elif unsafe_op in candea_op_covered:
                    unsafe_op_category.append("ASAP")
                    palette["ASAP"]='darkorange'
                    markers["ASAP"]="*"
                else:
                    unsafe_op_category.append("Unprotected")
                    palette["Unprotected"]='maroon'
                    markers["Unprotected"]="."
            frequency_data_frame[category]=unsafe_op_category
            frequency_data_frame["alpha"]=np.where(frequency_data_frame[category]=="OptiSan",1.0,0.3)
            
        elif ANALYZE_FREQUENCY_ONLY:

            # frequency_data_frame["Frequency"]=list(unsafe_operation_total_operations_freq_count.values())
            raw_freq_values=list(unsafe_operation_total_operations_freq_count.values())
                    
            # Convert to log scale
            num_free=len(raw_freq_values)
            raw_freq_values=[x for x in raw_freq_values if x  ]
            num_free=num_free-len(raw_freq_values)
            # print(len(raw_freq_values))
            frequency_values_np=np.array(raw_freq_values)
            frequency_values_np=np.squeeze(frequency_values_np)    
            # print("PRE LOG MEAN, MEDIAN:",frequency_values_np.shape,np.mean(frequency_values_np),np.median(frequency_values_np))
       
            # print(np.mean(raw_freq_values))
            # frequency_values_np=np.log10(frequency_values_np)
            # Add free unsafe operations back          
            # frequency_values_np=np.append(frequency_values_np,[0 for _ in range(num_free)])
            # frequency_values_np=np.array([math.log10(x) for x in raw_freq_values])
            frequency_values_np=np.squeeze(frequency_values_np) 
            # print("POST LOG MEAN, MEDIAN:",frequency_values_np.shape,np.mean(frequency_values_np),np.median(frequency_values_np))
          
            frequency_values_np=frequency_values_np.reshape(-1,1)
            # frequency_values_np=scaler.fit_transform(frequency_values_np)
            frequency_data_frame["Frequency"]=frequency_values_np.squeeze()

        
            # print(frequency_data_frame.describe())

            # ax= sb.kdeplot(data=frequency_data_frame,x='Frequency',color='crimson',fill=False)
            g = sb.displot(data=frequency_data_frame,x='Frequency',color='crimson',kde=True,log_scale=True)

            # def specs(x, **kwargs):
            #     plt.axvline(x.mean(), c='blue', ls=':', lw=2.5)
            #     plt.axvline(x.median(), c='orange', ls='--', lw=2.5)

            # g.map(specs,'Frequency' )
            mean=(np.mean(raw_freq_values))
            # mean=math.log10(np.mean(raw_freq_values))

            plt.axvline(mean, c='blue', ls=':', lw=2.5)
            plt.text(mean-1000000,-15,'Mean',rotation=35)
            median=(np.median(raw_freq_values))
            # median=math.log10(np.median(raw_freq_values))

            plt.axvline(median, c='orange', ls='--', lw=2.5)
            plt.text(median-1000,-15,'Median',rotation=35)
            g.set_axis_labels("Defense operations frequency (Logarithmic scale)", "Count of non free unsafe operations (#)")
            # ax = g.axes[0]

            # ax.set_xscale('log')

            # mean = np.mean(frequency_values_np)
            # median=np.median(frequency_values_np)
            # kdeline=ax.lines[0]
            # xs = kdeline.get_xdata()
            # ys = kdeline.get_ydata()
            # height = np.interp(mean, xs, ys)
            # ax.vlines(mean, 0, height, color='crimson', ls=':')
            # ax.vlines(median, 0, height, color='crimson', ls='-')
            # plt.xscale("log")
            # # plt.legend(markerscale=2)
            plt.savefig(name+'_freq_plot.pdf', dpi=400)
            plt.close()
            exit(0)


        elif profit_dist_dict:
            for unsafe_op in profit_dist_dict:
                if unsafe_op in free_unsafe_operations:
                    continue
                cost_values_list.append(unsafe_operation_to_cost[unsafe_op])
                unsafe_op_list.append(profit_dist_dict[unsafe_op])
                # if unsafe_op in optisan_asan_op_covered and unsafe_op in candea_op_covered:
                #     unsafe_op_category.append("BOTH")
                #     palette["BOTH"]='skyblue'
                #     markers["BOTH"]="o"
                # elif unsafe_op in optisan_asan_op_covered:
                #     unsafe_op_category.append("OptiSan")
                #     palette["OptiSan"]='darkgreen'
                #     markers["OptiSan"]="X"
                # elif unsafe_op in candea_op_covered:
                #     unsafe_op_category.append("ASAP")
                #     palette["ASAP"]='darkorange'
                #     markers["ASAP"]="*"
                # else:
                #     unsafe_op_category.append("Unprotected")
                #     palette["Unprotected"]='maroon'
                #     markers["Unprotected"]="."
            frequency_data_frame[category]=unsafe_op_category
            frequency_data_frame["alpha"]=np.where(frequency_data_frame[category]=="OptiSan",1.0,0.3)


        else:
            for unsafe_op in unsafe_operation_total_operations_freq_count:
                if unsafe_op in free_unsafe_operations:
                    continue
                cost_values_list.append(unsafe_operation_to_cost[unsafe_op])
                unsafe_op_list.append(profit_dist_dict[unsafe_op])
                if unsafe_op in optisan_asan_op_covered and unsafe_op in candea_op_covered:
                    unsafe_op_category.append("BOTH")
                    palette["BOTH"]='skyblue'
                    markers["BOTH"]="o"
                elif unsafe_op in optisan_asan_op_covered:
                    unsafe_op_category.append("OptiSan")
                    palette["OptiSan"]='darkgreen'
                    markers["OptiSan"]="X"
                elif unsafe_op in candea_op_covered:
                    unsafe_op_category.append("ASAP")
                    palette["ASAP"]='darkorange'
                    markers["ASAP"]="*"
                else:
                    unsafe_op_category.append("Unprotected")
                    palette["Unprotected"]='maroon'
                    markers["Unprotected"]="."
        
            frequency_data_frame[category]=unsafe_op_category
            frequency_data_frame["alpha"]=np.where(frequency_data_frame[category]=="OptiSan",1.0,0.3)
            

        frequency_data_frame['Cost']=cost_values_list
        frequency_data_frame['Usable Targets']=unsafe_op_list 

        # frequency_data_frame['Free']=unsafe_op_list 

        print(len(cost_values_list),"==",len(unsafe_op_list))
        frequency_data_frame[['Cost','Usable Targets']]=scaler.fit_transform(frequency_data_frame[['Cost','Usable Targets']])
        print(frequency_data_frame.describe())

        # frequency_values_np=np.array(frequency_values_list)

        # frequency_values_np=frequency_values_np.reshape(-1,1)
        # frequency_values_np=scaler.fit_transform(frequency_values_np)
        # # frequency_values_list=preprocessing.normalize(frequency_values_list)
        # print(np.var(frequency_values_np))
  
        # unsafe_op_np=np.array(unsafe_op_list)
        # unsafe_op_np=unsafe_op_np.reshape(-1,1)
        # unsafe_op_np=scaler.fit_transform(unsafe_op_np)
        # data={'freq': frequency_values_np.squeeze(), 'importance': unsafe_op_np.squeeze()}
        # print(np.var(frequency_values_np))

        ax = sb.scatterplot(data=frequency_data_frame[frequency_data_frame.alpha == 0.3],x='Cost',y='Usable Targets',style=category,hue=category,s=160,legend='full',markers=markers,palette=palette,alpha=0.4)

        sb.scatterplot(data=frequency_data_frame[frequency_data_frame.Status ==  "OptiSan"],x='Cost',y='Usable Targets',style=category,hue=category,s=160,legend='full',markers=markers,palette=palette,alpha=1,ax=ax)
        
        # sb.scatterplot(data=frequency_data_frame[frequency_data_frame.alpha == 0.3],x='Cost',y='Usable Targets',style=category,hue=category,s=120,legend='full',markers=markers,palette=palette,alpha=0.3,ax=ax)

        
        # ax2=sb.scatterplot(data=frequency_data_frame[frequency_data_frame.Status ==  "ASAP"],x='Cost',y='Usable Targets',style=category,hue=category,s=120,legend='full',markers=markers,palette=palette,alpha=1,ax=ax)

        # ax3=sb.scatterplot(data=frequency_data_frame[frequency_data_frame.Status ==  "Unprotected"],x='Cost',y='Usable Targets',style=category,hue=category,s=120,legend='full',markers=markers,palette=palette,alpha=0.3,ax=ax2)
        # ax3=sb.scatterplot(data=frequency_data_frame[frequency_data_frame.Status ==  "BOTH"],x='Cost',y='Usable Targets',style=category,hue=category,s=120,legend='full',markers=markers,palette=palette,alpha=0.3,ax=ax3)



        # sb.scatterplot(data=frequency_data_frame,x='Cost',y='Usable Targets',style=category,hue=category,s=120,legend='full',markers=markers,palette=palette,alpha=frequency_data_frame["alpha"])



        # sb.scatterplot(data=frequency_data_frame,x='Cost',y='Usable Targets',hue="Cost", size="Usable Targets",style=category, sizes=(100, 200),palette=sb.color_palette("flare", as_cmap=True),legend=False,markers=markers)

        # sb.scatterplot(data=frequency_data_frame,x='Cost',y='Usable Targets',hue="Cost", size="Usable Targets", sizes=(100, 200),palette=sb.color_palette("flare", as_cmap=True),legend='brief')

        # plt.legend(labels=[category])
     

        plt.legend(loc='upper right',markerscale=1)
        # plt.grid(True)
        plt.ylabel("Usable Targets",fontsize="16")
        plt.xlabel("Check Cost (s)",fontsize="16")
        plt.savefig(name+'_plot.pdf', dpi=400)
        plt.close()
        frequency_data_frame.drop(frequency_data_frame.index,inplace=True)
        #break
        
        
    
    # seaborn_plot=sb.displot(frequency_data_frame,kind="kde")
    # figure = seaborn_plot.get_figure()    
    # plt.savefig('svm_conf.png', dpi=400)






