"""
    Script to compare greedy heuristic (ASAP) for computing defense/sanitizer placement
    For fair comparison Candea will use all the unsafe operations found by Value Range analysis
    Cost can be user specified (seconds) or cost level based (similar to ASAP)
    We assume freq info for all unsafe ops are in DB
"""

from neo4j import GraphDatabase
from enum import Enum
import sys
import numpy as np
import matplotlib.pyplot as plt
import os.path
from monitoring_constants_and_ds import UNSAFE_POINTER_STATE_TYPE,UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, UNSAFE_POINTER_READ_STACK_ACTION_TYPE, UNSAFE_STACK_OBJECT
from monitoring_constants_and_ds import ASAN_ACCURACY,ENTRY_NODE
from monitoring_constants_and_ds import MonitorType, MonitorOperations, get_cost_estimates
from monitoring_constants_and_ds import exec_times_ref

REDZONE_SIZE = 32
ASAP_IGNORE_NO_USE_UPAS = False

USE_USER_SPECIEFIED_BUDGET = True
ITERATIVE_MODE = True
program_name = None

FEASIBILITY_TOL = 5

IGNORE_NUMBER_OF_TARGETS = False
IGNORE_PER_OBJECT_IN_PLOT = True
FAUX_TARGET_LABEL = "faux_target_"

OPTISAN_ASAN_ONLY_PATH = "~/Desktop/SmartMonitor/optisan_asan_only_res"
OPTISAN_BOTH_PATH = "~/Desktop/SmartMonitor/optisan_both_res"
OPTISAN_BAGGY_ONLY_PATH = "~/Desktop/SmartMonitor/optisan_baggy_only_res"
OPTISAN_BOTH_OBJECT_PATH = "~/Desktop/SmartMonitor/optisan_both_res_object"

MULTI_ASAN_ONLY_PATH = "~/Desktop/SmartMonitor/multi_asan_only_res"
MULTI_BOTH_PATH = "~/Desktop/SmartMonitor/multi_both_res"
MULTI_BOTH_OBJECT_PATH = "~/Desktop/SmartMonitor/multi_both_res_object"
MULTI_BAGGY_ONLY_PATH = "~/Desktop/SmartMonitor/multi_baggy_only_res"




# "458.sjeng":64, "458.sjeng":287
# old_free_protection={"445.gobmk":0,"453.povray":433,"400.perlbench":579,"403.gcc":1120}
# old_non_free_targets={"445.gobmk":1978,"453.povray":497,"400.perlbench":943,"403.gcc":2968}

old_free_protection = old_non_free_targets = {}

program_check_cost_estimate = None
program_md_cost_estimate = None


# To simulate Candea need to read monitoring options info and accuracy info - connect that to freq info

all_unsafe_operations = set()
unsafe_op_to_targets = {}
targets_to_unsafe_op = {}
unsafe_operations_freq_count = {}
# Unsafe operation to total freq of all operations needed for the unsafe operation
unsafe_operation_total_operations_freq_count = {}
profit_per_unsafe_operation = {}
num_targets = 0
unsafe_op_to_offset = {}
# MD Operations (See note below)
all_md_points = set()
md_operations_freq_count = {}
unsafe_op_to_md = {}
free_unsafe_operations = set()
num_free_unsafe_operations = 0
free_protection = 0

func_to_objects = {}
objs_to_func = {}


def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(
        uri, auth=("neo4j", "secret"), encrypted=False)
    return driver


def get_offset_for_action(action_id):
    # prev_nodes = set()
    global unsafe_op_to_offset
    if action_id in unsafe_op_to_offset:
        return unsafe_op_to_offset[action_id]
    driver = get_db_driver()

    offset = REDZONE_SIZE+1
    with driver.session() as session:
        # TODO - Remove program name
        results = session.run(
            "MATCH (upa:AttackGraphNode) WHERE upa.id=$id AND  EXISTS(upa.offset) RETURN upa.offset as offset",
            id=action_id)

        for record in results:
            # node_id = str(record["stateID"])
            offset = int(record["offset"])
            if offset == -1:
                offset = REDZONE_SIZE+1
            elif offset < 0:
                offset = abs(offset)
            # prev_nodes.add(node_id)

    # assert len(
    #     prev_nodes) == 1 and "Multiple unsafe ptr states for 1 action: CORRUPT AG"
    unsafe_op_to_offset[action_id] = offset
    return offset


def compute_cost_level_based_budget():
    pass


"""
    Read necessary safety information from db - unsafe operations, targets and frequency
"""


def read_necessary_safety_information():
    global all_unsafe_operations
    global unsafe_op_to_targets
    global targets_to_unsafe_op
    global driver
    global unsafe_operations_freq_count
    global profit_per_unsafe_operation
    global num_targets
    global free_unsafe_operations
    global free_protection
    global num_free_unsafe_operations
    global md_operations_freq_count
    global unsafe_operation_total_operations_freq_count
    global func_to_objects, objs_to_func
    reachable_targets = set()

    # For Candea - all unsafe operations
    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode) WHERE  node.program_name=$program_name AND (node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id as id,node.count_ref as count ORDER BY node.id",
            program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            node_id = str(record["id"])
            all_unsafe_operations.add(node_id)
            if not record["count"]:
                freq = 0
            else:
                freq = int(record["count"])
            # Freq ASAN as unsafe op is MP
            unsafe_operations_freq_count[node_id] = freq
            if node_id not in unsafe_op_to_md:
                unsafe_op_to_md[node_id] = set()

    # Now MD as a monitoring point for all  unsafe operations
    md_to_func = {}

    for unsafe_operation in unsafe_op_to_md:
        with driver.session() as session:
            result = session.run(
                "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(node:AttackGraphNode) WHERE  node.id=$node_id RETURN DISTINCT obj.id as objectID,p.function_name as functionName",
                node_id=unsafe_operation)

            for record in result:
                obj_id = str(record["objectID"])
                function_name = str(record["functionName"])
                md_to_func[obj_id] = function_name
                unsafe_op_to_md[unsafe_operation].add(obj_id)
                all_md_points.add(obj_id)

        for object_id in unsafe_op_to_md[unsafe_operation]:
            if object_id not in md_operations_freq_count:
                function_name = md_to_func[object_id]
                with driver.session() as session:
                    result = session.run(
                        "MATCH (func:Entry) WHERE func.function_name=$function_name AND func.program_name=$program_name RETURN func.count_ref as count",
                        program_name=program_name, function_name=function_name)

                    for record in result:
                        if record["count"]:
                            freq = int(record["count"])
                        else:
                            freq = 0
                        md_operations_freq_count[object_id] = freq

    # Now UPAs with usable targets

    with driver.session() as session:
        if IGNORE_NUMBER_OF_TARGETS:

            result = session.run(
                "MATCH (node:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN DISTINCT node.id as id ORDER BY node.id",
                program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)
            for record in result:
                node_id = str(record["id"])
                if node_id not in unsafe_op_to_targets:
                    unsafe_op_to_targets[node_id] = set()
                    target_id = FAUX_TARGET_LABEL+node_id
                    reachable_targets.add(target_id)
                    unsafe_op_to_targets[node_id].add(target_id)
                    if target_id not in targets_to_unsafe_op:
                        targets_to_unsafe_op[target_id] = set()
                    targets_to_unsafe_op[target_id].add(node_id)
        else:

            result = session.run(
                "MATCH (node:AttackGraphNode)-[:EDGE]->(target:AttackGraphNode) WHERE  node.program_name=$program_name AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id as id,target.id as target ORDER BY node.id",
                program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

            for record in result:
                node_id = str(record["id"])
                if node_id not in unsafe_op_to_targets:
                    unsafe_op_to_targets[node_id] = set()
                target_id = str(record["target"])
                reachable_targets.add(target_id)
                unsafe_op_to_targets[node_id].add(target_id)
                if target_id not in targets_to_unsafe_op:
                    targets_to_unsafe_op[target_id] = set()
                targets_to_unsafe_op[target_id].add(node_id)

    print("# reachable targets", len(reachable_targets))
    # for target in reachable_targets:
    #     if IGNORE_NUMBER_OF_TARGETS:
    #         if target not in targets_to_unsafe_op:
    #             targets_to_unsafe_op[target] = set()
    #         node_id = target[target.index(
    #             FAUX_TARGET_LABEL)+len(FAUX_TARGET_LABEL):]
    #         targets_to_unsafe_op[target].add(node_id)
    #     else:
    #         with driver.session() as session:
    #             result = session.run(
    #                 "MATCH (target:AttackGraphNode)<-[:EDGE]-(node:AttackGraphNode) WHERE  target.id=$target_id AND ( node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN target.id as id,node.id as node ORDER BY target.id",
    #                 target_id=target, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

    #             for record in result:
    #                 target_id = str(record["id"])
    #                 if target_id not in targets_to_unsafe_op:
    #                     targets_to_unsafe_op[target_id] = set()

    #                 node_id = str(record["node"])
    #                 targets_to_unsafe_op[target_id].add(node_id)
    num_targets = len(reachable_targets)
    print("# Total Unsafe operations", len(all_unsafe_operations))
    print("# Total MD points", len(all_md_points))
    print("# Unsafe operations with exploit object uses",
          len(unsafe_op_to_targets))
    print("# UPAs with freq info for candea",
          len(unsafe_operations_freq_count.keys()))
    print("# Targets:", len(targets_to_unsafe_op), num_targets)

    for unsafe_op in all_unsafe_operations:
        profit = 0.0
        if unsafe_op in unsafe_op_to_targets:
            for target in unsafe_op_to_targets[unsafe_op]:
                profit = profit+(1/len(targets_to_unsafe_op[target]))
        profit_per_unsafe_operation[unsafe_op] = profit
    # print(profit_per_unsafe_operation["708f9209-cd8e-4c61-9371-8490d447ed11"])

    for unsafe_operation in unsafe_op_to_targets:
        freq = unsafe_operations_freq_count[unsafe_operation]
        if not freq:
            md_free = True
            for md in unsafe_op_to_md[unsafe_operation]:
                if md_operations_freq_count[md]:
                    md_free = False
                    break
            # print("Testing for free:",unsafe_operation)
            if md_free:
                num_free_unsafe_operations = num_free_unsafe_operations+1
                free_protection = free_protection + \
                    profit_per_unsafe_operation[unsafe_operation]
                free_unsafe_operations.add(unsafe_operation)
                # print("FREE:",unsafe_operation)

    profit_values = list(profit_per_unsafe_operation.values())
    print("Avg max profit per unsafe operation", np.mean(profit_values))
    print("Std max profit per unsafe operation",
          np.std(profit_values))

    for unsafe_operation in unsafe_op_to_md:
        unsafe_operation_total_operations_freq_count[
            unsafe_operation] = unsafe_operations_freq_count[unsafe_operation]
        for md_operation in unsafe_op_to_md[unsafe_operation]:
            unsafe_operation_total_operations_freq_count[
                unsafe_operation] += md_operations_freq_count[md_operation]

    # with driver.session() as session:
    #     result = session.run("MATCH (obj:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE obj.program_name=$program_name AND obj.state_type=$unsafe_object_type RETURN DISTINCT p.function_name as function_name,COUNT(obj) as count",program_name=program_name,unsafe_object_type=UNSAFE_STACK_OBJECT)
    #     for record in result:
    #         function_name=str(record["function_name"])
    #         obj_count=int(record["count"])
    #         func_to_objects[function_name]=obj_count

    # with driver.session() as session:
    #     result = session.run("MATCH (obj:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE obj.program_name=$program_name AND obj.state_type=$unsafe_object_type RETURN DISTINCT p.function_name as function_name,obj.id as objID",program_name=program_name,unsafe_object_type=UNSAFE_STACK_OBJECT)
    #     for record in result:
    #         function_name=str(record["function_name"])
    #         object_id=str(record["objID"])
    #         objs_to_func[object_id]=function_name

    return


def compute_candea_placement(budget):
    global program_md_cost_estimate
    global program_check_cost_estimate
    global all_unsafe_operations
    global targets_to_unsafe_op
    global unsafe_operations_freq_count
    global unsafe_operation_total_operations_freq_count
    global profit_per_unsafe_operation
    global free_unsafe_operations
    global program_name
    global func_to_objects, objs_to_func

    if ASAP_IGNORE_NO_USE_UPAS:
        # print("ASAP IGNORE NO USE set",len(unsafe_op_to_targets.keys()))
        unsafe_operations_sorted = list(unsafe_op_to_targets.keys())
    else:
        unsafe_operations_sorted = list(all_unsafe_operations)

    unsafe_operations_sorted = sorted(
        unsafe_operations_sorted, key=lambda x: unsafe_operation_total_operations_freq_count[x])

    # print("CVE index:",unsafe_operations_sorted.index("5c03a862-9f38-4f7d-bc5f-de50bd756bef"))

    # Open up the aggregated gain (aggreation wrt unsafe operations. aggreation wrt uses later)
    num_unsafe_ops_wout_uses_covered = 0
    current_total_cost = 0
    total_md_cost = 0
    num_candea_ops_covered = 0
    candea_objective_value = 0
    unsafe_operations_covered = set()
    md_operations_covered = set()

    for unsafe_operation in unsafe_operations_sorted:
        freq = unsafe_operations_freq_count[unsafe_operation]
        current_total_cost = current_total_cost + \
            (freq * program_check_cost_estimate)
        new_md_operation_costs = 0
        accrues_md_cost = False
        # print(unsafe_operation,len(unsafe_op_to_md[unsafe_operation]))
        for md in unsafe_op_to_md[unsafe_operation]:
            if md not in md_operations_covered:
                current_md_operation_cost = (
                    md_operations_freq_count[md] * program_md_cost_estimate)
                # current_md_operation_cost=current_md_operation_cost/(func_to_objects[objs_to_func[md]])
                new_md_operation_costs += current_md_operation_cost
                md_operations_covered.add(md)
                accrues_md_cost = True
        if accrues_md_cost:
            total_md_cost = total_md_cost + new_md_operation_costs
            current_total_cost = current_total_cost+new_md_operation_costs
        # print(" MD Cost:",total_md_cost,len(md_operations_covered))
        # print(repr(current_total_cost),"<=",repr(budget))
        if (unsafe_operation not in free_unsafe_operations) and current_total_cost > budget:
            current_total_cost = current_total_cost - \
                (freq * program_check_cost_estimate)
            print("\t Backtracked check cost",
                  freq * program_check_cost_estimate)
            if accrues_md_cost:
                print("\t Backtracked MD cost", new_md_operation_costs)
                current_total_cost -= new_md_operation_costs
                total_md_cost = total_md_cost - new_md_operation_costs
            break
        if not profit_per_unsafe_operation[unsafe_operation]:
            # if freq:
            num_unsafe_ops_wout_uses_covered = num_unsafe_ops_wout_uses_covered+1

            # print("\t Unsafe op:", unsafe_operation)
            # print("\t Freq:", freq)
            # print("\t Profit:", profit_per_unsafe_operation[unsafe_operation])

        unsafe_operations_covered.add(unsafe_operation)
        if unsafe_operation not in free_unsafe_operations:
            num_candea_ops_covered = num_candea_ops_covered+1

    other_cves = ["baa67b0d-eb83-499b-bdc3-435c30194194", "3845c0fb-5ae2-40a4-8298-94a6c4e6f124",
                  "ab8acaea-c19e-4b98-a214-03fe8e2ee407",
                  "e61e3e7e-ad7a-4b30-8063-78160d8c3136",
                  "66454358-3164-4786-b932-3470742ff23f"]

    # print("CVE index:",unsafe_operations_sorted.index("d770d7c6-1599-4674-b569-5bbe732682b3"))

    # print("\t # Num of unsafe ops  without uses covered:",num_unsafe_ops_wout_uses_covered)
    for unsafe_operation in unsafe_operations_covered:
        # if unsafe_operation=="d770d7c6-1599-4674-b569-5bbe732682b3":
        #     print("CVE covered")
        #     exit(1)
        # if unsafe_operation ==other_cves[0]:
        #     print("CVE covered")
        #     exit(1)
        # if IGNORE_NUMBER_OF_TARGETS:
        #     candea_objective_value = candea_objective_value + (ASAN_ACCURACY)
        # else:
        candea_objective_value = candea_objective_value + \
            (profit_per_unsafe_operation[unsafe_operation]*ASAN_ACCURACY)
        # print(unsafe_operation,profit_per_unsafe_operation[unsafe_operation])

    # for target_id in targets_to_unsafe_op:
    #     target_val=0
    #     for unsafe_operation in targets_to_unsafe_op[target_id]:
    #         if unsafe_operation in unsafe_operations_covered:
    #             target_val=target_val+1
    #     candea_objective_value = candea_objective_value + (target_val/len(targets_to_unsafe_op[target_id]))

    print("\t # Targets protected:",
          candea_objective_value, candea_objective_value)
    print("\t # OPs covered (including free):", len(unsafe_operations_covered))
    print("\t # OPs covered:", candea_objective_value)
    print("\t MD Cost(s):", total_md_cost)
    print("\t Check Cost(s):", current_total_cost-total_md_cost)
    # print("\t # Num of non free unsafe ops  without uses covered:",num_unsafe_ops_wout_uses_covered)
    print("\t Budget used and budget given:", current_total_cost, budget)
    print("\n\n")
    # print("\t Budget used and budget given:",current_cost,budget)

    return candea_objective_value, num_candea_ops_covered


def run_asap_experiment():
    global unsafe_op_to_targets
    global program_name
    global program_check_cost_estimate, program_md_cost_estimate
    global unsafe_operation_total_operations_freq_count

    # Find avg freq as found in max profit (avg based on non zero upas with reachable uses )
    if USE_USER_SPECIEFIED_BUDGET:
        c = input("Enter budget(s)")
        c = float(c)
        c = round(c, 3)
    else:
        # c=1*exec_times_ref[program_name]/100
        c = 1.24
        c = round(c, 3)

    asap_results = {}
    if ITERATIVE_MODE:
        budget = c
        num_iter = 15
        num_iter = int(num_iter)
        print("Iterative:", str(num_iter))
        for _ in range(num_iter):
            print("Budget:", budget, repr(budget))
            objective_value, num_ops_covered = compute_candea_placement(budget)
            asap_results[budget] = (objective_value, num_ops_covered)
            budget = budget+c
            budget = round(budget, 6)
    else:

        for budget in [c, 2*c, 4*c, 8*c]:
            print("Budget:", budget)
            objective_value, num_ops_covered = compute_candea_placement(budget)
            asap_results[budget] = (objective_value, num_ops_covered)
            break

    return asap_results


def read_optisan_results():
    global num_free_unsafe_operations

    if IGNORE_NUMBER_OF_TARGETS:
        results_file = open(MULTI_ASAN_ONLY_PATH+"/" +
                            program_name+"_solver_results.txt", "r")
    else:
        expanded_file_path = os.path.expanduser(OPTISAN_ASAN_ONLY_PATH)
        results_file = open(expanded_file_path+"/" +
                            program_name+"_solver_results.txt", "r")
    # Budget, obj val (includes free) and ops covered (includes free)
    optisan_asan_results = {}
    for line in results_file:
        temp = line.split()
        budget = float(temp[0])
        obj_val = float(temp[1])
        ops_covered = float(temp[3])
        optisan_asan_results[budget] = (obj_val, ops_covered)
        # print(line.split())

    if IGNORE_NUMBER_OF_TARGETS:
        results_file = open(MULTI_BOTH_PATH+"/" +
                            program_name+"_solver_results.txt", "r")
    else:
        expanded_file_path = os.path.expanduser(OPTISAN_BOTH_PATH)
        results_file = open(expanded_file_path+"/" +
                            program_name+"_solver_results.txt", "r")
    # Budget, obj val (includes free) and ops covered (includes free)
    # Pre compute
    optisan_both_results = {}
    baggy_usage_all = []
    for line in results_file:
        temp = line.split()
        budget = float(temp[0])
        obj_val = float(temp[1])
        baggy_ops_covered = int(temp[2])
        # Assuming baggy covers free (obvi)
        # baggy_ops_covered=baggy_ops_covered-num_free_unsafe_operations
        asan_ops_covered = int(temp[3])
        # baggy_usage=(baggy_ops_covered/(baggy_ops_covered+asan_ops_covered))
        # baggy_usage=round(baggy_usage,2)
        # baggy_usage_all.append(baggy_usage)
        optisan_both_results[budget] = (
            obj_val, baggy_ops_covered+asan_ops_covered,asan_ops_covered)
        # print(line.split())

    # print("Avg baggy usage across budgets:",round(np.average(baggy_usage_all),2)*100)
    # print("Low baggy usage across budgets:",min(baggy_usage_all)*100)
    # exit(1)
    if IGNORE_NUMBER_OF_TARGETS and os.path.isfile(MULTI_BOTH_OBJECT_PATH+"/"+program_name+"_solver_results.txt"):
        results_file = open(MULTI_BOTH_OBJECT_PATH+"/" +
                            program_name+"_solver_results.txt", "r")
    elif os.path.isfile(OPTISAN_BOTH_OBJECT_PATH+"/"+program_name+"_solver_results.txt"):
        results_file = open(OPTISAN_BOTH_OBJECT_PATH+"/" +
                            program_name+"_solver_results.txt", "r")

    # Budget, obj val (includes free) and ops covered (includes free)
    optisan_both_obj_results = {}
    for line in results_file:
        temp = line.split()
        budget = float(temp[0])
        obj_val = float(temp[1])
        ops_covered = float(temp[2])
        optisan_both_obj_results[budget] = (obj_val, ops_covered)
        # print(line.split())

    optisan_baggy_results = {}
    if IGNORE_NUMBER_OF_TARGETS:
        results_file = open(MULTI_BAGGY_ONLY_PATH+"/" +
                            program_name+"_solver_results.txt", "r")

    else:
        expanded_file_path = os.path.expanduser(OPTISAN_BAGGY_ONLY_PATH)
        results_file = open(expanded_file_path+"/" +
                            program_name+"_solver_results.txt", "r")            

        # Budget, obj val (includes free) and ops covered (includes free)
        for line in results_file:
            temp = line.split()
            budget = float(temp[0])
            obj_val = float(temp[1])
            ops_covered = float(temp[2])
            optisan_baggy_results[budget] = (obj_val, ops_covered)

    return optisan_asan_results, optisan_both_results, optisan_both_obj_results, optisan_baggy_results


def plot_graph(asap_results):
    global free_protection
    global num_targets
    global unsafe_op_to_targets
    num_unsafe_ops_wtargets = len(unsafe_op_to_targets.keys())
    asap_objective_values = []
    optisan_asan_objective_values = []
    optisan_baggy_objective_values = []
    optisan_both_objective_values = []
    optisan_both_obj_objective_values = []
    # asap_ops_covered=[]
    num_non_free_targets = num_targets-free_protection
    budgets = []
    # If ignoring targets i.e multi eval then the third dict is for baggy only
    optisan_asan_results, optisan_both_results, optisan_both_obj_results, optisan_baggy_results = read_optisan_results()
    # if program_name in old_free_protection:
    #     free_protection=old_free_protection[program_name]
    #     num_non_free_targets=old_non_free_targets[program_name]
    #     print(free_protection,num_non_free_targets)

    for budget in asap_results:
        obj_val, num_non_free_ops = asap_results[budget]
        normalized_non_free_protection = (
            obj_val-free_protection)*1/num_non_free_targets
        asap_objective_values.append(normalized_non_free_protection)
        # asap_ops_covered.append(num_non_free_ops/num_unsafe_ops_wtargets)

    for budget in optisan_asan_results:
        budgets.append((budget/exec_times_ref[program_name])*100)
        optisan_obj_val, ops_covered = optisan_asan_results[budget]
        optisan_asan_objective_values.append(
            (optisan_obj_val-free_protection)*1/num_non_free_targets)

    for budget in optisan_baggy_results:
        optisan_obj_val, ops_covered = optisan_baggy_results[budget]
        optisan_baggy_objective_values.append(
            (optisan_obj_val-free_protection)*1/num_non_free_targets)

    for budget in optisan_both_results:
        optisan_obj_val, ops_covered = optisan_both_results[budget]
        optisan_both_objective_values.append(
            (optisan_obj_val-free_protection)*1/num_non_free_targets)

    for budget in optisan_both_obj_results:
        optisan_obj_val, ops_covered = optisan_both_obj_results[budget]
        optisan_both_obj_objective_values.append(
            (optisan_obj_val-free_protection)*1/num_non_free_targets)

    # if not asap_objective_values:
    #     asap_objective_values=[ 1 for _ in range(len(budgets))]

    max_optisan_asan_diff = 0
    max_optisan_both_diff = 0
    max_optisan_both_diff_optisan = 0
    max_optisan_both_diff_optisan_baggy = 0
    max_optisan_both_object_diff = 0
    optisan_asan_diffs = []
    optisan_asan_diffs_count = []
    optisan_both_diffs = []
    optisan_both_diffs_count = []

    optisan_both_diffs_w_optisan = []
    optisan_both_diffs_w_optisan_count = []
    optisan_both_diff_w_optisan_baggy = []
    optisan_both_diff_w_optisan_baggy_counts = []
    optisan_both_obj_diff_w_optisan_both = []
    max_budget_asap = 0
    for i in range(0, len(budgets)):
        optisan_asan_diff = optisan_asan_objective_values[i] - \
            asap_objective_values[i]
        optisan_asan_diffs_count.append(optisan_asan_diff*num_non_free_targets)
        optisan_asan_diff = (optisan_asan_diff/asap_objective_values[i])*100
        optisan_asan_diffs.append(optisan_asan_diff)
        max_optisan_asan_diff = max(max_optisan_asan_diff, optisan_asan_diff)

        if optisan_both_objective_values:
            optisan_both_diff = optisan_both_objective_values[i] - \
                asap_objective_values[i]
            optisan_both_diffs_count.append(
                optisan_both_diff*num_non_free_targets)
            optisan_both_diff = (
                optisan_both_diff/asap_objective_values[i])*100
            optisan_both_diffs.append(optisan_both_diff)
            max_optisan_both_diff = max(
                max_optisan_both_diff, optisan_both_diff)
            # print(optisan_both_diff,optisan_both_diffs_count[i])
            # Optisan both -optisan asan diff
            optisan_both_diff_optisan = optisan_both_objective_values[i] - \
                optisan_asan_objective_values[i]
            optisan_both_diffs_w_optisan_count.append(
                optisan_both_diff_optisan*num_non_free_targets)
            optisan_both_diff_optisan = (
                optisan_both_diff_optisan/optisan_asan_objective_values[i])*100
            max_optisan_both_diff_optisan = max(
                optisan_both_diff_optisan, max_optisan_both_diff_optisan)
            optisan_both_diffs_w_optisan.append(optisan_both_diff_optisan)
            if IGNORE_NUMBER_OF_TARGETS:
                # Optisan both -optisan baggy diff
                optisan_both_obj_diff_optisan_baggy = optisan_both_objective_values[
                    i]-optisan_baggy_objective_values[i]
                optisan_both_diff_w_optisan_baggy_counts.append(
                    optisan_both_obj_diff_optisan_baggy*num_non_free_targets)
                optisan_both_obj_diff_optisan_baggy = (
                    optisan_both_obj_diff_optisan_baggy/optisan_baggy_objective_values[i])*100
                max_optisan_both_diff_optisan_baggy = max(
                    optisan_both_obj_diff_optisan_baggy, max_optisan_both_diff_optisan_baggy)
                optisan_both_diff_w_optisan_baggy.append(
                    optisan_both_obj_diff_optisan_baggy)

            # Differ from optisan both per obj with optisan both
        if optisan_both_obj_objective_values:
            optisan_both_obj_diff_optisan_both = optisan_both_objective_values[i] - \
                optisan_both_obj_objective_values[i]
            optisan_both_obj_diff_optisan_both = (
                optisan_both_obj_diff_optisan_both/optisan_both_obj_objective_values[i])*100
            max_optisan_both_object_diff = max(
                optisan_both_obj_diff_optisan_both, max_optisan_both_object_diff)
            optisan_both_obj_diff_w_optisan_both.append(
                optisan_both_obj_diff_optisan_both)

    print("Avg optisan ASAN diff with ASAP (Relative)",
          np.average(optisan_asan_diffs))
    print("Avg optisan ASAN diff with ASAP count",
          np.average(optisan_asan_diffs_count))
    # print("Avg optisan ASAN diff with ASAP count (no accuracy)",np.average(optisan_asan_diffs_count)/ASAN_ACCURACY)
    print("Max (relative) optisan ASAN diff with ASAP:", max_optisan_asan_diff)
    print("Max (count) optisan ASAN diff with ASAP:", max_optisan_asan_diff*asap_objective_values[optisan_asan_diffs.index(
        max_optisan_asan_diff)]*num_non_free_targets/(100), "==", max(optisan_asan_diffs_count))
    # print("Max (count) optisan ASAN diff with ASAP (no accuracy):",max_optisan_asan_diff*asap_objective_values[optisan_asan_diffs.index(max_optisan_asan_diff)]*num_non_free_targets/(100*ASAN_ACCURACY),"==",max(optisan_asan_diffs_count)/ASAN_ACCURACY)

    print()

    print("Avg optisan BOTH diff with ASAP (Relative)",
          np.average(optisan_both_diffs))
    print("Avg optisan BOTH diff with ASAP count",
          np.average(optisan_both_diffs_count))
    # # exit(1)
    print("Max optisan BOTH diff with ASAP (relative):", max_optisan_both_diff)
    print("Max optisan BOTH diff with ASAP (count):", max_optisan_both_diff*asap_objective_values[optisan_both_diffs.index(
        max_optisan_both_diff)]*num_non_free_targets/100, "==", max(optisan_both_diffs_count))

    print()
    # print(optisan_both_diffs_w_optisan)
    # print(optisan_both_diffs_w_optisan_count)
    print("AVG optisan BOTH diff (relative) with optisan ASAN:",
          np.average(optisan_both_diffs_w_optisan))
    print("AVG optisan BOTH diff (count) with optisan ASAN:",
          np.average(optisan_both_diffs_w_optisan_count))

    print("Max optisan BOTH diff (relative) with optisan ASAN:",
          max_optisan_both_diff_optisan)
    print("Max optisan BOTH diff (count) with optisan ASAN:", max_optisan_both_diff_optisan *
          optisan_asan_objective_values[optisan_both_diffs_w_optisan.index(max_optisan_both_diff_optisan)]*num_non_free_targets/100, max(optisan_both_diffs_w_optisan_count))

    print()

    print("AVG optisan BOTH diff (relative) with optisan BBC:",
          np.average(optisan_both_diff_w_optisan_baggy))
    print("AVG optisan BOTH diff (count) with optisan BBC:", np.average(optisan_both_diff_w_optisan_baggy)
          * num_non_free_targets/100, np.average(optisan_both_diff_w_optisan_baggy_counts))

    print("Max optisan BOTH diff (relative) with optisan BBC:",
          max_optisan_both_diff_optisan_baggy)
    print("Max optisan BOTH diff (count) with optisan BBC:", max_optisan_both_diff_optisan_baggy*optisan_baggy_objective_values[optisan_both_diff_w_optisan_baggy.index(
        max_optisan_both_diff_optisan_baggy)]*num_non_free_targets/100, max(optisan_both_diff_w_optisan_baggy_counts))

    print()

    if optisan_both_obj_objective_values:

        print("AVG optisan BOTH obj diff  with optisan BOTH (relative):",
              np.average(optisan_both_obj_diff_optisan_both))
        print("Max optisan BOTH obj diff  with optisan BOTH (relative):",
              max_optisan_both_object_diff)

    # print(budgets,asap_objective_values)
    # print("ASAP:",asap_objective_values)
    # print(optisan_asan_objective_values)
    plt.plot(budgets, asap_objective_values, color="blue", label='ASAP')
    plt.plot(budgets, optisan_asan_objective_values,
             color="red", label='OptiSAN ASan')
    plt.plot(budgets, optisan_both_objective_values,
             color="darkred", label='OptiSAN Both')
    if optisan_both_obj_objective_values and not IGNORE_PER_OBJECT_IN_PLOT:
        plt.plot(budgets, optisan_both_obj_objective_values,
                 color="orange", label='OptiSAN Both Per Object')

    # print(index_pos,"==",optisan_both_diffs.index(max_optisan_both_diff))
    # print(index_pos,"==",opt.index(max_optisan_both_diff))
    # if  IGNORE_NUMBER_OF_TARGETS:
    #     # Both - asan only diff
    #     index_pos=optisan_asan_diffs_count.index(max(optisan_asan_diffs_count))
    #     plt.axvline(budgets[index_pos],ymax=optisan_asan_objective_values[index_pos],color="black", linestyle=":",linewidth=2)
    #     # Both - baggy only diff
    #     index_pos=optisan_both_diffs_w_optisan_count.index(max(optisan_both_diffs_w_optisan_count))
    #     plt.axvline(budgets[index_pos],ymax=optisan_both_objective_values[index_pos],color="black", linestyle="dashed",linewidth=2)
    # else:
    # OptiSan ASAN and  ASAP
    index_pos = optisan_asan_diffs_count.index(max(optisan_asan_diffs_count))
    plt.axvline(budgets[index_pos], ymax=optisan_asan_objective_values[index_pos],
                color="black", linestyle=":", linewidth=2)
    # print(index_pos)
    # OptiSan both and ASAN
    index_pos = optisan_both_diffs_w_optisan_count.index(
        max(optisan_both_diffs_w_optisan_count))
    plt.axvline(budgets[index_pos], ymax=optisan_both_objective_values[index_pos],
                color="black", linestyle="dashed", linewidth=2)
    # print(index_pos)

    # OptiSan both and BBC
    index_pos = optisan_both_diff_w_optisan_baggy_counts.index(
        max(optisan_both_diff_w_optisan_baggy_counts))
    plt.axvline(budgets[index_pos], ymax=optisan_both_objective_values[index_pos],
                color="black", linestyle="dashdot", linewidth=2)
    # print(index_pos)

    # plt.axvline(3,color="black", linestyle="dashed",linewidth=2)
    if IGNORE_NUMBER_OF_TARGETS:
        plt.plot(budgets, optisan_baggy_objective_values,
                 color="violet", label='OptiSAN Baggy')

    plt.xlabel("Budget (%) - "+program_name, fontsize=16)
    plt.ylabel("Unsafe Operations With Targets Protected", fontsize=16)
    plt.legend()
    plt.grid(True)
    plt.ylim(0, 1)
    # plt.gca().set_aspect('equal', adjustable='box')
    plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6,
               0.7, 0.8, 0.9, 1.0], fontsize=13)
    # plt.xticks(list(range(0,max(int(budgets)),1)))
    plt.savefig(program_name+".pdf")


def plot_raw_op_count_graphs(asap_results):
    global free_protection
    global num_targets
    global unsafe_op_to_targets
    global num_free_unsafe_operations
    asap_objective_values = []
    # OptiSan ASan objective value (targets), unsafe ops
    optisan_asan_unsafe_op_covered_values = []
    optisan_asan_target_values = []
    optisan_asan_effective_op_covered_values=[]
    #OptiSan Baggy objective value (targets), unsafe ops
    optisan_baggy_unsafe_op_covered_values = []
    optisan_baggy_target_values = []
    # OptiSan Both objective value (targets), unsafe ops
    optisan_both_unsafe_op_covered_values = []
    optisan_both_effective_op_covered_values=[]
    optisan_both_target_values = []
    optisan_both_obj_objective_values = []
    # asap_ops_covered=[]
    num_non_free_targets = num_targets-free_protection
    num_non_free_unsafe_operations=len(unsafe_op_to_targets.keys())-num_free_unsafe_operations
    # assert num_targets==num_unsafe_ops_wtargets
    budgets = []
    # If ignoring targets i.e multi eval then the third dict is for baggy only
    optisan_asan_results, optisan_both_results, optisan_both_obj_results, optisan_baggy_results = read_optisan_results()
 

    for budget in optisan_asan_results:
        budgets.append((budget/exec_times_ref[program_name])*100)
        optisan_obj_val, ops_covered = optisan_asan_results[budget]
        optisan_asan_unsafe_op_covered_values.append(
            (ops_covered-num_free_unsafe_operations)*1/num_non_free_unsafe_operations)
     
        effective_ops_covered=(ops_covered-num_free_unsafe_operations)*ASAN_ACCURACY
        optisan_asan_effective_op_covered_values.append(effective_ops_covered/num_non_free_unsafe_operations)
        optisan_asan_target_values.append(
            (optisan_obj_val-free_protection)*1/num_non_free_targets)
        # exit(1)

    for budget in optisan_baggy_results:
        optisan_obj_val, ops_covered = optisan_baggy_results[budget]
        optisan_baggy_unsafe_op_covered_values.append(
            (ops_covered-num_free_unsafe_operations)*1/num_non_free_unsafe_operations)
        optisan_baggy_target_values.append(
            (optisan_obj_val-free_protection)*1/num_non_free_targets)
    

    for budget in optisan_both_results:
        optisan_obj_val, ops_covered,asan_only_ops_covered = optisan_both_results[budget]
        optisan_both_unsafe_op_covered_values.append(
            (ops_covered-num_free_unsafe_operations)*1/num_non_free_unsafe_operations)
        effective_ops_covered=(ops_covered-asan_only_ops_covered-num_free_unsafe_operations)+(asan_only_ops_covered*ASAN_ACCURACY)
        optisan_both_effective_op_covered_values.append(
            (effective_ops_covered)*1/num_non_free_unsafe_operations)
        optisan_both_target_values.append(
            (optisan_obj_val-free_protection)*1/num_non_free_targets)

    max_optisan_asan_diff = 0
    max_optisan_both_diff = 0
    max_optisan_both_diff_optisan = 0
    max_optisan_both_ops_covered_diff_optisan_baggy = 0
    max_optisan_both_ops_covered_diff_optisan_asan=0
    max_optisan_both_targets_diff_optisan_baggy = 0

    max_optisan_both_object_diff = 0
    optisan_asan_diffs = []
    optisan_asan_diffs_count = []
    optisan_both_diffs = []
    optisan_both_diffs_count = []

    optisan_both_diffs_w_optisan = []
    optisan_both_diffs_w_optisan_count = []
    optisan_both_raw_diff_w_optisan_baggy = []
    optisan_both_effective_ops_w_optisan_baggy=[]
    optisan_both_raw_diff_w_optisan_baggy_counts = []
    optisan_both_targets_diff_w_optisan_baggy_values = []

    optisan_both_raw_diff_w_optisan_asan=[]
    optisan_both_raw_diff_w_optisan_asan_counts=[]
    optisan_both_targets_diff_w_optisan_asan_values = []
    optisan_both_effective_ops_w_optisan_asan=[]
    optisan_both_obj_diff_w_optisan_both = []
    max_budget_asap = 0
    for i in range(0, len(budgets)):
        if optisan_both_unsafe_op_covered_values or optisan_baggy_unsafe_op_covered_values:
        
            # Optisan both - optisan baggy diff
            optisan_both_ops_covered_diff_optisan_baggy = optisan_both_unsafe_op_covered_values[
                i]-optisan_baggy_unsafe_op_covered_values[i]
            optisan_both_raw_diff_w_optisan_baggy_counts.append(
                optisan_both_ops_covered_diff_optisan_baggy*num_non_free_unsafe_operations)
            
            if not optisan_baggy_unsafe_op_covered_values[i]:
                optisan_both_ops_covered_diff_optisan_baggy = 100
            else:      
                optisan_both_ops_covered_diff_optisan_baggy = (optisan_both_ops_covered_diff_optisan_baggy/optisan_baggy_unsafe_op_covered_values[i])*100
            optisan_both_raw_diff_w_optisan_baggy.append(
                optisan_both_ops_covered_diff_optisan_baggy)
            
            optisan_both_eff_ops_covered_diff_optisan_baggy=optisan_both_effective_op_covered_values[i]-optisan_baggy_unsafe_op_covered_values[i]
            if not optisan_baggy_unsafe_op_covered_values[i]:
                optisan_both_eff_ops_covered_diff_optisan_baggy = 100
            else:
                optisan_both_eff_ops_covered_diff_optisan_baggy = (
                    optisan_both_eff_ops_covered_diff_optisan_baggy/optisan_baggy_unsafe_op_covered_values[i])*100
            optisan_both_effective_ops_w_optisan_baggy.append(optisan_both_eff_ops_covered_diff_optisan_baggy)


            optisan_both_targets_diff_w_optisan_baggy=optisan_both_target_values[i]-optisan_baggy_target_values[i]
            if not optisan_baggy_target_values[i]:
                optisan_both_targets_diff_w_optisan_baggy = 100
            else:
                optisan_both_targets_diff_w_optisan_baggy = (
                    optisan_both_targets_diff_w_optisan_baggy/optisan_baggy_target_values[i])*100
            optisan_both_targets_diff_w_optisan_baggy_values.append(optisan_both_targets_diff_w_optisan_baggy)

            # OptiSan both - OptiSan asan diff 
            optisan_both_ops_covered_diff_optisan_asan = optisan_both_unsafe_op_covered_values[
                i]-optisan_asan_unsafe_op_covered_values[i]
            optisan_both_raw_diff_w_optisan_asan_counts.append(
                optisan_both_ops_covered_diff_optisan_asan*num_non_free_unsafe_operations)
            if not optisan_asan_unsafe_op_covered_values[i]:
                optisan_both_ops_covered_diff_optisan_asan = 100
            else:        
                optisan_both_ops_covered_diff_optisan_asan = (
                    optisan_both_ops_covered_diff_optisan_asan/optisan_asan_unsafe_op_covered_values[i])*100
            optisan_both_raw_diff_w_optisan_asan.append(
                optisan_both_ops_covered_diff_optisan_asan)
            

            optisan_both_eff_ops_covered_diff_optisan_asan=optisan_both_effective_op_covered_values[i]-optisan_asan_effective_op_covered_values[i]
            if not optisan_asan_effective_op_covered_values[i]:
                optisan_both_eff_ops_covered_diff_optisan_asan=100
            else:    
                optisan_both_eff_ops_covered_diff_optisan_asan = (
                    optisan_both_eff_ops_covered_diff_optisan_asan/optisan_asan_effective_op_covered_values[i])*100
            optisan_both_effective_ops_w_optisan_asan.append(optisan_both_eff_ops_covered_diff_optisan_asan)

            optisan_both_targets_diff_w_optisan_asan=optisan_both_target_values[i]-optisan_asan_target_values[i]
            if not optisan_asan_target_values[i]:
                optisan_both_targets_diff_w_optisan_asan=100
            else:    
                optisan_both_targets_diff_w_optisan_asan = (
                    optisan_both_targets_diff_w_optisan_asan/optisan_asan_target_values[i])*100
            optisan_both_targets_diff_w_optisan_asan_values.append(optisan_both_targets_diff_w_optisan_asan)


    print("OptiSan Both vs Optisan Baggy ")
    print("AVG optisan BOTH diff (relative) with optisan BBC:",np.average(optisan_both_raw_diff_w_optisan_baggy))
    print("AVG optisan BOTH diff (raw count) with optisan BBC:",  np.average(optisan_both_raw_diff_w_optisan_baggy_counts))

    print("Max optisan BOTH diff (relative) with optisan BBC:",
          max(optisan_both_raw_diff_w_optisan_baggy))
    print("Max optisan BOTH diff (raw count) with optisan BBC:",  max(optisan_both_raw_diff_w_optisan_baggy_counts))


    # print("AVG optisan BOTH targets diff (relative) with optisan BBC:",np.average(optisan_both_targets_diff_w_optisan_baggy_values))
    # print("MAX optisan BOTH targets diff (relative) with optisan BBC:",max(optisan_both_targets_diff_w_optisan_baggy_values))


    print("AVG optisan BOTH eff unsafe op diff (relative) with optisan BBC:",np.average(optisan_both_effective_ops_w_optisan_baggy))
    print("MAX optisan BOTH eff unsafe op diff (relative) with optisan BBC:",max(optisan_both_effective_ops_w_optisan_baggy))



    print()

    # print("OptiSan Both vs Optisan ASan ")
    # print("AVG optisan BOTH diff (relative) with optisan ASan:",np.average(optisan_both_raw_diff_w_optisan_asan))
    # print("AVG optisan BOTH diff (raw count) with optisan ASan:",  np.average(optisan_both_raw_diff_w_optisan_asan_counts))

    # print("Max optisan BOTH diff (relative) with optisan ASan:",
    #       max(optisan_both_raw_diff_w_optisan_asan))
    # print("Max optisan BOTH diff (raw count) with optisan ASan:",  max(optisan_both_raw_diff_w_optisan_asan_counts))


    # print("AVG optisan BOTH targets diff (relative) with optisan ASan:",np.average(optisan_both_targets_diff_w_optisan_asan_values))
    # print("MAX optisan BOTH targets diff (relative) with optisan ASan:",max(optisan_both_targets_diff_w_optisan_asan_values))


    # print("AVG optisan BOTH eff unsafe op diff (relative) with optisan ASan:",np.average(optisan_both_effective_ops_w_optisan_asan))
    # print("MAX optisan BOTH eff unsafe op diff (relative) with optisan ASan:",max(optisan_both_effective_ops_w_optisan_asan))


    # print()

 
    # print(optisan_asan_effective_op_covered_values)
    # print(optisan_both_effective_op_covered_values)
    plt.plot(budgets, optisan_baggy_unsafe_op_covered_values,
             color="violet", label='OptiSAN Baggy')
    plt.plot(budgets, optisan_both_unsafe_op_covered_values,
             color="red", label='OptiSAN Both')
    plt.plot(budgets, optisan_asan_effective_op_covered_values, color="blue", label='OptiSAN ASan Effective')
    plt.plot(budgets, optisan_both_effective_op_covered_values,
                color="darkred", label='OptiSAN Both Effective')

    

    # OptiSan both and OptiSan Baggy raw counts
    index_pos = optisan_both_raw_diff_w_optisan_baggy_counts.index(
        max(optisan_both_raw_diff_w_optisan_baggy_counts))
    plt.axvline(budgets[index_pos], ymax=optisan_both_unsafe_op_covered_values[index_pos],
                color="black", linestyle="dashdot", linewidth=2)

    # Effective
    index_pos = optisan_both_raw_diff_w_optisan_baggy_counts.index(
        max(optisan_both_raw_diff_w_optisan_baggy_counts))
    plt.axvline(budgets[index_pos], ymax=optisan_both_unsafe_op_covered_values[index_pos],
                color="black", linestyle="dashdot", linewidth=2)




    plt.xlabel("Budget (%) - "+program_name, fontsize=16)
    plt.ylabel("Unsafe Operations With Targets Protected", fontsize=16)
    plt.legend()
    plt.grid(True)
    plt.ylim(0, 1)
    plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6,
               0.7, 0.8, 0.9, 1.0], fontsize=13)
    plt.savefig(program_name+".pdf")


if __name__ == "__main__":
    driver = get_db_driver()
    program_name = str(sys.argv[1])
    program_check_cost_estimate=get_cost_estimates(program_name,MonitorOperations.Checks,MonitorType.ASAN)
    program_md_cost_estimate=get_cost_estimates(program_name,MonitorOperations.Metadata,MonitorType.ASAN)
    # print("ASAN MD Cost:",program_md_cost_estimate)
    # print("ASAN Check Cost:",program_check_cost_estimate)
    # if IGNORE_NUMBER_OF_TARGETS:
    #     ASAP_IGNORE_NO_USE_UPAS=True
    if not IGNORE_NUMBER_OF_TARGETS or program_name not in old_free_protection:
        read_necessary_safety_information()
    print("# Num of free unsafe ops:",num_free_unsafe_operations)
    print("Free protection:",free_protection)
    asap_results = []
    # # asap_results=run_asap_experiment()
    # # read_optisan_results()
    # # plot_graph(asap_results)
    plot_raw_op_count_graphs(asap_results)
