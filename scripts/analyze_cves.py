"""
    Utility script to fetch some info about specific unsafe ops (CVEs, looking at you :P)

"""

from neo4j import GraphDatabase
from enum import Enum
import sys
import numpy as np
import matplotlib.pyplot as plt
import os.path

program_name = None

"""
    Freq - index
	Placement index 
	Based on Target count
		above average 
		Importance index 	
		httpd, readelf
"""

old_free_protection = old_non_free_targets = {}

program_check_cost_estimate = None
program_md_cost_estimate = None

IGNORE_NUMBER_OF_TARGETS = False
FAUX_TARGET_LABEL = "faux_target_"


UNSAFE_POINTER_STATE_TYPE = "1"
UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE = "1"
UNSAFE_POINTER_READ_STACK_ACTION_TYPE = "2"
UNSAFE_STACK_OBJECT = "6"

# MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.program_name="readelf" RETURN COUNT(DISTINCT a);
# MATCH (a:AttackGraphNode)-[:EDGE]->(p:AttackGrapgNode) WHERE a.id="1c381b0a-2ec3-4a35-8278-1f4519d4042f" RETURN p;
# MATCH (a:AttackGraphNode)-[:EDGE]->(b:AttackGraphNode) WHERE a.id="708f9209-cd8e-4c61-9371-8490d447ed11" RETURN a;


# HTppd
# 1 byte CVE - 2598/2969
# ab8acaea-c19e-4b98-a214-03fe8e2ee407 - 759 (looks like this one)
# or 3845c0fb-5ae2-40a4-8298-94a6c4e6f124"
# baa67b0d-eb83-499b-bdc3-435c30194194
# Remote ip
# 5c03a862-9f38-4f7d-bc5f-de50bd756bef


# Libtiff (tiffcp)
# CVE-2016-10095 - _TIFFVGetField - 86ac8c7d-f3b5-4bf4-b693-283af79c38c1
#  CVE-2022-1355  - main (there are 4 switch cases) all not executed in the tests but we picked one d7e3336a-d1fb-47a6-a169-b3fc211eb280 (should have same reachability)
# Read eld
# 4c254627-66a5-4220-920a-552adb183b25

# nginx
# 55f95127-68a4-48f8-89e1-87ab1c96585b

# Openssl
# 2016 CVE - 708f9209-cd8e-4c61-9371-8490d447ed11
# CVE-2022-3786 32c202b4-d7f2-4cd2-8c5f-18877631c989
# CVE-2022-3602 8376c3a3-bb2e-42ce-bb61-d7c9720bfcfe

cve_ids = None

cve_name_to_cves = {"xmllint": ["179810a1-32cf-4520-b5fa-0ed79b3d797f", "4c5f9ff3-51ca-44eb-8028-3ddf0f3d1634", "695cc3fd-44af-466a-b2fb-11fdfcae97e1"], "openssl": [
    "708f9209-cd8e-4c61-9371-8490d447ed11", "32c202b4-d7f2-4cd2-8c5f-18877631c989","8376c3a3-bb2e-42ce-bb61-d7c9720bfcfe"], "httpd": ["5c03a862-9f38-4f7d-bc5f-de50bd756bef", "ab8acaea-c19e-4b98-a214-03fe8e2ee407"], "readelf": ["4c254627-66a5-4220-920a-552adb183b25"],"tiffcp":["86ac8c7d-f3b5-4bf4-b693-283af79c38c1","d7e3336a-d1fb-47a6-a169-b3fc211eb280"],"nginx":["55f95127-68a4-48f8-89e1-87ab1c96585b"]}

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

    print("# reachable targets", len(reachable_targets))
    for target in reachable_targets:
        if IGNORE_NUMBER_OF_TARGETS:
            if target not in targets_to_unsafe_op:
                targets_to_unsafe_op[target] = set()
            node_id = target[target.index(
                FAUX_TARGET_LABEL)+len(FAUX_TARGET_LABEL):]
            targets_to_unsafe_op[target].add(node_id)
        else:
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
    # print("Avg max profit per unsafe operation", np.mean(profit_values))
    # print("Std max profit per unsafe operation",
    #       np.std(profit_values))

    profit_values = sorted(profit_values, reverse=True)
    print("MIN PROFITT",min(profit_values),"MAX Profit",max(profit_values))
    print(profit_values)
    for cve_id in cve_ids:
        if cve_id in profit_per_unsafe_operation:
            cve_index = profit_values.index(
                profit_per_unsafe_operation[cve_id])
        else:
            print("\t No targets in DB (CHECK)",cve_id)
            cve_index = len(all_unsafe_operations)-1

        print(cve_id," profit :",cve_index,profit_per_unsafe_operation[cve_id])
        print(cve_id, " target rank (lower is better - more potential security impact): ", cve_index,"/",len(all_unsafe_operations))

    for unsafe_operation in unsafe_op_to_md:
        unsafe_operation_total_operations_freq_count[
            unsafe_operation] = unsafe_operations_freq_count[unsafe_operation]
        for md_operation in unsafe_op_to_md[unsafe_operation]:
            unsafe_operation_total_operations_freq_count[
                unsafe_operation] += md_operations_freq_count[md_operation]

    frequency_values=list(unsafe_operation_total_operations_freq_count.values())
    print(len([1 for f in frequency_values if f>=10**6]))
    frequency_values=sorted(frequency_values,reverse=False)
    print("MIN Freq",min(frequency_values))
    print(frequency_values)
    for cve_id in cve_ids:
        if cve_id in unsafe_operation_total_operations_freq_count:
            cve_index = frequency_values.index(
                unsafe_operation_total_operations_freq_count[cve_id])
        else:
            print("\t No freq info in DB (CHECK)",cve_id)
            cve_index = len(all_unsafe_operations)-1

        print(cve_id," freq :",cve_index,unsafe_operation_total_operations_freq_count[cve_id])
        print(cve_id, " freq rank (lower is better- cheaper): ", cve_index,"/",len(all_unsafe_operations))    


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


if __name__ == "__main__":
    driver = get_db_driver()
    program_name = str(sys.argv[1])
    if program_name in cve_name_to_cves:
        cve_ids = cve_name_to_cves[program_name]
        read_necessary_safety_information()
