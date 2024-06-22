"""
    Sanitizer Placement module
    Responsible for generating monitoring info (grew out from utilities of the AG framework)
"""

import itertools
import time
from collections import defaultdict
from neo4j import GraphDatabase
from monitoring_constants_and_ds import UNSAFE_POINTER_STATE_TYPE, MonitorType, MonitoringOption
from monitoring_constants_and_ds import ATTACK_ACTION_NT, ATTACK_STATE_NT
from monitoring_constants_and_ds import  IMPACTED_STACK_OBJECT, IMPACTED_STACK_POINTER
from monitoring_constants_and_ds import  UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, \
    SYS_CALL_ATTACK_ACTION_TYPE
from monitoring_constants_and_ds import PROBABILITY_OF_DETECTION_MINIMUM_THRESHOLD
from monitoring_constants_and_ds import IMPACTED_POINTER_WRITE_ACTION_TYPE, IMPACTED_POINTER_READ_ACTION_TYPE, \
    IMPACTED_POINTER_PROPAGATION_ACTION_TYPE, IMPACTED_DATA_OBJECT_LOCAL_ACTION_TYPE, \
    IMPACTED_DATA_OBJECT_NON_LOCAL_ACTION_TYPE, MONITORING_POINT_NODE_LABEL, REDZONE_SIZE, UNSAFE_POINTER_READ_STACK_ACTION_TYPE
from itertools import combinations
# Import ASAN cost estimates
from monitoring_constants_and_ds import get_cost_estimates,UNSAFE_STACK_OBJECT, MonitorOperations
from monitoring_constants_and_ds import  ASAP_MODE, IGNORE_NUMBER_OF_TARGETS, FAUX_TARGET_LABEL, BAGGY_ONLY_MODE


currentMonitorsFixedOrder = [MonitorType.ASAN, MonitorType.BBC]
_program_name = None
all_relevant_unsafe_operations = set()
# "Cache" where for any node we cache its predecessors (has an (1) edge to the node in question)
preceeding_nodes_cache = dict()
# Dict of unsafe op to monitor types which can be applied to the operation
unsafe_operations_to_monitor_type_to_monitoring_points = {}
relevant_unsafe_operations_which_can_be_monitored_per_target = defaultdict(set)
# Per target you have multiple monitoring options. Each monitoring option consists of unsafe operation,monitor type, monitoring points and accuracy
monitoring_options_per_unsafe_operation = defaultdict(list)
# Accuracy info. For a monitor all monitored operations and the accuracy at that operation
accuracy_per_monitor_type = {}
# Metadata operations related data structures
ordered_unsafe_object_ids = []
unsafe_object_to_func = {}    
func_to_unsafe_objects={}
func_to_labels={}
md_frequency_info={}

def set_program_name(program_name):
    global _program_name
    _program_name=program_name

def compute_target_weights(unsafe_operations_which_can_be_monitored, targets, is_unweighted=False):
    target_weights = {}
    weights = {}
    weights[IMPACTED_POINTER_READ_ACTION_TYPE] = 1
    weights[IMPACTED_POINTER_PROPAGATION_ACTION_TYPE] = 2
    weights[IMPACTED_POINTER_WRITE_ACTION_TYPE] = 3
    weights[IMPACTED_DATA_OBJECT_LOCAL_ACTION_TYPE] = 1
    weights[IMPACTED_DATA_OBJECT_NON_LOCAL_ACTION_TYPE] = 2

    if not is_unweighted:
        unsafe_op_to_impacted_obj, impacted_obj_to_uses_count = fetch_unsafe_operations_impacted_objects_and_uses(
            unsafe_operations_which_can_be_monitored)
    for target in targets:
        if is_unweighted:
            target_weights[target] = 1
        else:
            print("Target:", target)
            weight_for_target = 1
            for use_type in impacted_obj_to_uses_count[target]:
                print("\t\t Use type:", use_type)
                print("\t\t # of uses:",
                      impacted_obj_to_uses_count[target][use_type])
                weight_for_target = weight_for_target + (
                    weights[use_type] * impacted_obj_to_uses_count[target][use_type])
            target_weights[target] = weight_for_target
            print("Weight:", target_weights[target])
    return target_weights


def map_defenses_to_unsafe_operations_and_identify_monitoring_points():
    global unsafe_operations_to_monitor_type_to_monitoring_points
    unsafe_operations = fetch_relevant_unsafe_operations()
    for unsafe_operation in unsafe_operations:
        unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation] = {
        }
        for monitor_type in currentMonitorsFixedOrder:
            unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation][monitor_type] = set(
            )
    # Annotate nodes
    find_and_annotate_monitoring_points()


"""
    Finds the set of unsafe operations which can affect a target
    (As computed in the attack graph)
"""


def find_unsafe_operations_can_be_monitored_per_target(targets):
    global relevant_unsafe_operations_which_can_be_monitored_per_target
    worklist = []
    # To deal with loops
    nodes_seen = set()
    need_to_traverse_more = False
    # TODO - Make it a DAG so we can topologically sort and use the targets (avoid recomputation)
    for target in targets:
        worklist.clear()
        nodes_seen.clear()
        if IGNORE_NUMBER_OF_TARGETS:
            unsafe_operation = target[target.index(
                FAUX_TARGET_LABEL)+len(FAUX_TARGET_LABEL):]
            relevant_unsafe_operations_which_can_be_monitored_per_target[target].add(
                unsafe_operation)
        else:
            worklist.append(target)
            # Find all operations that need be monitored for a target
            # In our current model we are not considering the OR so we've simplified rhe algo below to just take the simple cut
            while worklist:
                node = worklist.pop()
                nodes_seen.add(node)
                if node in unsafe_operations_to_monitor_type_to_monitoring_points:
                    relevant_unsafe_operations_which_can_be_monitored_per_target[target].add(
                        node)
                # else:
                preceding_actions = get_preceeding_actions(node)

                for unsafe_operation in preceding_actions:
                    if unsafe_operation in unsafe_operations_to_monitor_type_to_monitoring_points:
                        relevant_unsafe_operations_which_can_be_monitored_per_target[target].add(
                            unsafe_operation)
                    if unsafe_operation not in nodes_seen:
                        worklist.append(unsafe_operation)

        # print("Target:", target, ": # unsafe operations - ",
        #       len(relevant_unsafe_operations_which_can_be_monitored_per_target[target]))

"""
    Current design is that the solver reads a txt file to read execution profile data for each monitor's operation 
    and we rely on a fixed order to correlate 
"""
def generate_coverage_file(program_name):
    coverage_file = open(program_name+"_coverage.txt", "w")
    driver = get_db_driver()

    # Same order i.e all check operations for all monitors first ordered by ID
    with driver.session() as session:
        result = session.run(
            "MATCH (mp:MP)-[:EDGE]->(p:ProgramInstruction) WHERE mp.program_name=$program_name RETURN mp.count_ref as count,mp.id as ID ORDER BY mp.id", program_name=program_name)
        for record in result:
            if not record["count"]:
                # print("ID:", str(record["ID"]))
                coverage_file.write(str(0)+"\n")
            else:
                coverage_file.write(str(record["count"])+"\n")

    # MD Operations - common across unsafe ops for a monitor
    global ordered_unsafe_object_ids 
    global unsafe_object_to_func 
    global func_to_unsafe_objects
    global md_frequency_info
    global func_to_labels
    md_points_seen=set()
    find_all_relevant_md_operations()

    # MD objects are common as we provide options per relevant unsafe operation.
    # Can MD vary?. Maybe MD point?
    asan_program_check_cost_estimate = get_cost_estimates(_program_name,
        MonitorOperations.Checks, MonitorType.ASAN)
    asan_program_md_cost_estimate = get_cost_estimates(_program_name,
        MonitorOperations.Metadata, MonitorType.ASAN)
    baggy_program_check_cost_estimate = get_cost_estimates(_program_name,
        MonitorOperations.Checks, MonitorType.BBC)
    baggy_program_md_cost_estimate = get_cost_estimates(_program_name,
        MonitorOperations.Metadata, MonitorType.BBC)
    print("ASAN:",asan_program_check_cost_estimate,asan_program_md_cost_estimate)    
    print("Baggy:",baggy_program_check_cost_estimate,baggy_program_md_cost_estimate)    
    total_md_freq = 0
    for monitor_type in currentMonitorsFixedOrder:
        # For ASAN and Baggy these queries without specifying the monitor is sufficient. However, more robust and extensible would be to specify monitor
        if monitor_type == MonitorType.ASAN:   
            for objID in ordered_unsafe_object_ids:
                function_name = unsafe_object_to_func[objID]
                # To take into account multiple objects in a function so we model func MD operation (in a conservative manner 1 md object, the others free -> Func md cost )
                objID=func_to_labels[function_name]
                freq=md_frequency_info[function_name]
                orig_freq = freq
                # print("Orig md freq:",freq)
                effective_md_cost_estimate=asan_program_md_cost_estimate        
                # Adjust MD freq to take into account MD operations (or generally  different class of operations) may not cost the same      
                freq = (orig_freq/asan_program_check_cost_estimate) * \
                    effective_md_cost_estimate  
                freq = int(freq)
                # print("Adjust freq:",freq)
                if objID not in md_points_seen:
                # print("Obj id:",objID, orig_freq,freq)
                    coverage_file.write(str(freq)+"\n")
                    md_points_seen.add(objID)
                    total_md_freq = total_md_freq+freq

        elif monitor_type == MonitorType.BBC:
            # Find unsafe object(s) corresponding to this unsafe operation               
            for objID in ordered_unsafe_object_ids:
                function_name = unsafe_object_to_func[objID]
                # To take into account multiple objects in a function so func MD operation 
                objID=func_to_labels[function_name]
                effObjID = "BAGGY_"+objID
                freq=md_frequency_info[function_name]
                orig_freq = freq
                # print("Orig md freq:",freq)
                effective_md_cost_estimate=baggy_program_md_cost_estimate
                # freq=freq/func_to_objects[function_name]
                # Adjust MD freq to take into account MD operations (or generally  different class of operations) may not cost the same      
                freq = (orig_freq/baggy_program_check_cost_estimate) * \
                    effective_md_cost_estimate  
                freq = int(freq)
                # print("Adjust freq:",freq)           
                if effObjID not in md_points_seen:
                    coverage_file.write(str(freq)+"\n")
                    md_points_seen.add(effObjID)
    
    coverage_file.close()
    print("Total ASAN adjusted MD freq:", total_md_freq,
          total_md_freq*asan_program_check_cost_estimate)



"""
    We  provide the monitoring options for each unsafe operation (this includes monitoring points).
    The solver will then find the right choices (be it multiple locations) as part of the optimal
    solution.
"""


def generate_monitoring_options_for_unsafe_operations(unsafe_operation):
    global monitoring_options_per_unsafe_operation

    for monitor_type in unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation]:
        monitoring_option = MonitoringOption()
        # Step 1 - Find monitoring point(s) for monitor applied to an unsafe operation
        monitoring_points = unsafe_operations_to_monitor_type_to_monitoring_points[
            unsafe_operation][monitor_type]
        # Step 2 - Create monitoring option - Singleton set
        monitoring_option.add_monitor(
            unsafe_operation, monitoring_points, monitor_type)

        # Step 3 include accuracy
        monitoring_option.accuracy = accuracy_per_monitor_type[monitor_type][unsafe_operation]

        monitoring_options_per_unsafe_operation[unsafe_operation].append(
            monitoring_option)


def generate_monitoring_options_and_weights():
    # Step 1 - Fetch actual targets/goals
    targets = fetch_targets(
        True, [IMPACTED_STACK_OBJECT, IMPACTED_STACK_POINTER])
    # Step 2 - Map monitors to nodes and annotate MPs (Unsafe operations -> monitor type -> )
    map_defenses_to_unsafe_operations_and_identify_monitoring_points()
    # Step 3 - Find the relevant unsafe operations per target (Unsafe operations - Target mapping)
    find_unsafe_operations_can_be_monitored_per_target(targets)

    # Remove targets which do not have any monitoring options (Hack to deal with memcpy etc)
    # targets = list(relevant_unsafe_operations_which_can_be_monitored_per_target.keys())

    unsafe_operations_which_can_be_monitored = set()
    # Step 4 - Generate monitoring options for the relevant unsafe operations per target
    for target in targets:
        for unsafe_operation in relevant_unsafe_operations_which_can_be_monitored_per_target[target]:
            unsafe_operations_which_can_be_monitored.add(unsafe_operation)

    for unsafe_operation in unsafe_operations_which_can_be_monitored:
        generate_monitoring_options_for_unsafe_operations(unsafe_operation)

    target_weights = compute_target_weights(unsafe_operations_which_can_be_monitored,
                                            targets, is_unweighted=True)
    # print("Target weights:", target_weights)
    unsafe_operations_which_can_be_monitored = sorted(
        list(unsafe_operations_which_can_be_monitored))
    return unsafe_operations_which_can_be_monitored, target_weights


def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(
        uri, auth=("neo4j", "secret"), encrypted=False)
    return driver


def generate_monitoring_info():
    program_name = _program_name
    # print("Rrogram name:",_program_name)
    start=time.time()
    # Generate costs (Some complexity introduced because of "holistic" monitors like Proc Wall)
    monitor_type_cost_dict, nodes_realized_type_dict = compute_monitor_costs_and_sanity_checks()
    end=time.time()
    print("Step 1 - Cost estimates for monitors:", end-start)

    start=time.time()
    # Read accuracy info
    read_accuracy_info()
    end=time.time()
    print("Step 2 - Accuracy info:", end-start)

    start=time.time()
    # Generate monitoring info - nodes to be monitored for given target and weights
    unsafe_operations_to_be_monitored, target_weights = generate_monitoring_options_and_weights()
    end=time.time()

    # print("Step 3 - Monitoring info:", end-start)
    start=time.time()
    # Generate ordered list of relevant node ids (Frequency etc)
    relevant_ordered_attack_graph_node_ids = gen_ids()
    end=time.time()
    print("Step 3 - Generating logical node ids :", end-start)

    start=time.time()
    # Generate necessary frequency data in order
    generate_coverage_file(program_name)
    end=time.time()
    print("Step 4 - Generating execution profile  :", end-start)


     # ID File to map
    id_file = open(program_name + "_ids.txt", "w")
    for node_id in relevant_ordered_attack_graph_node_ids:
        id_file.write(str(relevant_ordered_attack_graph_node_ids.index(
            node_id)) + " " + str(node_id) + "\n")
    id_file.close()


   

    # Finally create txt files - Update costs to reflect type of monitor
    cost_file = open(program_name + "_costs.txt", "w")
    for monitor_type in MonitorType:
        if monitor_type.value in monitor_type_cost_dict:
            print("Monitor type:", monitor_type)
            print("Monitor type:", monitor_type_cost_dict[monitor_type.value])
            cost_file.write(str(monitor_type_cost_dict[monitor_type.value]))
            cost_file.write("\n")
    cost_file.close()

    # We map individual monitors to nodes and the formulation finds necessary sets
    all_monitored_unsafe_operations = set()
    all_monitoring_points_seen = set()
    monitor_type_file = open(program_name + "_monitor_types.txt", "w")
    accuracy_file = open(program_name + "_accuracy.txt", "w")
    with open(program_name + "_t" + str(
        len(relevant_unsafe_operations_which_can_be_monitored_per_target.keys())) + "_n" + str(
            len(unsafe_operations_to_be_monitored)) + "_tes.txt", "w") as tes_file:
        # Number of targets
        # tes_file.write(str(len(relevant_unsafe_operations_which_can_be_monitored_per_target.keys())) + "\n")
        for unsafe_operation in unsafe_operations_to_be_monitored:
            # Number of monitoring options for this unsafe operation
            tes_file.write(
                str(len(monitoring_options_per_unsafe_operation[unsafe_operation])) + "\n")
            monitor_type_file.write(
                str(len(monitoring_options_per_unsafe_operation[unsafe_operation])) + "\n")
            accuracy_file.write(
                str(len(monitoring_options_per_unsafe_operation[unsafe_operation])) + "\n")
            # print("Unsafe op pos:id (MPs) - ", str(relevant_ordered_attack_graph_node_ids.index(unsafe_operation)+1), ":",
            #       str(unsafe_operation))
            # Unsafe operation
            tes_file.write(str(unsafe_operations_to_be_monitored.index(
                unsafe_operation)) + "\n")
            for monitoring_option in monitoring_options_per_unsafe_operation[unsafe_operation]:
                monitoring_points = monitoring_option.get_monitoring_points()
                monitor_type = monitoring_option.get_monitor_type()
                all_monitored_unsafe_operations.add(unsafe_operation)
                if (unsafe_operation, monitor_type) in nodes_realized_type_dict:
                    monitor_type_file.write(
                        str(nodes_realized_type_dict[(unsafe_operation, monitor_type)]) + " ")
                else:
                    monitor_type_file.write(str(monitor_type.value) + " ")

                monitor_type_file.write("\n")
                # Write the monitoring points info
                for monitoring_point in monitoring_points:
                    # print("\t \t Monitoring point:", monitoring_point)
                    all_monitoring_points_seen.add(monitoring_point)
                    tes_file.write(str(relevant_ordered_attack_graph_node_ids.index(
                        monitoring_point)) + " ")
                tes_file.write("\n")
                # Accuracy
                accuracy_file.write(
                    str(monitoring_option.get_accuracy()) + "\n")

    monitor_type_file.close()
    accuracy_file.close()

    # Targets - unsafe ops info
    with open(program_name + "_tgroup.txt", "w") as target_group_file:
        # Iterate over each actual target
        for target in relevant_unsafe_operations_which_can_be_monitored_per_target.keys():
            # print("Unsafe operations :",
            #       relevant_unsafe_operations_which_can_be_monitored_per_target[target])
            for unsafe_operation in relevant_unsafe_operations_which_can_be_monitored_per_target[target]:
                unsafe_operation_pos = unsafe_operations_to_be_monitored.index(
                    unsafe_operation)
                target_group_file.write(str(unsafe_operation_pos) + " ")
            # Write the detection threshold per target
            target_group_file.write(
                str(PROBABILITY_OF_DETECTION_MINIMUM_THRESHOLD))
            target_group_file.write("\n")

    print("# Unique unsafe operations which can be monitored:",
          len(all_monitored_unsafe_operations))
    print("# Unique monitoring points :",
          len(all_monitoring_points_seen), len(relevant_ordered_attack_graph_node_ids))

    # Write the target weights into another file
    with open(program_name + "_tw.txt", "w") as tw_file:
        for target_weight in target_weights.keys():
            # Target weight
            tw_file.write(str(target_weights[target_weight]) + "\n")

    # New file for per object constraint (Each line multiple unsafe operations which correspond to same object). We care only if there are at least 2 unsafe operations which correspond to same object
    driver = get_db_driver()

    # For each unsafe object finding common unsafe operations will effective lead to multiple constraints enforcing the correct groups
    obj_to_unsafe_op = {}
    with driver.session() as session:
        result = session.run(
            "MATCH (obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(mp:MP) WHERE mp.program_name=$program_name RETURN DISTINCT obj.id as objID,mp.id as mpID ORDER BY obj.id",
            program_name=program_name)
        for record in result:
            objID = str(record["objID"])
            mpID = str(record["mpID"])
            if objID not in obj_to_unsafe_op:
                obj_to_unsafe_op[objID] = set()
            obj_to_unsafe_op[objID].add(mpID)

    # Write the groups to the new file
    with open(program_name + "_object.txt", "w") as obj_file:
        for obj_id in obj_to_unsafe_op:
            if len(obj_to_unsafe_op[obj_id])>1:
                for unsafe_op_id in obj_to_unsafe_op[obj_id]:
                        obj_file.write(str(relevant_ordered_attack_graph_node_ids.index(unsafe_op_id)) + " ")
                obj_file.write("\n") 


def compute_monitor_costs_and_sanity_checks():
    global _program_name
    program_name = _program_name
    # The costs should be modelled only for different monitor types. Therefore proc wall should be broken into types
    # This might become troublesome for a cheaper check if it varies per node. A principled approach should not though
    monitor_type_cost_dict = dict()
    # (node id, original monitor type) to realized type
    nodes_realized_type_dict = {}
    # Using cost analyses average cost per monitored operation
    monitor_type_cost_dict[MonitorType.ASAN.value]=get_cost_estimates(_program_name,MonitorOperations.Checks,MonitorType.ASAN)
    monitor_type_cost_dict[MonitorType.BBC.value]=get_cost_estimates(_program_name,MonitorOperations.Checks,MonitorType.BBC)

    return monitor_type_cost_dict, nodes_realized_type_dict


def read_accuracy_info():
    global accuracy_per_monitor_type
    unsafe_operations = fetch_relevant_unsafe_operations()
    for monitor_type in currentMonitorsFixedOrder:
        accuracy_per_monitor_type[monitor_type] = {}

    # TODO Update this
    for unsafe_operation_id in unsafe_operations:
        for monitor_type in currentMonitorsFixedOrder:
            # Ignoring intra object overflow for now
            accuracy = 1
            if ASAP_MODE:
                accuracy = 0
            # WP is possible
            if monitor_type == MonitorType.ASAN:
                # For Baggy only
                if BAGGY_ONLY_MODE:
                    accuracy=0
                # elif get_offset_for_action(unsafe_operation_id) <= REDZONE_SIZE:
                #     # reachable_actions = get_number_of_reachable_attack_actions(unsafe_operation_id)
                #     # print("\t Reachable actions:",str(reachable_actions))
                #     accuracy = 0.9
                else:
                    # accuracy = 1 - (reachable_actions / total_actions)
                    accuracy = 0.8
            accuracy_per_monitor_type[monitor_type][unsafe_operation_id] = accuracy


def gen_ids():
    # IMPORTANT - We need the ids to be in the same order to correlate (We rely on the DB query returning the same order)
    relevant_ag_ids = []
    # Fetch monitoring points in order
    monitoring_points = fetch_all_monitoring_points_in_order()
    for operation_id in monitoring_points:
        relevant_ag_ids.append(operation_id)
    print("# Relevant node (ids)", len(relevant_ag_ids))
    return relevant_ag_ids


def abort_on_error(message):
    print(message)
    exit(0)


# Pure DB utility functions. Simple parameterized queries


# Fetch unsafe operations, order by id if specified
def fetch_relevant_unsafe_operations(ordered=True):
    global all_relevant_unsafe_operations
    # if (not ordered) and all_relevant_unsafe_operations:
    #     return list(all_relevant_unsafe_operations)
    program_name = _program_name
    driver = get_db_driver()
    upas = []
    # TODO - Lib calls etc, we cannot handle for now so we use a hacky approach to ignore them.
    with driver.session() as session:
        if IGNORE_NUMBER_OF_TARGETS:
            result = session.run(
            "MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.type=$type  AND (a.action_type=$action_type OR a.action_type=$oob_read_type) AND a.program_name=$program_name  RETURN (a.id) as  actionID ORDER BY a.id",
            type=ATTACK_ACTION_NT, action_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, oob_read_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE,
            program_name=program_name)    
        else:
            result = session.run(
                "MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.type=$type  AND (a.action_type=$action_type OR a.action_type=$oob_read_type) AND a.program_name=$program_name AND (a)-[:EDGE]->(:AttackGraphNode) RETURN (a.id) as  actionID ORDER BY a.id",
                type=ATTACK_ACTION_NT, action_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, oob_read_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE,
                program_name=program_name)
        for record in result:
            action_id = str(record["actionID"])
            upas.append(action_id)
    if not all_relevant_unsafe_operations:
        all_relevant_unsafe_operations = set(upas)
    return upas

def find_all_relevant_md_operations():
    global ordered_unsafe_object_ids 
    global unsafe_object_to_func 
    global func_to_unsafe_objects
    global md_frequency_info
    if not ordered_unsafe_object_ids:
        driver=get_db_driver()
        # First fetch all md operations (for unsafe ops with targets) ORDERED, compute unsafe object to function mapping
        with driver.session() as session:   
            result = session.run(
                    "MATCH (p:ProgramInstruction)<-[:EDGE]-(obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(mp:MP) WHERE mp.program_name=obj.program_name=$program_name  AND obj.state_type=$unsafe_object_type RETURN DISTINCT obj.id as objID, p.function_name as function_name ORDER BY obj.id",
                    program_name=_program_name,unsafe_object_type=UNSAFE_STACK_OBJECT)
            for record in result:
                function_name=str(record["function_name"])
                obj_id=str(record["objID"])
                ordered_unsafe_object_ids.append(obj_id)
                unsafe_object_to_func[obj_id]=function_name
                if function_name in func_to_unsafe_objects:
                    obj_count=func_to_unsafe_objects[function_name]+1
                else:
                    obj_count=1        
                func_to_unsafe_objects[function_name]=obj_count

        # Fetch freq info
        for func_name in  func_to_unsafe_objects:   
            freq = 0
            func_label=""
            with driver.session() as session:
                result = session.run( "MATCH (func:Entry) WHERE func.function_name=$function_name AND func.program_name=$program_name RETURN func.label as label,func.count_ref as count ORDER BY func.label", 
                                    program_name=_program_name,function_name=func_name)
                for record in result:
                    func_label=str(record["label"])
                    if record["count"]:
                        freq=int(record["count"])
                    else:
                        freq = 0
                        print("Function freq not present",func_name)   
            if not func_label:
                print("No entry node for func:",func_name)            
            func_to_labels[func_name]=func_label     
            md_frequency_info[func_name]=freq    

     

def find_and_annotate_monitoring_points():
    global unsafe_operations_to_monitor_type_to_monitoring_points
    all_monitoring_points = set()
    driver = get_db_driver()
    program_name = _program_name

    # First - find check monitoring points
    for unsafe_operation in unsafe_operations_to_monitor_type_to_monitoring_points:
        for monitor_type in unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation]:
            if monitor_type == MonitorType.ASAN:
                unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation][monitor_type].add(
                    unsafe_operation)
                all_monitoring_points.add(unsafe_operation)
            elif monitor_type == MonitorType.BBC:
                for gep_op in get_preceeding_geps(unsafe_operation):
                    unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation][monitor_type].add(
                        gep_op)
                    all_monitoring_points.add(gep_op)

    #  Clear any previous placement
    with driver.session() as session:
        session.run(
            "MATCH (mp:MP) WHERE mp.program_name=$program_name REMOVE mp:" +
            MONITORING_POINT_NODE_LABEL,
            program_name=program_name)

    # Annotate all checks as MPs (SETTING MP LABEL). Let's leave objs as is. Maybe annotate with something else???
    with driver.session() as session:
        for monitoring_point in all_monitoring_points:
            session.run(
                "MATCH (mp:AttackGraphNode) WHERE mp.id=$mp_id SET mp:" +
                MONITORING_POINT_NODE_LABEL,
                mp_id=monitoring_point)

    # MD operations - are identified using the annotated checks (so we don't annotate) and objects are common (Is this always true?)
    global unsafe_object_to_func
    global func_to_labels
    find_all_relevant_md_operations()

    # Model relevant metatadata (stack objs) as monitoring points for each relevant unsafe operation
    for unsafe_operation in unsafe_operations_to_monitor_type_to_monitoring_points:
        for monitor_type in unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation]:
            # TODO - CHECK IF MP common for both defenses and across unsafe operations is problematic
            if monitor_type == MonitorType.ASAN:
                # Find unsafe object(s) corresponding to this unsafe operation
                with driver.session() as session:
                    result = session.run(
                        "MATCH (obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(mp:MP) WHERE mp.program_name=$program_name AND mp.id=$mp_id RETURN DISTINCT obj.id as objID ORDER BY obj.id",
                        program_name=program_name, mp_id=unsafe_operation)
                    for record in result:
                        objID = str(record["objID"])
                        objID=func_to_labels[unsafe_object_to_func[objID]]
                        unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation][monitor_type].add(
                            objID)
            elif monitor_type == MonitorType.BBC:
                # Find unsafe object(s) corresponding to this unsafe operation
                with driver.session() as session:
                    result = session.run(
                        "MATCH (obj:AttackGraphNode)-[:SOURCE]->(mp:MP)-[:EDGE]->(unsafeOp:AttackGraphNode) WHERE mp.program_name=$program_name AND unsafeOp.id=$mp_id RETURN DISTINCT obj.id as objID ORDER BY obj.id",
                        program_name=program_name, mp_id=unsafe_operation)
                    for record in result:
                        objID = str(record["objID"])
                        objID=func_to_labels[unsafe_object_to_func[objID]]
                        objID = "BAGGY_"+objID
                        unsafe_operations_to_monitor_type_to_monitoring_points[unsafe_operation][monitor_type].add(
                            objID)

    print("All check monitoring points annotated/found for ",
          len(all_monitoring_points))


def fetch_all_monitoring_points_in_order():
    program_name = _program_name
    driver = get_db_driver()
    monitoringPoints = []
    # Current order all checks ordered by ID first (no duplicates ensured since distinct checks)
    with driver.session() as session:
        result = session.run(
            "MATCH (mp:MP) WHERE mp.program_name=$program_name RETURN DISTINCT mp.id as mpID ORDER BY mp.id",
            program_name=program_name)
        for record in result:
            mpID = str(record["mpID"])
            monitoringPoints.append(mpID)

    global unsafe_object_to_func
    global func_to_labels
    find_all_relevant_md_operations()

    # Then ASAN objs/metadata ordered by ID followed by baggy
    # Both monitors in this case have the same unsafe objects but different operations so we use a hack to separate them instead of relying on object id
    for monitor_type in currentMonitorsFixedOrder:
        # For ASAN and Baggy these queries without specifying the monitor is sufficient. However, more robust and extensible would be to specify monitor
        if monitor_type == MonitorType.ASAN:
            with driver.session() as session:
                result = session.run(
                    "MATCH (obj:AttackGraphNode)-[:SOURCE]->(:AttackGraphNode)-[:EDGE]->(mp:MP) WHERE mp.program_name=$program_name RETURN DISTINCT obj.id as objID ORDER BY obj.id",
                    program_name=program_name)
                for record in result:
                    objID = str(record["objID"])
                    objID=func_to_labels[unsafe_object_to_func[objID]]
                    if objID not in monitoringPoints:
                        monitoringPoints.append(objID)

        elif monitor_type == MonitorType.BBC:
            # Find unsafe object(s) corresponding to this unsafe operation
            with driver.session() as session:
                result = session.run(
                    "MATCH (obj:AttackGraphNode)-[:SOURCE]->(mp:MP) WHERE mp.program_name=$program_name RETURN DISTINCT obj.id as objID ORDER BY obj.id",
                    program_name=program_name)
                for record in result:
                    objID = str(record["objID"])
                    objID=func_to_labels[unsafe_object_to_func[objID]]
                    objID = "BAGGY_"+objID
                    if objID not in monitoringPoints:
                        monitoringPoints.append(objID)

    return monitoringPoints


def fetch_targets(states=False, sub_type=SYS_CALL_ATTACK_ACTION_TYPE):
    program_name = _program_name
    driver = get_db_driver()
    goals = []

    if IGNORE_NUMBER_OF_TARGETS:
        for unsafe_op in fetch_relevant_unsafe_operations():
            goals.append(FAUX_TARGET_LABEL+unsafe_op)
        return goals
    if states:
        node_type = ATTACK_STATE_NT
        query_string = "MATCH (a:AttackGraphNode) WHERE a.type=$type  AND a.state_type=$sub_type AND a.program_name=$program_name  RETURN (a.id) as  ID ORDER BY a.id"
    else:
        node_type = ATTACK_ACTION_NT
        query_string = "MATCH (a:AttackGraphNode) WHERE a.type=$type  AND a.action_type=$sub_type AND a.program_name=$program_name  RETURN (a.id) as  ID"
    if isinstance(sub_type, str):
        # Make it both categories
        with driver.session() as session:
            result = session.run(query_string, type=node_type,
                                 sub_type=sub_type, program_name=program_name)
            for record in result:
                node_id = str(record["ID"])
                goals.append(node_id)
    else:
        for a_type in sub_type:
            # Make it both categories
            with driver.session() as session:
                result = session.run(
                    query_string, type=node_type, sub_type=a_type, program_name=program_name)
                for record in result:
                    node_id = str(record["ID"])
                    goals.append(node_id)

    return goals


def get_preceeding_actions(attack_graph_node_id):
    # First check cache
    if attack_graph_node_id in preceeding_nodes_cache.keys():
        prev_nodes = preceeding_nodes_cache[attack_graph_node_id]
        # print("Cache hit", prev_nodes)
        return list(prev_nodes)

    prev_nodes = set()
    program_name = _program_name
    driver = get_db_driver()
    with driver.session() as session:
        results = session.run(
            "MATCH (a:AttackGraphNode)-[:EDGE]->(c:AttackGraphNode) WHERE c.id=$id AND a.program_name=c.program_name=$program_name  AND a.type=$action_type  RETURN DISTINCT (a.id) as attackGraphNodeID",
            id=attack_graph_node_id, action_type=ATTACK_ACTION_NT, program_name=program_name)

        for record in results:
            node_id = str(record["attackGraphNodeID"])
            prev_nodes.add(node_id)

    # Insert into cache
    # print("Cache miss:", prev_nodes)
    preceeding_nodes_cache[attack_graph_node_id] = prev_nodes
    return list(prev_nodes)


def get_preceeding_geps(attack_graph_node_id):
    #  # First check cache
    if attack_graph_node_id in preceeding_nodes_cache.keys():
        prev_nodes = preceeding_nodes_cache[attack_graph_node_id]
        # print("Cache hit", prev_nodes)
        return prev_nodes

    driver = get_db_driver()
    # Fetch all geps preceeding an unsafe operation in a single query

    with driver.session() as session:
        results = session.run(
            "MATCH (a:AttackGraphNode)-[:EDGE]->(c:AttackGraphNode) WHERE c.id=$action_id AND a.type=$node_type AND a.state_type=$state_type  RETURN DISTINCT (a.id) as prevNodeID",
            action_id=attack_graph_node_id, node_type=ATTACK_STATE_NT, state_type=UNSAFE_POINTER_STATE_TYPE)
        for record in results:
            curr_node_id = attack_graph_node_id
            if curr_node_id in preceeding_nodes_cache:
                prev_nodes = preceeding_nodes_cache[curr_node_id]
            else:
                prev_nodes = set()
            prev_node_id = str(record["prevNodeID"])
            prev_nodes.add(prev_node_id)
            preceeding_nodes_cache[curr_node_id] = prev_nodes

    if attack_graph_node_id not in preceeding_nodes_cache:
        return 

    return preceeding_nodes_cache[attack_graph_node_id]


def get_offset_for_action(action_id):
    # prev_nodes = set()
    program_name = _program_name
    driver = get_db_driver()
    offset = REDZONE_SIZE+1
    with driver.session() as session:
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
    return offset


def fetch_unsafe_operations_impacted_objects_and_uses(unsafe_operations):
    # Unsafe op (ID) to impacted obj type to obj id
    unsafe_op_to_impacted_obj = {}
    # Impacted obj to use type to count
    impacted_obj_to_uses_count = {}
    impacted_objs = set()
    program_name = _program_name
    driver = get_db_driver()
    offset = None
    with driver.session() as session:
        # Step 1 - For each unsafe op fetch impacted obj  (data obj or ptr)
        for unsafe_operation in unsafe_operations:
            unsafe_op_to_impacted_obj[unsafe_operation] = {}
            unsafe_op_to_impacted_obj[unsafe_operation][IMPACTED_STACK_POINTER] = set(
            )
            unsafe_op_to_impacted_obj[unsafe_operation][IMPACTED_STACK_OBJECT] = set(
            )
            results = session.run(
                "MATCH (upa:AttackGraphNode)-[:EDGE]->(impactedObj:AttackGraphNode) WHERE upa.id=$id AND upa.program_name=impactedObj.program_name=$program_name  AND (impactedObj.state_type=$impacted_data_obj_type OR impactedObj.state_type=$impacted_ptr_obj_type)  RETURN DISTINCT (impactedObj.id) as impactedObjID, impactedObj.state_type as type",
                id=unsafe_operation, impacted_data_obj_type=IMPACTED_STACK_OBJECT,
                impacted_ptr_obj_type=IMPACTED_STACK_POINTER, program_name=program_name)

            for record in results:
                node_id = str(record["impactedObjID"])
                impactedObjType = str(record["type"])
                # if  impactedObjType==IMPACTED_STACK_POINTER:
                #     # Impacted obj to number of uses
                unsafe_op_to_impacted_obj[unsafe_operation][impactedObjType].add(
                    node_id)
                impacted_objs.add(node_id)

    # Step 2 - Fetch all uses of all impacted objects
    with driver.session() as session:
        for obj in impacted_objs:
            impacted_obj_to_uses_count[obj] = {}
            results = session.run(
                "MATCH (impactedObj:AttackGraphNode)-[:EDGE]->(use:AttackGraphNode) WHERE impactedObj.id=$id AND use.program_name=impactedObj.program_name=$program_name   RETURN COUNT(DISTINCT use) as count, use.action_type as use_type ",
                id=obj, impacted_data_obj_type=IMPACTED_STACK_OBJECT, impacted_ptr_obj_type=IMPACTED_STACK_POINTER,
                program_name=program_name)

            for record in results:
                count = int(record["count"])
                use_type = str(record["use_type"])
                # if  impactedObjType==IMPACTED_STACK_POINTER:
                #     # Impacted obj to number of uses
                impacted_obj_to_uses_count[obj][use_type] = count

    return unsafe_op_to_impacted_obj, impacted_obj_to_uses_count




if __name__ == "__main__":
    print("Enter program name:")
    _program_name = input()
    generate_monitoring_info()
