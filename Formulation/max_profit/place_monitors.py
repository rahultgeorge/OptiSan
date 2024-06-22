"""
     Annotate nodes which need to be monitored

"""


from neo4j import GraphDatabase
import sys
from enum import Enum


driver = None
program_name = None
UNSAFE_STACK_OBJECT = "6"


# Must maintain order for correlation as was done during generation
# Metadata operations related data structures
ordered_unsafe_object_ids = []
unsafe_object_to_func = {}    
func_to_unsafe_objects={}
func_to_labels={}
md_frequency_info={}


class MonitorType(Enum):
    # Baggy bounds
    BBC = 1
    # Address sanitizer
    ASAN = 2

currentMonitorsFixedOrder = [MonitorType.ASAN, MonitorType.BBC]

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
                    program_name=program_name,unsafe_object_type=UNSAFE_STACK_OBJECT)
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
                                    program_name=program_name,function_name=func_name)
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

     

def fetch_all_monitoring_points_in_order():
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





def clear_prev_annotations():
    with driver.session() as session:
        session.run(
            "MATCH (node:AttackGraphNode) WHERE  node.program_name=$program_name  AND EXISTS (node.monitor) REMOVE node.monitor",
            program_name=program_name)


# 1 is Baggy and 2 is ASAN (as declared in monitoring constants (Not very robust I know-share ds later))
def annotate_nodes():
    mp_ids = fetch_all_monitoring_points_in_order()
    print("# MPs fetched (must corrlate exactly):",len(mp_ids))
    # Read the file
    with open("result_placement.txt", "r") as results_file:
        node_mon_type_info = results_file.readline()
        while node_mon_type_info:
            node_id_pos, mon_type = node_mon_type_info.split()
            node_id_pos = int(node_id_pos)
            node_id = mp_ids[node_id_pos]
            # print(node_id_pos,node_id, mon_type)
            node_mon_type_info = results_file.readline()
            if mon_type == "1":
                mon_name = "BBC"
            elif mon_type == "2":
                mon_name = "ASAN"
            with driver.session() as session:
                session.run(
                    "MATCH (node:MP) WHERE  node.id=$node_id  SET node.monitor=$monitor_name",
                    node_id=node_id, monitor_name=mon_name)


def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(
        uri, auth=("neo4j", "secret"), encrypted=False)
    return driver


def abort_on_error(message):
    print(message)
    exit(0)


if __name__ == "__main__":
    driver = get_db_driver()
    program_name = str(sys.argv[1])
    clear_prev_annotations()
    annotate_nodes()




