from neo4j import GraphDatabase

program_name=None

DELIMITER=":"

def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(uri, auth=("neo4j", "secret"), encrypted=False)
    return driver

# Function to read from a file
def read_from_file(file_path):
    try:
        mp_id_monitor_data={}
        with open(file_path, 'r') as file:
            data=file.readline()
            while data  :
                mp_id,monitor= data.split(DELIMITER)
                monitor=monitor.removesuffix("\n")
                # print(mp_id,monitor)
                mp_id_monitor_data[mp_id]=monitor
                data=file.readline()

        return mp_id_monitor_data
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

# Function to write to a text file
def write_to_file(file_path, content):
    try:
        with open(file_path, 'w') as file:
            for line in content:
                file.write(line + '\n')
        print(f"Data written to '{file_path}' successfully")
    except Exception as e:
        print(f"Error: {e}")


def save_current_placement():
    global driver
    mp_id_monitor_data=[]
    with driver.session() as session:
        result = session.run(
            "MATCH (node:MP) WHERE  node.program_name=$program_name AND EXISTS(node.monitor)  RETURN node.id as id, node.monitor as monitor ORDER BY node.id",
            program_name=program_name)

        for record in result:
            node_id = str(record["id"])
            monitor = str(record["monitor"])

            mp_id_monitor_data.append(node_id+DELIMITER+monitor)

    write_to_file(program_name+"_placement.txt",mp_id_monitor_data)


def restore_placement():
    global driver
    file_name=str(input("Enter placement file name:"))
    mp_id_monitor_data= read_from_file(file_name)
    with driver.session() as session:
            result = session.run(
                "MATCH (node:MP) WHERE  node.program_name=$program_name  AND EXISTS(node.monitor) REMOVE node.monitor",
                program_name=program_name)
    print("# MPs (from file) :",len(mp_id_monitor_data))
    for mp_id in mp_id_monitor_data:
          with driver.session() as session:
            result = session.run(
                "MATCH (node:MP) WHERE  node.id=$mp_id  SET node.monitor=$monitor RETURN node.id as id, node.monitor as monitor",
                mp_id=mp_id,monitor=mp_id_monitor_data[mp_id])

            for record in result:
                node_id = str(record["id"])
                monitor = str(record["monitor"])
                assert node_id==mp_id
                assert monitor == mp_id_monitor_data[mp_id]
    return



program_name=str(input("Enter program name:"))
driver=get_db_driver()
restore_placement()
# save_current_placement()



