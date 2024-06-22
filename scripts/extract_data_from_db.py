import subprocess,os
from neo4j import GraphDatabase


driver=None
# programs=["605.mcf_s","641.leela_s","657.xz_s","631.deepsjeng_s","625.x264_s","600.perlbench_s","619.lbm_s","644.nab_s","510.parest_r","511.povray_r"]
programs=["xmllint"]

EXTRACT_ALL_DATA=False

def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(uri, auth=("neo4j", "secret"), encrypted=False)
    return driver

def extract_pdg_nodes_csv(program_name):
    statement="MATCH (p1:ProgramInstruction) WHERE p1.program_name=$program_name WITH collect(DISTINCT p1) as export_nodes CALL apoc.export.csv.data(export_nodes,[],$csv_file_name,{}) YIELD file, source, format, nodes, properties, time RETURN nodes, time;"
    with driver.session() as session:
        results=session.run(statement,program_name=program_name,csv_file_name=program_name+str("_nodes.csv")) 
        # print(results)   
    return 

def extract_pdg_rels_csv():
    return 

def extract_ag_nodes(program_name):
    statement=" MATCH (a:AttackGraphNode) WHERE a.program_name=$program_name WITH collect(DISTINCT a) as export_nodes CALL apoc.export.csv.data(export_nodes,[],$csv_file_name,{}) YIELD file, source, format, nodes, properties, time RETURN nodes, time;"
    with driver.session() as session:
        result=session.run(statement,program_name=program_name,csv_file_name=program_name+"_ag_nodes.csv")
        # print(result)
    return   


def extract_ag_pdg_relationships(program_name):
    
    new_statement=""" CALL apoc.export.csv.query("MATCH (a:AttackGraphNode)-[r:EDGE]->(p1:ProgramInstruction) WHERE a.program_name=p1.program_name='%s' RETURN a.id AS source, p1.label AS dest", $csv_file_name,{}) 
    """
    new_statement=new_statement%(program_name)
    print(new_statement)
    with driver.session() as session:
        # query_res=session.run(query_str,program_name=program_name)
        result=session.run(new_statement,csv_file_name=program_name+"_ag_rels.csv")
        print(result)
    return   


def annotate_actions_asan(program_name):
    statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.type=$type AND a.program_name=p.program_name=$program_name SET a.monitor=$monitor_type";
    mp_statement = " MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.type=$type AND a.program_name=p.program_name=$program_name SET a:MP";

    with driver.session() as session:
        result=session.run(statement,program_name=program_name,type="AttackAction",monitor_type="ASAN")
        print(result)
        session.run(mp_statement,program_name=program_name,type="AttackAction",monitor_type="ASAN")
    return       

def create_func_entry_nodes(program_name):
    statement="MATCH (a:AttackGraphNode)-[:EDGE]->(p:ProgramInstruction) WHERE a.type=$type AND a.program_name=p.program_name=$program_name WITH DISTINCT p MERGE (p1:Entry{ program_name:$program_name, instruction:$instruction, function_name:p.function_name}) ON CREATE SET p1.label=randomUUID() RETURN COUNT(DISTINCT p1) as count";

    with driver.session() as session:
        result=session.run(statement,program_name=program_name,type="AttackAction",instruction="ENTRY:")
        print(result)
        for record in result:
            print(record["count"])

def annotate_asan_programs():
    for program in programs:
        print("Program:",program)
        create_func_entry_nodes(program)
        annotate_actions_asan(program)




def extract_ag_ag_relationships(program_name):
    
    new_statement=""" CALL apoc.export.csv.query("MATCH (obj:AttackGraphNode)-[r:SOURCE]->(a:AttackGraphNode) WHERE a.program_name=obj.program_name='%s' RETURN obj.id AS source, a.id AS dest", $csv_file_name,{}) 
    """
    new_statement=new_statement%(program_name)
    print(new_statement)
    with driver.session() as session:
        # query_res=session.run(query_str,program_name=program_name)
        result=session.run(new_statement,csv_file_name=program_name+"_rels.csv")
        print(result)
    return    

def extract_data_for_program():
    for program in programs:
        print("Program:",program)
        # Extract pdg nodes
        extract_pdg_nodes_csv(program)
        # if EXTRACT_ALL_DATA:
        #     extract_pdg_rels_csv()
        # Extract ag nodes
        extract_ag_nodes(program)
        # Extract ag relationships
        extract_ag_ag_relationships(program)
        extract_ag_ag_relationships(program)
        # break




def import_ag_ag_edges(program_name):
    csv_file=f"file:///{program_name}_rels.csv"

    statement="LOAD CSV WITH HEADERS FROM $csv_file  AS row WITH row MATCH (obj:AttackGraphNode) WHERE obj.id=row.source WITH obj MATCH (a:AttackGraphNode) WHERE a.id=row.dest MERGE ((obj)-[r:SOURCE]->(a)) RETURN COUNT(DISTINCT r);"
    with driver.session() as session:
        result=session.run(statement,csv_file=csv_file)
        print(result)
    return    

def import_data():
    for program in programs:
        print("Program:",program)
        import_ag_ag_edges(program)
     

if __name__ == "__main__":
    driver=get_db_driver()
    extract_data_for_program()
    # import_data()
