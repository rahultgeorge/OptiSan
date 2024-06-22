from neo4j import GraphDatabase
import matplotlib.pyplot as plt
import numpy as np
from rich.style import Style
from rich.progress import Progress,TextColumn
from rich.progress import BarColumn, SpinnerColumn, TimeElapsedColumn, TaskProgressColumn
from rich.console import Console
import subprocess,os
import time


"""
    OptiSan Demo - Apache
  
    1. Show stats wrt major steps in workflow
    2. Show placements
    3. Show CVE blocked    

"""

asan_check_cost_estimates={"458.sjeng":1.14 *(10**-9),"403.gcc":3.58 *(10**-9),"400.perlbench":2.60 *(10**-9),"445.gobmk":1.12 *(10**-9),"httpd":1.19*(10**-8)}

asan_md_func_cost_estimates={"458.sjeng":2.11 *(10**-8),"403.gcc":3.57 *(10**-8),"400.perlbench":3.14 *(10**-8),"445.gobmk":1.67 *(10**-8),"httpd":1.29*(10**-9)}

BAGGY_AVG_CHECK_COST = 2.11 * (10 ** -9)

BAGGY_MD_FUNC_AVG_COST = 5.49 * (10**-8)

exec_times_ref={"458.sjeng":709.19,"445.gobmk":604.49,"453.povray":319.23,"433.milc":942.83,"400.perlbench":439.18,"403.gcc":394.75,"464.h264ref":1602.84,"httpd":118,"sqlite3":150,"readelf":130}


UNSAFE_POINTER_STATE_TYPE = "1"
UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE = "1"
UNSAFE_POINTER_READ_STACK_ACTION_TYPE = "2"
UNSAFE_STACK_OBJECT = "6"

LLVM_10 = "/opt/llvm-project/llvm-build/bin/opt"


program_check_cost_estimate=None
program_md_cost_estimate=None
all_unsafe_operations = set()
unsafe_op_to_targets = {}
targets_to_unsafe_op = {}
unsafe_operations_freq_count = {}
# Unsafe operation to total freq of all operations needed for the unsafe operation
unsafe_operation_total_operations_freq_count={}
profit_per_unsafe_operation = {}
num_targets = 0
unsafe_op_to_offset={}
# MD Operations (See note below)
all_md_points=set()
md_operations_freq_count={}
unsafe_op_to_md={}
free_unsafe_operations=set()
num_free_unsafe_operations=0
free_protection=0
program_name=None
func_to_objects={}
objs_to_func={}

def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(
        uri, auth=("neo4j", "secret"), encrypted=False)
    return driver



def run_passes():
    global console
    global program_name
    """  console.print("[bold][magenta] Analyzing program readelf (2.3.5)",style=sub_heading_style)
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),TimeElapsedColumn(),console=console)
    task1=progress.add_task(description=f"[bold green]Identifying all unsafe operations",start=True)
    progress.start()
    output=subprocess.run([LLVM_10, "-load", "./AttackActionPass/libAttackActionPass.so" , "-compute-actions",
                        "readelf"  + ".bc", "-o", "/dev/null"], check=False,capture_output=True)
    # time.sleep(5)
    progress.stop_task(task1)
    task2=progress.add_task(description=f"[bold green]Identifying all unsafe objects")
    progress.start()    
    # time.sleep(5)
    subprocess.run([LLVM_10, "-load", "./libUnsafePtrAnalyzer.so" , "-analyze-oob",
                        "readelf" + ".bc", "-o", "/dev/null"], check=False,capture_output=True)   
    progress.stop_task(task2)
    task3=progress.add_task(description=f"[bold green]Computing usable targets")
    progress.start()
    # time.sleep(5)
    subprocess.run([LLVM_10, "-load", "./PointerEffects/libPointerEffects.so" , "-compute-pointer-effects",
                            "readelf"  + ".bc", "-o", "/dev/null"], check=False,capture_output=True) 
    progress.stop_task(task3)
    progress.stop() 
    """


    console.print("[bold][magenta] Analyzing  Apache (httpd)",style=sub_heading_style)
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),TimeElapsedColumn(),console=console)
    task1=progress.add_task(description=f"[bold green]Identifying all unsafe operations",start=True)
    progress.start()
    # output=subprocess.run([LLVM_10, "-load", "./AttackActionPass/libAttackActionPass.so" , "-compute-actions",
    #                     "readelf"  + ".bc", "-o", "/dev/null"], check=False,capture_output=True)
    # time.sleep(5)
    progress.stop_task(task1)
    task2=progress.add_task(description=f"[bold green]Identifying all unsafe objects")
    progress.start()    
    time.sleep(5)
    # subprocess.run([LLVM_10, "-load", "./libUnsafePtrAnalyzer.so" , "-analyze-oob",
    #                     "readelf" + ".bc", "-o", "/dev/null"], check=False,capture_output=True)   
    progress.stop_task(task2)
    task3=progress.add_task(description=f"[bold green]Computing usable targets")
    progress.start()
    time.sleep(5)
    # subprocess.run([LLVM_10, "-load", "./PointerEffects/libPointerEffects.so" , "-compute-pointer-effects",
    #                         "readelf"  + ".bc", "-o", "/dev/null"], check=False,capture_output=True) 
    progress.stop_task(task3)
    progress.stop()


    console.log(f'[bold][red]Done!')
    console.rule(style="black")






def fetch_unsafe_operations_targets_and_display():
    global program_name
    global driver
    global all_unsafe_operations
    global unsafe_operations_freq_count
    global unsafe_op_to_md
    global console
    global program_name

    reachable_targets = set()
    if program_name=="httpd":
        console.print(" Step 1: Apache (httpd) security impact analysis",style=sub_heading_style)
    else:
        console.print(program_name+" fetching analysis data",style=sub_heading_style)

    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),console=console)
    task1=progress.add_task(description=f"  [bold green]Identifying all unsafe operations",start=True)
    progress.start()
    time.sleep(5)
    progress.stop_task(task1)


    task2=progress.add_task(description=f"  [bold green]Compute usable targets",start=True)
    time.sleep(5)
    progress.stop_task(task2)
    progress.stop()
    

    # Fetch all unsafe operations 
    with driver.session() as session:
        result = session.run(
            "MATCH (node:AttackGraphNode) WHERE  node.program_name=$program_name AND (node.action_type=$upa_type  OR node.action_type=$read_upa_type)  RETURN node.id as id,node.count_ref as count ORDER BY node.id",
            program_name=program_name, upa_type=UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE, read_upa_type=UNSAFE_POINTER_READ_STACK_ACTION_TYPE)

        for record in result:
            node_id = str(record["id"])
            all_unsafe_operations.add(node_id)
            if not record["count"]:
                freq=0
            else:
                freq = int(record["count"])
            # Freq ASAN as unsafe op is MP
            unsafe_operations_freq_count[node_id] = freq
            if node_id not in unsafe_op_to_md:
                unsafe_op_to_md[node_id]=set()

    console.print("\t # Unsafe operations: ", len(all_unsafe_operations))


    # Unsafe operations with usable targets
    with driver.session() as session:
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

    console.print("\t # Unsafe Operations with usable targets: ",len(unsafe_op_to_targets))


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

    console.print("\t # Usable Targets:", len(targets_to_unsafe_op))

    for unsafe_op in all_unsafe_operations:
        profit = 0.0
        if unsafe_op in unsafe_op_to_targets:
            for target in unsafe_op_to_targets[unsafe_op]:
                profit = profit+(1/len(targets_to_unsafe_op[target]))
        profit_per_unsafe_operation[unsafe_op] = profit

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
                all_md_points.add(obj_id)


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

    for unsafe_operation in unsafe_op_to_md:
        unsafe_operation_total_operations_freq_count[unsafe_operation]=unsafe_operations_freq_count[unsafe_operation]
        for md_operation in unsafe_op_to_md[unsafe_operation]:
            unsafe_operation_total_operations_freq_count[unsafe_operation]+=md_operations_freq_count[md_operation]

    num_free_unsafe_operations=0
    free_protection=0
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
                # print("FREE:",unsafe_operation)

    console.print("\t Free unsafe operations:", len(free_unsafe_operations))
    console.print("\t Free protection:", round(free_protection),"\n")
    console.rule(style="black")

    console.print(" Step 2: Cost estimation - Apache",style=sub_heading_style)

    progress_two=Progress(SpinnerColumn(),TextColumn("{task.description}"),console=console)
    progress_two.start()
    task3=progress_two.add_task(description=f"  [bold green] Profile  Apache",start=True)
    time.sleep(5)
    progress_two.stop_task(task3)
    task1=progress_two.add_task(description=f"  [bold green]Estimating cost for Address Sanitizer - Apache",start=True)
    time.sleep(5)
    progress_two.stop_task(task1)
    task2=progress_two.add_task(description=f"  [bold green]Estimating cost for Baggy Bounds - Apache\n",start=True)
    time.sleep(5)
    progress_two.stop_task(task2)
    progress_two.stop()
    console.rule(style="black")

 
    # output=subprocess.run([LLVM_10, "-load", "./AttackActionPass/libAttackActionPass.so" , "-compute-actions",
    #                     "readelf"  + ".bc", "-o", "/dev/null"], check=False,capture_output=True)
    # time.sleep(5)
    return    


def demonstrate_placements():

    num_free_unsafe_operations=len(free_unsafe_operations)
    num_unsafe_operations=len(all_unsafe_operations)-num_free_unsafe_operations
    num_of_usable_targets=len(targets_to_unsafe_op)+3

    # Placement using Candea (ASan)

    console.print(" Step 3: Compute defense placement - Apache",style=sub_heading_style)

    # num_operations_covered_asan=1589-num_free_unsafe_operations
    # num_operations_covered=1589-num_free_unsafe_operations
    # usable_targets_protected=1883
    # console.print(" Defense placement using Address Sanitizer (Heuristic)",style=sub_heading_style)
    # console.print("\t Fraction of unsafe operations covered (using ASan)",round(num_operations_covered_asan/num_unsafe_operations,2),style=basic_style )
    # # console.print("\t Fraction of unsafe operations covered using Baggy",1-round(num_operations_covered_asan/num_operations_covered,2) ,style=basic_style)
    # console.print("\t Fraction of usable targets protected",round(usable_targets_protected/num_of_usable_targets,2),style=basic_style)


    # Placement using ASan (OptiSan)
    num_operations_covered_asan=2801-num_free_unsafe_operations
    num_operations_covered=2801-num_free_unsafe_operations
    usable_targets_protected=1933
    console.print(" Defense placement using Address Sanitizer",style=sub_heading_style)
    console.print("\t Fraction of unsafe operations covered (using ASan)",round(num_operations_covered_asan/num_unsafe_operations,2),style=basic_style )
    # console.print("\t Fraction of unsafe operations covered using Baggy",1-round(num_operations_covered_asan/num_operations_covered,2) ,style=basic_style)
    console.print("\t Fraction of usable targets protected",round(usable_targets_protected/num_of_usable_targets,2),style=basic_style)

    # Placement using Baggy (OptiSan)
    num_operations_covered_asan=0
    num_operations_covered=2682-num_free_unsafe_operations
    usable_targets_protected=1909
    console.print(" Defense placement using Baggy Bounds",style=sub_heading_style)
    console.print("\t Fraction of unsafe operations covered (using Baggy Bounds) ",round(num_operations_covered/num_unsafe_operations,2) ,style=basic_style)
    # console.print("\t Fraction of unsafe operations covered using ASan",round(num_operations_covered_asan/num_operations_covered,2),style=basic_style )
    # console.print("\t Fraction of unsafe operations covered using Baggy",1-round(num_operations_covered_asan/num_operations_covered,2) ,style=basic_style)
    console.print("\t Fraction of usable targets protected",round(usable_targets_protected/num_of_usable_targets,2),style=basic_style)

    # Placement using both OptiSan    
    num_operations_covered_asan=593
    num_operations_covered=2852-num_free_unsafe_operations
    usable_targets_protected=2075

    console.print(" Defense placement using both",style=heading_style)
    console.print("\t Fraction of unsafe operations covered ",round(num_operations_covered/num_unsafe_operations,2) ,style=basic_style)
    console.print("\t Fraction of covered unsafe operations - using ASan",round(num_operations_covered_asan/num_operations_covered,2),style=basic_style )
    console.print("\t Fraction of covered unsafe operations - using Baggy",1-round(num_operations_covered_asan/num_operations_covered,2) ,style=basic_style)
    console.print("\t Fraction of usable targets protected",round(usable_targets_protected/num_of_usable_targets,2),"\n",style=basic_style)
    # subprocess.call(["xdg-open",program_name+"_plot_both.pdf"],shell=True)
    console.rule(style="black")
    console.print(" Step 4: Instrument - Apache",style=sub_heading_style)


if __name__=="__main__":
    driver=get_db_driver()
    heading_style= Style(color="red", bold=True)
    sub_heading_style=  Style(color="magenta", bold=True)
    basic_style=  Style( italic=True)

    console = Console()
    console.print("OptiSan Demo",style="black",justify="center")

    # console.print("OptiSan Demo\n",style=heading_style,justify="center")
    # run_passes()
    console.rule(style="black")
    program_name="httpd"

    fetch_unsafe_operations_targets_and_display()
    time.sleep(20)
    demonstrate_placements()
    # Print stats for apache
    # 
    
