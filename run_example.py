from neo4j import GraphDatabase

LLVM_BIN_DIR="/opt/llvm-project/llvm-build/bin/"
LLVM_OPT_10 = "/opt/llvm-project/llvm-build/bin/opt"

import os
import subprocess
import scripts.monitoring_info_driver_example as monitoring_info

current_dir=None

def get_pwd():
    global current_dir
    current_dir=os.getcwd()
    
def get_db_driver():
    uri = "bolt://localhost:7687"
    driver = GraphDatabase.driver(
        uri, auth=("neo4j", "secret"), encrypted=False)
    return driver
    
def check_file_exists(file_path):
    return os.path.exists(file_path)    


def setup_end():
    subprocess.run(["source","./optisan_bash_aliases"])
    subprocess.run(["source","./optisan_bash_aliases"])


def setup_db_indexes():
    driver=get_db_driver()
    with driver.session() as session:
        session.run(
            "CALL db.createIndex($first,$second)",first=":ProgramInstruction(instruction)",second="lucene+native-1.0")
        session.run(
            "CREATE CONSTRAINT on (a:AttackGraphNode) ASSERT a.id is UNIQUE")        
        session.run("CREATE CONSTRAINT on (p:ProgramInstruction) ASSERT p.label is UNIQUE")        
    return

def run_pass_to_compute_unsafe_operations():
    subprocess.run([LLVM_OPT_10, "-load", "./SecurityImpactAnalysis/ValueRangeAnalysis/libNesCheck.so" , "-nescheck",
                        "./example/xmllint"  + ".bc", "-o", "/dev/null"], check=False,capture_output=False)
    subprocess.run([LLVM_OPT_10, "-load", "./Utilities/libDebugModulePass.so" , "-dbgid",
                        "./example/xmllint"  + ".bc", "-o", "/dev/null"], check=False,capture_output=False)
    subprocess.run([LLVM_OPT_10, "-load", "./SecurityImpactAnalysis/libUnsafeMemoryOperationsAnalysis.so" , "-compute-actions",
                    "./example/xmllint"  + ".bc", "-o", "/dev/null"], check=False,capture_output=False)
    subprocess.run([LLVM_OPT_10, "-load", "./Utilities/libDebugModulePass.so" , "-dbgid","-mem"
                        "./example/xmllint"  + ".bc", "-o", "/dev/null"], check=False,capture_output=False)
    return


def run_pass_to_compute_usable_targets():
    subprocess.run([LLVM_OPT_10, "-load", "./SecurityImpactAnalysis/libSecurityImpactAnalysis.so" , "-compute-usable-targets",
                    "./example/xmllint"  + ".bc", "-o", "/dev/null"], check=False,capture_output=False)
    return    


def test_usable_target_analysis():
    print("     Computing usable targets, first need to compute unsafe operations using VR from prior work")
    # 40 VR, 15 DBG ID, 40 Unsafe op, DBG ID  3, Target computaiton - 4hours
    print("     ETA: 360 minutes")
    # Computing unsafe operations is 40 minutes but for demo uncessary
    run_pass_to_compute_unsafe_operations()
    run_pass_to_compute_usable_targets()





def test_cost_estimation():
    print("Demonstrating Cost Estimation - ASan Check Cost")
    subprocess.run("./example/build_example_asan.sh")
    # print("Demonstrating how we save")
    # # Demonstrating the pass
    # Saving the execution profile in db
    monitoring_info.generate_monitoring_options_and_weights()
    # subprocess.run([LLVM_OPT_10, "-load", "./CostEstimation/libCostEstimationPass.so" , "-estimate-cost","-cov",
    #                 "./example/xmllint"  + ".profile.bc", "-o", "/dev/null"], check=False,capture_output=False)


def compute_defense_placement():
    print("Testing input generation for solver")
    monitoring_info.set_program_name("./example/xmllint")
    monitoring_info.generate_monitoring_info()
    print("Testing solver, after matlab is invoked please run max_profit_main.m")
    subprocess.run(["matlab","-nodisplay","-nosplash","-nodesktop"])


def test_instrumentation():
    subprocess.run("./example/build_example_place.sh")


def run_example():
    # Step 1 - Unsafe operations and Targets computation
    # print("Component 1 - Unsafe operations and Usable Targets computation - Testing the LLVM Passes")
    test_usable_target_analysis()
    # print("Component 2 - Cost Estimation ")
    test_cost_estimation()
    print("Component 3 - Protection Budget Problem - Solver")
    compute_defense_placement()    
    print("Component 4 - Instrumentation")
    test_instrumentation()

if __name__ == "__main__":
    run_example()
