"""
        Constanst and DS related to the monitors/defenses
        
"""

from copy import deepcopy
from distutils.debug import DEBUG
from enum import Enum
from random import randint


# MONITORING SET - DETECTION THRESHOLD
PROBABILITY_OF_DETECTION_MINIMUM_THRESHOLD = 0
DEBUG = False
MONITORING_POINT_NODE_LABEL = "MP"
REDZONE_SIZE = 32
ASAN_ACCURACY = 0.8
ASAP_MODE = False
BAGGY_ONLY_MODE = False
IGNORE_NUMBER_OF_TARGETS = False
FAUX_TARGET_LABEL = "faux_target_"
ENTRY_NODE = "ENTRY:"
ENTRY_NODE_LABEL= "Entry"

class MonitorType(Enum):
    # Baggy bounds
    BBC = 1
    # Address sanitizer
    ASAN = 2
    EFSAN = 3
    PROC_WALL_MONITOR_TYPE = 4
    DYN_TAINT_MONITOR_TYPE = 5


class MonitorOperations(Enum):
    Checks = 1
    Metadata = 2


class MonitoringOption:
    unsafe_operation = None
    monitor_type = None
    monitoring_points = None
    accuracy = None

    def __init__(self):
        self.monitoring_points = set()

    def add_monitor(self, unsafe_operation, monitoring_points, monitor_type):
        self.unsafe_operation = unsafe_operation
        self.monitor_type = monitor_type
        self.monitoring_points = deepcopy(monitoring_points)

    def get_monitoring_points(self):
        return self.monitoring_points

    def get_monitor_type(self):
        return self.monitor_type

    def get_accuracy(self):
        return self.accuracy


# NEO4J NODE TYPE DEFINITIONS
    
    

PDG_NT = "ProgramInstruction"

ATTACK_SURFACE_NT = "AttackSurface"

ATTACK_STATE_NT = "AttackState"

ATTACK_ACTION_NT = "AttackAction"

# New Attack State types
INVALID_STATE_TYPE = "-1"
SYS_CALL_ATTACK_STATE_TYPE = "0"
# OOB
UNSAFE_POINTER_STATE_TYPE = "1"
TAINTED_OPERAND_STATE_TYPE = "2"
DERIVED_UNSAFE_POINTER_STATE_TYPE = "3"
IMPACTED_STACK_POINTER = "4"
IMPACTED_STACK_OBJECT = "5"
UNSAFE_STACK_OBJECT = "6"

# New constants to model different types of attack actions
INVALID_ACTION_TYPE = "-1"
SYS_CALL_ATTACK_ACTION_TYPE = "0"
UNSAFE_POINTER_WRITE_STACK_ACTION_TYPE = "1"
UNSAFE_POINTER_READ_STACK_ACTION_TYPE = "2"
UNSAFE_POINTER_WRITE_NON_STACK_ACTION_TYPE = "3"
UNSAFE_POINTER_READ_NON_STACK_ACTION_TYPE = "4"
UNSAFE_POINTER_MANIPULATION_STACK_ACTION_TYPE = "5"
UNSAFE_POINTER_MANIPULATION_NON_STACK_ACTION_TYPE = "6"
# Write most important - 3
IMPACTED_POINTER_WRITE_ACTION_TYPE = "7"
# Read least important - 1
IMPACTED_POINTER_READ_ACTION_TYPE = "8"
# Propagation may lead to read/write so 2
IMPACTED_POINTER_PROPAGATION_ACTION_TYPE = "9"
# Uses where corrupt value is used inside the function - 1
IMPACTED_DATA_OBJECT_LOCAL_ACTION_TYPE = "10"
# Uses which may outlive the function i.e corrupt value leaves the function eg global var, return val  -2
IMPACTED_DATA_OBJECT_NON_LOCAL_ACTION_TYPE = "11"


ASAN_AVG_CHECK_COST = 1.42 * (10 ** -9)

ASAN_MD_FUNC_AVG_COST = 2.30 * (10 ** -8)

BAGGY_AVG_CHECK_COST = 2.11 * (10 ** -9)

BAGGY_MD_FUNC_AVG_COST = 5.49 * (10**-8)

# O0
exec_times_ref_no_opt={"458.sjeng":709.19,"445.gobmk":604.49,"453.povray":319.23,"433.milc":942.83,"400.perlbench":439.18,"403.gcc":394.75,"464.h264ref":1602.84,"httpd":118,"sqlite3":150, "readelf":60,"redis-cli":406, "xmllint":58,"openssl":489,"tiffcp":1}

asan_check_cost_estimates_no_opt = {"458.sjeng": 1.14 * (10**-9), "403.gcc": 3.58 * (10**-9), "400.perlbench": 2.60 * (
    10**-9), "445.gobmk": 1.12 * (10**-9), "453.povray": 9.75*(10**-10), "httpd": 1.19*(10**-8)}

asan_md_cost_estimates_no_opt = {"458.sjeng": 2.11 * (10**-8), "403.gcc": 3.57 * (
    10**-8), "400.perlbench": 3.14 * (10**-8), "445.gobmk": 1.67 * (10**-8), "httpd": 1.29*(10**-9)}

baggy_check_cost_estimates_no_opt = {"458.sjeng": 2.30 * (10**-9), "403.gcc": 3.58 * (10**-9), "400.perlbench": 2.60 * (
    10**-9), "445.gobmk": 1.12 * (10**-9), "453.povray": 9.75*(10**-10), "httpd": 1.19*(10**-8)}

baggy_md_cost_estimates_no_opt = {"458.sjeng": 1.13 * (10**-7), "403.gcc": 3.58 * (10**-9), "400.perlbench": 2.60 * (
    10**-9), "445.gobmk": 1.12 * (10**-9), "453.povray": 9.75*(10**-10), "httpd": 1.19*(10**-8)}

# O2
exec_times_ref={
    "458.sjeng":400.76,
    "400.perlbench":246.60,
    "631.deepsjeng_s":397.67,
    "625.x264_s":240.65,
    "600.perlbench_s":359.93,
    "602.gcc_s":588.40,
    "644.nab_s":2021.52,
    "511.povray_r":457.53,
    "526.blender_r":280.12332,
    "httpd":104.44,
    "openssl":391.55,
    "xmllint":60.67}


asan_check_cost_estimates = {
    # "458.sjeng": 2.37 * (10**-9), 
    "458.sjeng": 1.14 * (10**-9),
    "403.gcc": 2.26 * (10**-9), 
    "400.perlbench": 2.57 * (10**-9), 
    "httpd": 2.17 * (10**-9),
    "openssl": 4.6 * (10**-10),
    "libxml2": 8.62 * (10**-10),
    "631.deepsjeng_s":4.72E-10,
    "625.x264_s":5.82E-10,
    "600.perlbench_s":6.81E-10,
    "602.gcc_s":5.58E-10,
    "644.nab_s":3.97E-10,
    "511.povray_r":4.58E-10,
    "526.blender_r":4.34E-10
    }


asan_md_cost_estimates = {
    # "458.sjeng": 4.08 * (10**-8), 
    "458.sjeng": 2.11 * (10**-8),
    "400.perlbench": 1.63 * (10**-8), 
    "httpd": 1.21*(10**-7),
    "openssl": 1.02 * (10**-8),
    "libxml2":4.75 * (10**-7),
    "631.deepsjeng_s":1.32E-08,
    "625.x264_s":5.03E-10,
    "600.perlbench_s":1.00E-08,
    "602.gcc_s":9.13E-09,
    "644.nab_s":8.75E-04,
    "511.povray_r":5.68E-09,
    "526.blender_r":1.62E-08}

baggy_md_cost_estimates = {"458.sjeng": 1.13 * (10**-7),
                              "400.perlbench": 3.61 * (10**-8),  
    "httpd": 1.25*(10**-7),
    "openssl": 8.06*(10**-9),
    "libxml2": 1.28 * (10**-7),
    "631.deepsjeng_s":3.01E-08,
    "625.x264_s":7.24E-09,
    "600.perlbench_s":1.82E-08,
    "602.gcc_s":5.13E-09,
    "644.nab_s":2.25E-04,
    "511.povray_r":4.69E-09,
    "526.blender_r":2.02E-08
    }



baggy_check_cost_estimates = {"458.sjeng": 2.30 * (10**-9), 
                              "400.perlbench": 3.47 * (10**-9), 
    "httpd": 2.64*(10**-8),
    "openssl": 1.23*(10**-9),
    "libxml2":1.56 * (10**-9),
    "631.deepsjeng_s":1.15E-09,
    "625.x264_s":9.92E-10,
    "600.perlbench_s":1.66E-09,
    "602.gcc_s":1.21E-09,
    "644.nab_s":8.30E-10,
    "511.povray_r":1.18E-09,
    "526.blender_r":9.77E-10
    }





def get_cost_estimates(program_name,operation_class,monitor_type):
    if operation_class == MonitorOperations.Checks:
        if monitor_type==MonitorType.ASAN:
            if program_name in asan_check_cost_estimates:
                return asan_check_cost_estimates[program_name]
            else:
                return ASAN_AVG_CHECK_COST
        elif monitor_type==MonitorType.BBC:
            if program_name in baggy_check_cost_estimates:
                return baggy_check_cost_estimates[program_name]
            else:
                return BAGGY_AVG_CHECK_COST                
    elif operation_class == MonitorOperations.Metadata:
        if monitor_type==MonitorType.ASAN:
            if program_name in asan_md_cost_estimates:
                return asan_md_cost_estimates[program_name]/1
            else:
                return ASAN_MD_FUNC_AVG_COST/1
        elif monitor_type==MonitorType.BBC:
            if program_name in asan_md_cost_estimates:
                return baggy_md_cost_estimates[program_name]/1
            else:
                return BAGGY_MD_FUNC_AVG_COST/1          