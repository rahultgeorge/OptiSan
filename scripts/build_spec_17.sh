#!/bin/bash

# Script to compile SPEC 2006 and SPEC 17 benchmark with varying configurations

# 648.exchange2_s- Fortran so cannot do anything, clang doesn't support it

SPEC_CPU_2006_INT_DIR="CINT2006"
SPEC_CPU_2006_FLOAT_DIR="CFP2006"
SPEC_CPU_2017_INT_SPEED_DIR="CINT2017speed"
SPEC_CPU_2017_FLOAT_SPEED_DIR="CFP2017speed"
SPEC_CPU_2017_FLOAT_RATE_DIR="CFP2017rate"

# 458.sjeng 400.perlbench
all_spec_06_int_programs=(400.perlbench)

# all_speed_int_programs=( 605.mcf_s 641.leela_s 631.deepsjeng_s 625.x264_s 600.perlbench_s 602.gcc_s  657.xz_s 620.omnetpp_s 623.xalancbmk_s)

# fcommon issue, will come back to this
# all_speed_int_programs=( 641.leela_s )


all_speed_int_programs=(625.x264_s)



# all_speed_float_programs=( 603.bwaves_s 607.cactuBSSN_s 619.lbm_s 621.wrf_s 627.cam4_s 628.pop2_s 638.imagick_s 644.nab_s 649.fotonik3d_s 654.roms_s)

# all_speed_float_programs=( 644.nab_s )

# all_rate_float_programs=(508.namd_r 510.parest_r 511.povray_r 526.blender_r)

# all_rate_float_programs=(510.parest_r)


# all_rate_float_programs=(511.povray_r  526.blender_r)


all_rate_float_programs=(511.povray_r)



# Note about coverage files - Stale files are evil beware (breaky breaky)

WORKLOAD_TYPE="ref"

LLVM_BUILD_DIR=/opt/llvm-project/llvm-build
SPEC_2006_DIR=~/Desktop/SPEC2006/
SPEC_2017_DIR=~/Desktop/cpu2017-1_0_2
SPEC_BASELINE_BITCODE_DIR=~/Desktop/SPEC_17_BASELINE_BC
SPEC_BASELINE_PROFILE_BITCODE_DIR=~/Desktop/SPEC_BASELINE_PROFILE_BC
# CLANG
CLANG_WRAPPER=$LLVM_BUILD_DIR/bin/clang
CLANG_CXX_COMPILER_WRAPPER=$LLVM_BUILD_DIR/bin/clang++
# WLLVM
WLLVM_WRAPPER="wllvm"
CXX_WLLVM_WRAPPER="wllvm++"


# MY_CLANG  - To compile with monitors and coverage we leverage ASAP's wrapper script 
COMPILER_WRAPPER=$LLVM_BUILD_DIR/bin/"my-clang"
CXX_COMPILER_WRAPPER=$LLVM_BUILD_DIR/bin/"my-clang++"
# Flags used to build bitcode we analyze 
BASELINE_ANALYSIS_CFLAGS="-O0 -g "
BASELINE_ANALYSIS_CXX_FLAGS="-O0 -g"
BASELINE_COVERAGE_DIR=~/Desktop/SmartMonitor/COVERAGE
# For O0 baseline (we run dce and simplify cfg)
BASELINE_RUN_O0_CFLAGS="-O0 -Xclang -disable-O0-optnone -g"
BASELINE_RUN_O0_CXX_FLAGS="-O0 -Xclang -disable-O0-optnone -g"
# Optimized baseline
BASELINE_RUN_CFLAGS="-O2 -g"
BASELINE_RUN_CXX_FLAGS="-O2 -g"
# These are flags to instrument with both monitors (Need DCE)
# Optimization level and DI nastiness, can either use O1 and disable-llvm-passes or O0 and disable optnone. Reverting to just use O0
# PLACEMENT_CFLAGS="place -O0 -g"
# PLACEMENT_CXXFLAGS="place -O0 -g"
PLACEMENT_CFLAGS="-O2 -g"
PLACEMENT_CXXFLAGS="-O2 -g"

# Normal flags - halt on error type
# ASAN_CFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"
# ASAN_CXXFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"
# Optimization
ASAN_CFLAGS="-O2 -g"
ASAN_CXXFLAGS="-O2 -g"

# ASAN - no halt on error, -fsanitize=address -fsanitize-recover=address
# ASAN_CFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"
# ASAN_CXXFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"


# Flags for baggy used for cost estimation
# BAGGY_CFLAGS="baggy -O0 -Xclang -disable-O0-optnone -g"
# BAGGY_CXXFLAGS="baggy -O0 -Xclang -disable-O0-optnone -g"
# Optimization
BAGGY_CFLAGS="-O2 -g"
BAGGY_CXXFLAGS="-O2 -g"



BAGGY_ASAN_CFLAGS="baggyasan -O0 -Xclang -disable-O0-optnone -g"
BAGGY_ASAN_CXXFLAGS="baggyasan -O0 -Xclang -disable-O0-optnone -g"


export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=/opt/llvm-project/llvm-build/bin

# Halt on error disable could lead to bad things also not as stable
# ASAN ENV VARIABLE FOR RUNTIME OPTIONS (HALT ON ERROR TO PROFILE PROGRAMS WITH ISSUES)
# export ASAN_OPTIONS=halt_on_error=0


declare -i mode
declare monitor_name
declare programs

# Build with coverage flags and save bitcode, coverage data
build_and_profile() {
  # First arg - Results dir to save bitcode, coverage data etc
  # Iterative
  # Step 1 - Build  and run the programs
  for i in ${programs[*]}; do
    echo "Compiling: "$i
    export OPTISAN_PROGRAM_NAME=$i
    cd External/SPEC/$SPEC_DIR/$i
    

    make clean &>/dev/null
    rm *.bc &>/dev/null
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null
    # Clear old coverage files
    rm *.gcda  &>/dev/null
    rm *.gcno &>/dev/null
    make -j8

    # Delete directory to clear everything (stale coverage files)
    # rm -r $1/$i/$WORKLOAD_TYPE &>/dev/null
    find $1/$i/$WORKLOAD_TYPE -name "*.gcno" | xargs rm
    find $1/$i/$WORKLOAD_TYPE -name "*.gcda" | xargs rm

    mkdir -p $1/$i/$WORKLOAD_TYPE


    # Copy all bitcode files (just in case)
    find . -name "*.bc.o" | xargs -I{} cp -u {} $1/$i/$WORKLOAD_TYPE

    # Run the workload
    /opt/llvm-project/llvm-build/bin/llvm-lit . -o $WORKLOAD_TYPE"_out.txt"

    # Copy the output
    mv $WORKLOAD_TYPE"_out.txt" $1/$i/$WORKLOAD_TYPE


    # Extract single bitcode file
    find . -name "*.bc.o" | xargs /opt/llvm-project/llvm-build/bin/llvm-link  -o ./$i.profile.bc
    cp $i.profile.bc $1/$i/$WORKLOAD_TYPE

    # Copy the coverage files
    find . -name "*.gcno" | xargs -I{} cp -u {} $1/$i/$WORKLOAD_TYPE
    find . -name "*.gcda" | xargs -I{} cp -u {} $1/$i/$WORKLOAD_TYPE

    # Clear coverage files  (Not necessary actually)
    rm *.gcda  &>/dev/null
    rm *.gcno &>/dev/null

    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done
}

# Build and extract bitcode (For threat graph/analysis)
build_and_extract_bitcode() {
  # First arg - bitcode dir
  # Step 1- Build the programs
  for i in ${all_speed_int_programs[*]}; do
    echo "Compiling CINT2017Speed: "$i

    cd External/SPEC/CINT2017speed/$i

    make clean &>/dev/null
    rm *.bc &>/dev/null
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null
    make -j8

    # Step 2 - Extract bitcode file
    extract-bc $i -o $i.bc
    cp $i.bc $1
    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done

  
  # for i in ${all_speed_float_programs[*]}; do
  #   echo "Compiling CFP2017Speed: "$i

  #   cd External/SPEC/CFP2017speed/$i
  #   make clean &>/dev/null
  #   rm *.bc &>/dev/null
  #   rm -r CMakeFiles cmake_install.cmake &>/dev/null
  #   rm *.ll &>/dev/null
  #   make -j4

  #   # Step 2 - Extract bitcode file
  #   extract-bc $i -o $i.bc
  #   cp $i.bc $1
  #   cd $LLVM_BUILD_DIR/projects/test-suite-build
  # done


  # for i in ${all_rate_float_programs[*]}; do
  #   echo "Compiling CFP2017rate: "$i

  #   cd External/SPEC/CFP2017rate/$i
  #   make clean &>/dev/null
  #   rm *.bc &>/dev/null
  #   rm -r CMakeFiles cmake_install.cmake &>/dev/null
  #   rm *.ll &>/dev/null
  #   make -j4

  #   # Step 2 - Extract bitcode file
  #   extract-bc $i -o $i.bc
  #   cp $i.bc $1
  #   cd $LLVM_BUILD_DIR/projects/test-suite-build
  # done

}


build_and_run()
{
  # First arg - Dir to save results etc

  # Build the programs and run
  for i in ${programs[*]}; do
    echo "Compiling: "$i
    export OPTISAN_PROGRAM_NAME=$i
    cd External/SPEC/$SPEC_DIR/$i
    
    make clean &>/dev/null
    rm *.bc &>/dev/null
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null

    make -j8

    mkdir -p $1/$i/$WORKLOAD_TYPE

    rm -f $1/$i/$WORKLOAD_TYPE/exec_info.out
 
    find . -name "*.bc.o" | xargs /opt/llvm-project/llvm-build/bin/llvm-link  -o ./$i.bc
    cp $i.bc $1/$i/$WORKLOAD_TYPE
    cp $i $1/$i/$WORKLOAD_TYPE

    echo "Running: " $i
    # Run the workload using the python script (Compute std deviation and drops samples etc)
    python3 ~/Desktop/SmartMonitor/scripts/run_program.py >& exec_info.out
    
    mv exec_info.out $1/$i/$WORKLOAD_TYPE


    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done

}


build_and_place_monitors()
{

  # Let's build it first
  for i in ${programs[*]}; do
    echo "Compiling: "$i
    export OPTISAN_PROGRAM_NAME=$i
    echo $OPTISAN_PROGRAM_NAME
    cd External/SPEC/$SPEC_DIR/$i
    if [ $mode -eq 0 ]; then
      make clean -j$(nproc) &>/dev/null
    fi
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null
    rm *.bc &>/dev/null

    make -j8

    mkdir -p $1/$i/$WORKLOAD_TYPE

    find . -name "*.bc" | xargs  -I{}  cp  {} $1/$i/$WORKLOAD_TYPE
    
    # find . -name "*.o.bc" | xargs $LLVM_BUILD_DIR/bin/llvm-link -v -o  $1/$i/$WORKLOAD_TYPE/$i.placement.bc

    # Copy the final executable
    mv $i $i.placement
    cp $i.placement $1/$i/$WORKLOAD_TYPE
    # rename it
    mv $i.placement $i
    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done

  neo4j stop
  sleep 5

  # # Now let's run
  for i in ${programs[*]}; do
    echo " Running: "$i
    cd External/SPEC/$SPEC_DIR/$i
    python3 ~/Desktop/SmartMonitor/scripts/run_program.py >& placement.exec_info.out
    mv placement.exec_info.out $1/$i/$WORKLOAD_TYPE
    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done

  neo4j start
}



# Step 1 Configure test suite
cd $LLVM_BUILD_DIR/projects/test-suite-build
if [ "$2" == "fast" ]; then
  echo "Fast mode"
  mode=1
else
  # make clean
  rm -r CMakeFiles Makefile CMakeCache.txt cmake_install.cmake &> /dev/null
  # Ensures we rebuild the tools first (Fair comparison then, alternatively we can build the tools just once with normal flags)
  rm -r tools/* &> /dev/null
  mode=0
fi


if [ "$1" == "1" ]; then
  export OPTISAN_COMPILER_STATE="ASanStackMD"
  echo "ASAN Build:",$OPTISAN_COMPILER_STATE
  # Disabling sanity mode and other interceptions (We can enable these but how does one selectively turn these off or replace these)
  # report_globals=false - causes bug
  export ASAN_OPTIONS=detect_stack_use_after_return=0:halt_on_error=0:detect_leaks=0:replace_str=false:replace_intrin=false:intercept_strchr=0:intercept_strndup=0:intercept_strlen=0:use_sigaltstack=false:print_summary=false:check_printf=false:detect_deadlocks=false:intercept_strstr=0:intercept_strspn=0:intercept_strpbrk=0:intercept_memcmp=0	
  echo "ASan Runtime env options "$ASAN_OPTIONS
  echo "C Flags "$ASAN_CFLAGS
  echo "C++ Flags "$ASAN_CXXFLAGS
  monitor_name="ASAN"
  neo4j stop
  sleep 5
  # # Step 1 - Run and save coverage info (Already have this for O0)
  # echo "  Building and running for coverage/frequency info - ASan"
  # export OPTISAN_COMPILER_STATE="ASanFull"
  # cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$ASAN_CFLAGS " -DCMAKE_CXX_FLAGS="$ASAN_CXXFLAGS " -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # programs=${all_speed_int_programs[*]}
  # SPEC_DIR="CINT2017speed"
  # build_and_profile $BASELINE_COVERAGE_DIR/$monitor_name 
  # # # Clean everything up
  # rm -r CMakeFiles Makefile CMakeCache.txt &> /dev/null
  # # Ensures we rebuild the tools first (Fair comparison then, alternatively we can build the tools just once with normal flags)
  # rm -r tools/* &> /dev/null
  # Step 2 - Run multiple times to estimate monitor overhead
  echo " Running multiple times (samples) for cost estimation"
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$ASAN_CFLAGS" -DCMAKE_CXX_FLAGS="$ASAN_CXXFLAGS" -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  programs=${all_speed_int_programs[*]}
  SPEC_DIR="CINT2017speed"
  build_and_run $BASELINE_COVERAGE_DIR/$monitor_name 
  programs=${all_rate_float_programs[*]}
  SPEC_DIR="CFP2017rate"
  build_and_run $BASELINE_COVERAGE_DIR/$monitor_name  
  neo4j start
elif [ "$1" == "2" ]; then
  echo "Baggy Bounds build:" $BAGGY_CFLAGS $BAGGY_CXXFLAGS
  monitor_name="BaggyBounds"
  neo4j stop
  sleep 5
  export OPTISAN_COMPILER_STATE="BaggyFull"
  # Step 1 - Run and save coverage info (Already have this for O0)
  echo "  Building for coverage/frequency info - Baggy bounds"
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BAGGY_CFLAGS " -DCMAKE_CXX_FLAGS="$BAGGY_CXXFLAGS" -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # programs=${all_speed_int_programs[*]}
  # SPEC_DIR="CINT2017speed"
  # build_and_profile $BASELINE_COVERAGE_DIR/$monitor_name 
  # programs=${all_speed_float_programs[*]}
  # SPEC_DIR="CFP2017speed"
  # build_and_profile $BASELINE_COVERAGE_DIR/$monitor_name 
  programs=${all_rate_float_programs[*]}
  SPEC_DIR="CFP2017rate"
  build_and_profile $BASELINE_COVERAGE_DIR/$monitor_name 
  # Clean everything up
  # rm -r CMakeFiles Makefile CMakeCache.txt &> /dev/null
  # # Ensures we rebuild the tools first (Fair comparison then, alternatively we can build the tools just once with normal flags)
  # rm -r tools/* &> /dev/null
  # # Step 2 - Run multiple times to estimate monitor overhead
  # echo "  Running multiple samples for cost estimation"
  # cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BAGGY_CFLAGS" -DCMAKE_CXX_FLAGS="$BAGGY_CXXFLAGS" -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # programs=${all_speed_float_programs[*]}
  # SPEC_DIR="CFP2017speed"
  # build_and_run $BASELINE_COVERAGE_DIR/$monitor_name 
  neo4j start
elif [ "$1" == "3" ]; then
  echo "Guided Sanitizer placement build (GODSPEED)" $PLACEMENT_CFLAGS
  export ASAN_OPTIONS=detect_stack_use_after_return=0:detect_leaks=0:replace_str=false:replace_intrin=false:intercept_strchr=0:intercept_strndup=0:intercept_strlen=0:use_sigaltstack=false:print_legend=false:print_full_thread_history=false:check_malloc_usable_size=false:poison_heap=false:poison_array_cookie=false:detect_container_overflow=false:malloc_context_size=0:poison_partial=false:alloc_dealloc_mismatch=false:new_delete_type_mismatch=false:allow_user_poisoning=false:intercept_memcmp=false:check_printf=false
  export OPTISAN_COMPILER_STATE="PlacementMode"
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$PLACEMENT_CFLAGS" -DCMAKE_CXX_FLAGS="$PLACEMENT_CXXFLAGS" -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  export OPTISAN_PROGRAM_NAME=""
  programs=${all_spec_06_int_programs[*]}
  SPEC_DIR=$SPEC_CPU_2006_INT_DIR
  # programs=${all_speed_int_programs[*]}
  # SPEC_DIR=$SPEC_CPU_2017_INT_SPEED_DIR
  build_and_place_monitors $BASELINE_COVERAGE_DIR
  # export OPTISAN_PROGRAM_NAME=""
  # programs=${all_rate_float_programs[*]}
  # SPEC_DIR="CFP2017rate"
  # build_and_place_monitors $BASELINE_COVERAGE_DIR
elif [ "$1" == "4" ]; then
  echo "Building bitcode for Analysis"
  cmake -DCMAKE_C_COMPILER=$WLLVM_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_WLLVM_WRAPPER  -DCMAKE_C_FLAGS="$BASELINE_ANALYSIS_CFLAGS" -DCMAKE_CXX_FLAGS="$BASELINE_ANALYSIS_CXX_FLAGS"  -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_extract_bitcode $SPEC_BASELINE_BITCODE_DIR
elif [ "$1" == "5" ]; then
  # echo "Baseline build for profiling (Cost estimation)"
  # echo "C Flags "$BASELINE_RUN_CFLAGS
  # echo "C++ Flags "$BASELINE_RUN_CXX_FLAGS
  neo4j stop
  sleep 5
  # cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG"  -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BASELINE_RUN_CFLAGS " -DCMAKE_CXX_FLAGS="$BASELINE_RUN_CXX_FLAGS " -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # programs=${all_speed_int_programs[*]}
  # SPEC_DIR="CINT2017speed"
  # build_and_profile $BASELINE_COVERAGE_DIR 
  # programs=${all_speed_float_programs[*]}
  # SPEC_DIR="CFP2017speed"
  # build_and_profile $BASELINE_COVERAGE_DIR 
  # programs=${all_rate_float_programs[*]}
  # SPEC_DIR="CFP2017rate"
  # build_and_profile $BASELINE_COVERAGE_DIR 
  # rm -r CMakeFiles Makefile CMakeCache.txt &> /dev/null
  # rm -r tools/* &> /dev/null
  echo "Baseline run with optimization for cost estimation (execution time)"
  echo "C Flags "$BASELINE_RUN_CFLAGS
  echo "C++ Flags "$BASELINE_RUN_CXX_FLAGS
  unset OPTISAN_COMPILER_STATE
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG"  -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BASELINE_RUN_CFLAGS " -DCMAKE_CXX_FLAGS="$BASELINE_RUN_CXX_FLAGS " -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # cmake -DCMAKE_C_COMPILER=$CLANG_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CLANG_CXX_COMPILER_WRAPPER  -DCMAKE_C_FLAGS="$BASELINE_RUN_CFLAGS" -DCMAKE_CXX_FLAGS="$BASELINE_RUN_CXX_FLAGS"  -DTEST_SUITE_SPEC2017_ROOT=$SPEC_2017_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # programs=${all_speed_int_programs[*]}
  # SPEC_DIR="CINT2017speed"
  # build_and_run $BASELINE_COVERAGE_DIR
  # programs=${all_rate_float_programs[*]}
  # SPEC_DIR="CFP2017rate"
  # build_and_run $BASELINE_COVERAGE_DIR
  export OPTISAN_PROGRAM_NAME=""
  programs=${all_spec_06_int_programs[*]}
  SPEC_DIR=$SPEC_CPU_2006_INT_DIR
  build_and_run $BASELINE_COVERAGE_DIR

  neo4j start
fi






