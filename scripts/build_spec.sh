#!/bin/bash

# Script to compile SPEC benchmark with varying configurations
# programs=(400.perlbench)
programs=(458.sjeng)
# programs=(458.sjeng 403.gcc 400.perlbench 445.gobmk)
# SPEC CPU 2006 - CINT
# All Programs
# programs=( 429.mcf 462.libquantum 456.hmmer 464.h264ref 401.bzip2 458.sjeng 403.gcc 400.perlbench 445.gobmk 471.omnetpp 473.astar 483.xalancbmk)
# All Programs sans xalancbmk
# programs=( 429.mcf 456.hmmer 462.libquantum 464.h264ref 401.bzip2 458.sjeng 403.gcc 400.perlbench 445.gobmk 471.omnetpp 473.astar)
# ALL PROGRAMS BAGGY+ASAN sans omnetpp
#programs=( 429.mcf 456.hmmer 462.libquantum 464.h264ref 401.bzip2 458.sjeng 403.gcc 400.perlbench 445.gobmk 473.astar 483.xalancbmk)
# ASAN  - No halt on error - No omnitepp
# programs=( 429.mcf 462.libquantum 456.hmmer 401.bzip2 458.sjeng 403.gcc 400.perlbench 445.gobmk 473.astar 483.xalancbmk)
# Non bug progs - ASAN
# programs=(464.h264ref)
# Non bug progs - Baggy  (Baggy gcc and xalanbmk not supported because of recovery)
# programs=( 429.mcf 462.libquantum 401.bzip2 456.hmmer 458.sjeng 403.gcc 400.perlbench 445.gobmk)
# Bug progs - Need to turn off sanity checks (ASAN different flags, baggy needs to be recompiled with silent mode enabled)
# programs=(464.h264ref)
#programs=( 429.mcf 462.libquantum 401.bzip2 456.hmmer 458.sjeng 464.h264ref 400.perlbench 445.gobmk)



# C small programs
#programs=( 429.mcf 456.hmmer 462.libquantum 401.bzip2 458.sjeng)
# C LARGE PROGRAMS
#programs=(445.gobmk 403.gcc 400.perlbench)
# ALL C Programs
# programs=( 429.mcf 456.hmmer 462.libquantum 464.h264ref 401.bzip2 458.sjeng 403.gcc 400.perlbench 445.gobmk)
# ALL C++ programs
# programs=(473.astar 471.omnetpp 483.xalancbmk)


#CFP Programs
# programs=(433.milc 444.namd 453.povray 470.lbm 482.sphinx3)

# Note about coverage files - Stale files are evil beware (breaky breaky)

WORKLOAD_TYPE="ref"

LLVM_BUILD_DIR=/opt/llvm-project/llvm-build
SPEC_2006_DIR=~/Desktop/SPEC2006/
SPEC_BASELINE_BITCODE_DIR=~/Desktop/SPEC_BASELINE_BC
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
BASELINE_ANALYSIS_CFLAGS="-O0 -g"
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
PLACEMENT_CFLAGS="place -O0 -g"
PLACEMENT_CXXFLAGS="place -O0 -g"
# PLACEMENT_CFLAGS="place -O2 -g"
# PLACEMENT_CXXFLAGS="place -O2 -g"

# Normal flags - halt on error type
ASAN_CFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"
ASAN_CXXFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"
# ASAN - no halt on error, -fsanitize=address -fsanitize-recover=address
# ASAN_CFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"
# ASAN_CXXFLAGS="asan -O0 -Xclang -disable-O0-optnone -g"


# Flags for baggy used for cost estimation
BAGGY_CFLAGS="baggy -O0 -Xclang -disable-O0-optnone -g"
BAGGY_CXXFLAGS="baggy -O0 -Xclang -disable-O0-optnone -g"

BAGGY_ASAN_CFLAGS="baggyasan -O0 -Xclang -disable-O0-optnone -g"
BAGGY_ASAN_CXXFLAGS="baggyasan -O0 -Xclang -disable-O0-optnone -g"


export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=/opt/llvm-project/llvm-build/bin

# Halt on error disable could lead to bad things also not as stable
# ASAN ENV VARIABLE FOR RUNTIME OPTIONS (HALT ON ERROR TO PROFILE PROGRAMS WITH ISSUES)
# export ASAN_OPTIONS=halt_on_error=0


declare -i mode
declare monitor_name

# Build with coverage flags and save bitcode, coverage data
build_and_profile() {
  # First arg - Results dir to save bitcode, coverage data etc
  # Iterative
  # Step 1 - Build  and run the programs
  for i in ${programs[*]}; do
    echo "Compiling: "$i
    export OPTISAN_PROGRAM_NAME=$i
    # cd External/SPEC/CINT2006/$i
    cd External/SPEC/CFP2006/$i

    make clean &>/dev/null
    rm *.bc &>/dev/null
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null
    # Clear old coverage files
    rm *.gcda  &>/dev/null
    rm *.gcno &>/dev/null
    make -j$(nproc)

    # Delete directory to clear everything (stale coverage files)
    rm -r $1/$i/$WORKLOAD_TYPE &>/dev/null
    mkdir -p $1/$i/$WORKLOAD_TYPE

    # Extract bitcode file
    find . -name "*.bc.o" | xargs /opt/llvm-project/llvm-build/bin/llvm-link -v -o ./$i.profile.bc
    cp $i.profile.bc $1/$i/$WORKLOAD_TYPE

    # Run the workload
    /opt/llvm-project/llvm-build/bin/llvm-lit . -o $WORKLOAD_TYPE"_out.txt"

    # Copy the output
    mv $WORKLOAD_TYPE"_out.txt" $1/$i/$WORKLOAD_TYPE
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
  for i in ${programs[*]}; do
    echo "Compiling: "$i

    cd External/SPEC/CINT2006/$i
    # cd External/SPEC/CFP2006/$i

    make clean &>/dev/null
    rm *.bc &>/dev/null
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null
    make -j4

    # Step 2 - Extract bitcode file
    extract-bc $i -o $i.bc
    cp $i.bc $1
    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done
}


build_and_run()
{
  # First arg - Dir to save results etc
  # Iterative

  # Build the programs and run
  for i in ${programs[*]}; do
    echo "Compiling: "$i
    export OPTISAN_PROGRAM_NAME=$i
    # cd External/SPEC/CINT2006/$i
    cd External/SPEC/CFP2006/$i
    make clean &>/dev/null
    rm *.bc &>/dev/null
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null

    make -j4

    mkdir -p $1/$i/$WORKLOAD_TYPE

    # rm -f $1/$i/$WORKLOAD_TYPE/exec_info.out
    # Run the workload using the python script (Compute std deviation and drops samples etc)
    python3 ~/Desktop/SmartMonitor/run_program.py >& exec_info.out
    
    mv exec_info.out $1/$i/$WORKLOAD_TYPE

    find . -name "*.bc.o" | xargs /opt/llvm-project/llvm-build/bin/llvm-link -v -o ./$i.bc
    cp $i.bc $1/$i/$WORKLOAD_TYPE

    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done

}


build_and_place_monitors()
{

  # Let's build it first
  for i in ${programs[*]}; do
    echo "Compiling: "$i
    export OPTISAN_PROGRAM_NAME=$i
    cd External/SPEC/CINT2006/$i
    if [ $mode -eq 0 ]; then
      make clean -j$(nproc) &>/dev/null
    fi
    rm -r CMakeFiles cmake_install.cmake &>/dev/null
    rm *.ll &>/dev/null
    rm *.bc &>/dev/null

    make -j$(nproc)

    mkdir -p $1/$i/$WORKLOAD_TYPE

    # Our toolchain creates a placement.bc file (the resultant bitcode file)
    # cp $i.placement.bc $1/$i/$WORKLOAD_TYPE

    # Copy the final executable
    mv $i $i.placement
    cp $i.placement $1/$i/$WORKLOAD_TYPE
    # rename it
    mv $i.placement $i
    cd $LLVM_BUILD_DIR/projects/test-suite-build
  done

  neo4j stop
  sleep 5

  # Now let's run
  for i in ${programs[*]}; do
    echo " Running: "$i
    cd External/SPEC/CINT2006/$i
    python3 ~/Desktop/SmartMonitor/run_program.py >& placement.exec_info.out
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
  echo "ASAN Build"
  # Disabling sanity mode and other interceptions (We can enable these but how does one selectively turn these off or replace these)
  export ASAN_OPTIONS=halt_on_error=0:detect_leaks=0:replace_str=false:replace_intrin=false:intercept_strchr=0:intercept_strndup=0:intercept_strlen=0
  echo $ASAN_OPTIONS
  monitor_name="ASAN"
  neo4j stop
  sleep 5
  # Step 1 - Run and save coverage info (Already have this for O0)
  echo "  Building for coverage/frequency info"
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$ASAN_CFLAGS -profile" -DCMAKE_CXX_FLAGS="$ASAN_CXXFLAGS -profile" -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_profile $BASELINE_COVERAGE_DIR/$monitor_name 
  # Clean everything up
  rm -r CMakeFiles Makefile CMakeCache.txt &> /dev/null
  # Ensures we rebuild the tools first (Fair comparison then, alternatively we can build the tools just once with normal flags)
  rm -r tools/* &> /dev/null
  # Step 2 - Run multiple times to estimate monitor overhead
  echo "  Running multiple samples for cost estimation"
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$ASAN_CFLAGS" -DCMAKE_CXX_FLAGS="$ASAN_CXXFLAGS" -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_run $BASELINE_COVERAGE_DIR/$monitor_name 
  neo4j start
elif [ "$1" == "2" ]; then
  echo "Baggy Bounds build:" $BAGGY_CFLAGS
  monitor_name="BaggyBounds"
  neo4j stop
  sleep 5
  # Step 1 - Run and save coverage info (Already have this for O0)
  # echo "  Building for coverage/frequency info"
  # cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BAGGY_CFLAGS -profile" -DCMAKE_CXX_FLAGS="$BAGGY_CXXFLAGS -profile" -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # build_and_profile $BASELINE_COVERAGE_DIR/$monitor_name 
  # Clean everything up
  rm -r CMakeFiles Makefile CMakeCache.txt &> /dev/null
  # Ensures we rebuild the tools first (Fair comparison then, alternatively we can build the tools just once with normal flags)
  rm -r tools/* &> /dev/null
  # Step 2 - Run multiple times to estimate monitor overhead
  echo "  Running multiple samples for cost estimation"
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BAGGY_CFLAGS" -DCMAKE_CXX_FLAGS="$BAGGY_CXXFLAGS" -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_run $BASELINE_COVERAGE_DIR/$monitor_name 
  neo4j start
elif [ "$1" == "3" ]; then
  echo "Guided Sanitizer placement build (GODSPEED)" $PLACEMENT_CFLAGS
  export ASAN_OPTIONS=detect_leaks=0:replace_str=false:replace_intrin=false:intercept_strchr=0:intercept_strndup=0:intercept_strlen=0:halt_on_error=0
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$PLACEMENT_CFLAGS" -DCMAKE_CXX_FLAGS="$PLACEMENT_CXXFLAGS" -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  export OPTISAN_PROGRAM_NAME=""
  build_and_place_monitors $BASELINE_COVERAGE_DIR
elif [ "$1" == "4" ]; then
  echo "Building for Analysis"
  cmake -DCMAKE_C_COMPILER=$WLLVM_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_WLLVM_WRAPPER  -DCMAKE_C_FLAGS="$BASELINE_ANALYSIS_CFLAGS" -DCMAKE_CXX_FLAGS="$BASELINE_ANALYSIS_CXX_FLAGS"  -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_extract_bitcode $SPEC_BASELINE_BITCODE_DIR
elif [ "$1" == "5" ]; then
  # Step 1 - Build with coverage, run once and record frequency info
  # echo "Baseline build O0 with profiling (for Cost estimation)"
  # cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG"  -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BASELINE_RUN_O0_CFLAGS -profile" -DCMAKE_CXX_FLAGS="$BASELINE_RUN_O0_CXX_FLAGS -profile" -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  # build_and_profile $BASELINE_COVERAGE_DIR
  # rm -r CMakeFiles Makefile CMakeCache.txt &> /dev/null
  # # Ensures we rebuild the tools first 
  # rm -r tools/* &> /dev/null
  # neo4j stop
  # sleep 5
  # Step 2 - Run multiple times to observe overhead
 echo "Baseline run O0"
 cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER  -DCMAKE_C_FLAGS="$BASELINE_RUN_O0_CFLAGS" -DCMAKE_CXX_FLAGS="$BASELINE_RUN_O0_CXX_FLAGS"  -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
 build_and_run $BASELINE_COVERAGE_DIR
#  neo4j start
elif [ "$1" == "6" ]; then
  echo "Baseline build with optimization and profiling (Cost estimation)"
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG"  -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER -DCMAKE_C_FLAGS="$BASELINE_RUN_CFLAGS -profile" -DCMAKE_CXX_FLAGS="$BASELINE_RUN_CXX_FLAGS -profile" -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_profile $BASELINE_COVERAGE_DIR
  rm -r CMakeFiles Makefile CMakeCache.txt &> /dev/null
  rm -r tools/* &> /dev/null
  neo4j stop
  sleep 5
  echo "Baseline run with optimization"
  cmake -DCMAKE_C_COMPILER=$CLANG_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CLANG_CXX_COMPILER_WRAPPER  -DCMAKE_C_FLAGS="$BASELINE_RUN_CFLAGS" -DCMAKE_CXX_FLAGS="$BASELINE_RUN_CXX_FLAGS"  -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_run $BASELINE_COVERAGE_DIR
  neo4j start
elif [ "$1" == "7" ]; then
  neo4j stop
  sleep 5
  monitor_name="BaggyASAN"
  echo "Baggy + ASAN Cost estimation (Coverage). CFLAGS " $BAGGY_ASAN_CFLAGS "CXX_FLAGS:" $BAGGY_ASAN_CXXFLAGS
  cmake -DCMAKE_C_COMPILER=$COMPILER_WRAPPER -DCMAKE_BUILD_TYPE="DEBUG" -DCMAKE_CXX_COMPILER=$CXX_COMPILER_WRAPPER  -DCMAKE_C_FLAGS="$BAGGY_ASAN_CFLAGS" -DCMAKE_CXX_FLAGS="$BAGGY_ASAN_CXXFLAGS"  -DTEST_SUITE_SPEC2006_ROOT=$SPEC_2006_DIR -DTEST_SUITE_COLLECT_CODE_SIZE=OFF -DTEST_SUITE_RUN_TYPE=$WORKLOAD_TYPE  ../llvm-test-suite
  build_and_run $BASELINE_COVERAGE_DIR/$monitor_name
  neo4j start
fi






