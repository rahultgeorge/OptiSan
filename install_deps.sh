#!/bin/bash

set -e

function install_prereq {
    clear
    apt install -y autoconf libtool  git tar wget nano software-properties-common  libedit-dev  pkg-config libcypher-parser-dev ruby-full libssl-dev gcc g++ maven openjdk-8-jdk debhelper devscripts dos2unix dpkg make xmlstarlet software-properties-common python3 python3-pip  build-essential libncurses5 libncurses-dev cmake zlib1g-dev libtinfo5 zip >& /dev/null
    # Compiler wrapper
    gem install shellwords pathname open3 fileutils singleton
}

function install_cmake {
    pushd .
    if [ ! -d "./cmake_dir" ] ; then
        mkdir -p cmake_dir
        cd cmake_dir
        wget https://github.com/Kitware/CMake/releases/download/v3.23.0/cmake-3.23.0.tar.gz
        tar -xvf cmake-3.23.0.tar.gz
        cd cmake-3.23.0
        ./configure
        make -j8
        make install
        cd ..
    fi    
    popd
}

function run_with_sudo {
    COMMAND=$1
    if [ "$EUID" -ne 0 ]; then
        sudo $COMMAND
    else
        $COMMAND    
    fi
}

# Download and setup LLVM 10
function setup_llvm {
    if [ ! -d "/opt/llvm-project" ] ; then
        echo "Downloading and building LLVM 10"
        pushd .
        mkdir -p /opt    
        cd /opt 
        git clone https://github.com/llvm/llvm-project.git >& /dev/null
        git checkout tags/llvmorg-10.0.0 >& /dev/null
        # update-alternatives --config gcc
        cd llvm-project 
        cp $optisan_root_dir/patches/llvm_patch.txt .
        git apply llvm_patch.txt >& /dev/null
        git apply $optisan_root_dir/patches/asan_precise_stack_md.patch  >& /dev/null
        mkdir -p llvm-build
        cd llvm-build
        ulimit -s unlimited
        cmake   -DCMAKE_BUILD_TYPE="Release"   -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_ENABLE_PROJECTS='clang;compiler-rt;lld;'    ../llvm
        # sudo cmake   -DCMAKE_BUILD_TYPE="Release"  -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_ENABLE_PROJECTS='clang;compiler-rt;lld;'    ../llvm
        # run_with_sudo "make -j8"
        make -j8 
        make -j8 clang opt asan compiler-rt llc llvm-link 
        clear
        popd
    fi    
}

# Function 2: Prints the current date and time
function setup_neo4j_from_source {
    # Neo4j 3.5 has reached end of life so no deb for corresponding cypher-shell
    #  Build form source

    pushd .
    if [ ! -d "./neo4j" ] ; then
        git clone https://github.com/neo4j/neo4j.git
        cd neo4j
        git checkout tags/3.5.5 
        # Need to use java 8 for build process
        echo "Please pick Java 8 (java and javac) as the default for Neo4j" 
        update-alternatives --config java
        update-alternatives --config javac
        ulimit -n 40000
        mvn clean install -DskipTests -Dlicensing.skip=true -DminimalBuild
        # # mvn clean install -DskipTests -Dlicensing.skip=true -DminimalBuild
        cd packaging/standalone/target
        tar -xvf neo4j-community-3.5.5-SNAPSHOT-unix.tar.gz 
        run_with_sudo "mkdir  -p /var/lib/neo4j/certificates/revoked"
        run_with_sudo "mkdir  -p /var/lib/neo4j/certificates/trusted"
        cd neo4j-community-3.5.5-SNAPSHOT
        # Update the config file, no password 
        cd conf 
        mv neo4j.conf neo4j_def.conf
        cp $optisan_root_dir/neo4j.conf .
        cd ..
        ln -s  $PWD/certificates /var/lib/neo4j/certificates
        # enable APOC
        cd plugins
        wget https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/3.5.0.11/apoc-3.5.0.11-all.jar
        cd ..
        cd bin
        export PATH="$PWD:$PATH"
        neo4j start
    fi    
    popd 
}

# Easier to build form source, instead of ad
function setup_neo4j_c_driver {
    pushd .
    if [ ! -d "libneo4j-client" ]; then
        git clone https://github.com/cleishm/libneo4j-client.git
        cd libneo4j-client
        ./autogen.sh
        # ./configure --without-tls --disable-tools  --disable-werror
        ./configure --without-tls   --disable-werror
        make clean check -j
        make install
    fi
    popd 
}


function setup_neo4j {
    # Neo4j C community driver 
    setup_neo4j_c_driver
    # Neo4j 3.5 
    setup_neo4j_from_source
    # Python3 neo4j driver
    pip3 install neo4j
}


function build_svf {
    if [ ! -d "SVF" ]; then
        git clone https://github.com/SVF-tools/SVF.git
        cd SVF 
        git checkout tags/SVF-2.1
        git cherry-pick ada34e76eb5dc72720821ef735d14c630363ecdc
        export LLVM_DIR=/opt/llvm-project/llvm-build/lib/cmake/llvm/
        git clone "https://github.com/SVF-tools/Test-Suite.git"
        ./setup.sh
        # ./build.sh >&
        cmake .
        make -j4
    fi    
}

function setup_solver {
    clear
    echo "Please use the links below, unfortunately this step is manual and requires licenses"
    echo -e "Matlab: "https://www.mathworks.com/help/install/ug/install-products-with-internet-connection.html
    echo -e "Gurobi (Download optimizer): "https://www.gurobi.com/downloads/gurobi-software/
    echo -e "Gurobi For Matlab: "https://support.gurobi.com/hc/en-us/articles/4533938303505-How-do-I-install-Gurobi-for-Matlab
}

function modify_compiler_chain {
    ln -s $optisan_root_dir/Instrumentation/my-clang.rb /opt/llvm-project/llvm-build/bin/my-clang >& /dev/null
    ln -s $optisan_root_dir/Instrumentation/my-clang.rb /opt/llvm-project/llvm-build/bin/my-clang++ >& /dev/null
    source ./optisan_bash_aliases
    my-clang -v
}



if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./install_deps.sh"
    exit
else
    optisan_root_dir=$(pwd)
    echo "ETA: 90 minutes, depends on LLVM build mainly"
    echo "OptiSan Root dir:"$optisan_root_dir
    echo "------------------------------------"
    install_prereq
    echo "------------------------------------"
    install_cmake
    echo "------------------------------------"
    setup_llvm
    echo "------------------------------------"
    setup_neo4j
    echo "------------------------------------" 
    build_svf
    echo "------------------------------------" 
    setup_solver
    echo "------------------------------------"
    modify_compiler_chain
    echo "------------------------------------"
    echo "Please modify the path variables in Utilites/my_clang_utils.rb manually"
fi
