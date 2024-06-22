#!/bin/bash

set -e



function build_and_run {
    export CC=my-clang CXX=my-clang++ CFLAGS="-O2 -g" CXX_FLAGS="-O2 -g"
    cd repo
    export LD=ld
    ./autogen.sh \
            --with-http=no \
            --with-python=no \
            --with-lzma=yes \
            --with-threads=no \
            --disable-shared
    export OPTISAN_COMPILER_STATE="PlacementMode"            
    make -j$(nproc) clean >& /dev/null
    make -j$(nproc) all 
    make tests >& /dev/null
    time make tests
    cd ../..
}


source ./optisan_bash_aliases
set_local_llvm_build
export ASAN_OPTIONS=detect_stack_use_after_return=0:halt_on_error=0:detect_leaks=0:replace_str=false:replace_intrin=false:intercept_strchr=0:intercept_strndup=0:intercept_strlen=0:use_sigaltstack=false:print_summary=false:check_printf=false:detect_deadlocks=false:intercept_strstr=0:intercept_strspn=0:intercept_strpbrk=0:intercept_memcmp=0  
cd example
echo "Demonstrating instrumentation pipeline"
build_and_run

