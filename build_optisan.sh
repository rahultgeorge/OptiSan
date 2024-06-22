#!/bin/bash

export LLVM_DIR=/opt/llvm-project/llvm-build/lib/cmake/llvm/

if [ -e "$LLVM_DIR" ]; then
    echo "Found local LLVM build:" $LLVM_DIR
    echo "Now building OptiSan passes"
    cmake .
    make pdg -j4
    make -j8
    cd BaggyBounds
    cmake .
    make -j4
    cd ..
    echo "Ready to setup and run example/test"
else
    echo "Local LLVM build not found in /opt:" $LLVM_DIR
fi

