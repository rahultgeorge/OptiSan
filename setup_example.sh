#!/bin/bash

set -e

function apply_patches {
    find "patches/setup" "patches/bugs" -name "*.patch" | \
    while read patch; do
        echo "Applying $patch"
        name=${patch##*/}
        name=${name%.patch}
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1 -d "./repo"
    done
}

function setup_example_source_code {
    if [ ! -d "./repo" ] ; then
        mkdir -p repo
        cd repo
        git clone --no-checkout https://gitlab.gnome.org/GNOME/libxml2.git .
        git -C . checkout ec6e3efb06d7b15cf5a2328fabd3845acea4c815   
        cd ..
    fi    
}

function build_and_extract_bitcode {
    export CC=wllvm CXX=wllvm++ CFLAGS="-O0 -g" CXX_FLAGS="-O0 -g"
    cd repo
    ./autogen.sh \
            --with-http=no \
            --with-python=no \
            --with-lzma=yes \
            --with-threads=no \
            --disable-shared
    make -j$(nproc) clean
    make -j$(nproc) all
    extract-bc xmllint -o xmllint.bc 
    cp xmllint.bc ..
    cd ../..
}

function extract_existing_exec_prof_data {
    tar -xvf example/coverage.tgz
    cp COVERAGE/xmllint/ref/xmllint.profile.bc ./example
    mkdir -p COVERAGE/example
    mv COVERAGE/xmllint  COVERAGE/./example/xmllint

    # mv xmllint.profile.bc ./example/xmllint.profile.bc

}




# pip3 install wllvm >& /dev/null
source ./optisan_bash_aliases
set_local_llvm_build
extract_existing_exec_prof_data
cd example
echo "Using libxml2 from MAGMA dataset as the example" 
setup_example_source_code
echo "Applying patches:"
apply_patches
echo "Building and extract LLVM bitcode for analysis"
build_and_extract_bitcode