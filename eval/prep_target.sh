#!/bin/bash

#########################################################################################
# This script shows how to instrument a sample target with sievefuzz instrumentation 
#########################################################################################

if [ ! "$#" -eq 2 ]; then
  echo "Usage: $0 <target_folder> <mode> [bitcode, sievefuzz]"
  exit 1
fi

TARGET="$1"
MODE="$2"
ROOT="/root/sievefuzz/third_party"
sievefuzz="$ROOT/sievefuzz" # AFL with SieveFuzz specific modifications

# Export this variable because we use this variable in build scripts
export TARGET_DIR="/root/sievefuzz/benchmarks/$TARGET"
OUTDIR="/root/sievefuzz/benchmarks/out_$TARGET" # Outdir where the final created targets will be held
DATA="/root/sievefuzz/eval/data/$TARGET" # Auxiliary data used required for building target 
export DATA=$DATA

AF_CLANG="clang"
AF_CLANGXX="clang++"
AF_LLVMCONFIG="llvm-config"
AF_AR="llvm-ar-9"
AF_LLVMLINK="llvm-link"
GCLANG="$ROOT/SVF/Release-build/bin/gclang"
GCLANGXX="$ROOT/SVF/Release-build/bin/gclang++"
GETBC="$ROOT/SVF/Release-build/bin/get-bc"

# Create key-value pairs for final fuzz target names for creating bitcode 
declare -A locs
locs["tidy"]="tidy"

build_target() {
echo "[X] Creating variant"
/bin/bash $DATA/sievefuzz_setup.sh
cd -
}

# Bitcode of target for the purpose of static analysis
make_bitcode() {
    # Sets up the Gclang to use clang-9.0 as the compiler
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/sievefuzz/third_party/SVF/Release-build

    export SVFHOME=$HOME/sievefuzz/third_party/SVF
    # export LLVM_DIR=$SVFHOME/llvm-10.0.0.obj
    export PATH=$LLVM_DIR/bin:$PATH

    export CC=$GCLANG
    export CXX=$GCLANGXX
    export CFLAGS="-g" 
    export LLVM_CONFIG=$AF_LLVMCONFIG
    export PREFIX=$OUTDIR/BITCODE

    clean_counters
    build_target
     
    # Create bitcode
    cd $OUTDIR/BITCODE
    echo ${locs[${TARGET}]}
    echo $PWD
    echo "$GETBC -a $AF_AR -l $AF_LLVMLINK ${locs[${TARGET}]}"
    $GETBC -a $AF_AR -l $AF_LLVMLINK ${locs[${TARGET}]}
    cd -
}

# Variant with function activation policy inferred through static analysis
make_sievefuzz() {
    # Setup environment variables
    export CC=$sievefuzz/afl-clang-fast
    export CXX=$sievefuzz/afl-clang-fast++
    export LLVM_CONFIG=$AF_LLVMCONFIG
    export AFL_CC=$AF_CLANG
    export AFL_CXX=$AF_CLANGXX
    export AFL_USE_ASAN=1
    export PREFIX=$OUTDIR/sievefuzz
    export ASAN_OPTIONS=detect_leaks=0

    clean_counters
    build_target

    # Copy over the function indices list
    cp /tmp/fn_indices.txt $OUTDIR/sievefuzz/fn_indices.txt
    cd -
    echo "[X] Please check that the two numbers are within delta of 1. If not, please re-run the script to build the target. This info is used to sanity-check that each function was assigned a unique ID" 
    cat /tmp/fn_indices.txt | wc -l && tail -n1 /tmp/fn_indices.txt
}


# These files are used for keeping track of intermediate state when generating
# sievefuzz-instrumented files 
clean_counters() {
    rm -f /tmp/fn_indices.txt
    rm -f /tmp/fn_counter.txt
}


# Script is being run to generate sievefuzz-opt variant
if [ "$MODE" = "sievefuzz" ]; then
    echo "[X] Generating sievefuzz-opt variant of target"
    rm -rf $OUTDIR/sievefuzz
    mkdir -p $OUTDIR/sievefuzz
    make_sievefuzz
    exit 0
fi

# Generate bitcode file for static analysis
if [ "$MODE" = "bitcode" ]; then
    echo "[X] Generating bitcode for target"
    rm -rf $OUTDIR/BITCODE
    mkdir -p $OUTDIR/BITCODE
    make_bitcode
    exit 0
fi
