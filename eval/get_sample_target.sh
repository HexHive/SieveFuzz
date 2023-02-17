#!/bin/bash

# This downloads the sample target 

TARGET_DIR="/root/sievefuzz/benchmarks"
mkdir -p $TARGET_DIR

# Unpack tidy 
if [ ! -d $TARGET_DIR/tidy ]; then
    cd "$TARGET_DIR/../eval/data/tidy"
    mkdir -p $TARGET_DIR/tidy
    tar -xf tidy.tar.gz --strip-components=1 -C $TARGET_DIR/tidy
    cp Makefile_tidy $TARGET_DIR/tidy/build/gmake/Makefile
fi

