#!/bin/bash

# get AFL (used for SieveFuzz modifications)
if [ ! -d sievefuzz ]; then
git clone https://github.com/AFLplusplus/AFLplusplus sievefuzz
cd sievefuzz && git reset --hard 70a67c && cd -

# Link AFL-specific files
echo "Patching afl-fuzz.c..."
rm sievefuzz/src/afl-fuzz.c
ls -lh `pwd`/../patches/afl/afl-fuzz.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz.c sievefuzz/src || exit 1

echo "Patching afl-fuzz-queue.c..."
rm sievefuzz/src/afl-fuzz-queue.c
ls -lh `pwd`/../patches/afl/afl-fuzz-queue.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz-queue.c sievefuzz/src || exit 1

echo "Patching afl-fuzz-globals.c..."
rm sievefuzz/src/afl-fuzz-globals.c
ls -lh `pwd`/../patches/afl/afl-fuzz-globals.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz-globals.c sievefuzz/src || exit 1

echo "Patching afl-fuzz-run.c..."
rm sievefuzz/src/afl-fuzz-run.c
ls -lh `pwd`/../patches/afl/afl-fuzz-run.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz-run.c sievefuzz/src || exit 1

echo "Patching afl-fuzz.h..."
rm sievefuzz/include/afl-fuzz.h
ls -lh `pwd`/../patches/afl/afl-fuzz.h || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz.h sievefuzz/include || exit 1

echo "Patching afl-sharedmem.c..."
rm sievefuzz/src/afl-sharedmem.c
ls -lh `pwd`/../patches/afl/afl-sharedmem.c || exit 1
ln -s `pwd`/../patches/afl/afl-sharedmem.c sievefuzz/src || exit 1

echo "Patching config.h..."
rm sievefuzz/include/config.h
ls -lh `pwd`/../patches/afl/config.h || exit 1
ln -s `pwd`/../patches/afl/config.h sievefuzz/include || exit 1

echo "Adding helper.h..."
if [ ! -f sievefuzz/include/helper.h ]; then
ls -lh `pwd`/../patches/afl/helper.h || exit 1 
ln -s `pwd`/../patches/afl/helper.h sievefuzz/include || exit 1
fi

echo "Adding utarray.h..."
if [ ! -f sievefuzz/include/utarray.h ]; then
ls -lh `pwd`/../patches/afl/utarray.h || exit 1 
ln -s `pwd`/../patches/afl/utarray.h sievefuzz/include || exit 1
fi

echo "Patching Makefile in sievefuzz/llvm_mode..."
rm sievefuzz/llvm_mode/Makefile
ls -lh `pwd`/../patches/afl/Makefile_AFL_llvm_mode || exit 1
ln -s `pwd`/../patches/afl/Makefile_AFL_llvm_mode sievefuzz/llvm_mode/Makefile || exit 1

echo "Patching Makefile in sievefuzz..."
rm sievefuzz/Makefile
ls -lh `pwd`/../patches/afl/Makefile_AFL || exit 1
ln -s `pwd`/../patches/afl/Makefile_AFL sievefuzz/Makefile || exit 1

echo "Patching afl-llvm-pass.c..."
rm sievefuzz/llvm_mode/afl-llvm-pass.so.cc
ls -lh `pwd`/../patches/afl/afl-llvm-pass.so.cc || exit 1 
ln -s `pwd`/../patches/afl/afl-llvm-pass.so.cc sievefuzz/llvm_mode/afl-llvm-pass.so.cc || exit 1

echo "Patching afl-llvm-rt.o.c..."
rm sievefuzz/llvm_mode/afl-llvm-rt.o.c
ls -lh `pwd`/../patches/afl/afl-llvm-rt.o.c || exit 1 
ln -s `pwd`/../patches/afl/afl-llvm-rt.o.c sievefuzz/llvm_mode/afl-llvm-rt.o.c || exit 1

echo "Patching fn_bit.txt..."
if [ ! -f sievefuzz/llvm_mode/fn_bit.txt ]; then
ln -s `pwd`/../patches/afl/fn_bit.txt sievefuzz/llvm_mode/fn_bit.txt || exit 1
fi

echo "Building sievefuzz..."
cd sievefuzz
rm -f /tmp/fn_indices.txt /tmp/fn_counter.txt /tmp/log.txt
AF=1 TRACE_METRIC=1 CC=clang-9 CXX=clang++-9 LLVM_CONFIG=llvm-config-9 make all -j $(nproc) || exit 1
cd llvm_mode
AF=1 TRACE_METRIC=1 CC=clang-9 CXX=clang++-9 LLVM_CONFIG=llvm-config-9 make all -j $(nproc) || exit 1
cd ../../
fi
