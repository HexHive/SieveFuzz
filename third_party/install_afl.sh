#!/bin/bash

# get AFL (used for AreaFuzz modifications)
if [ ! -d AFL_AF ]; then
git clone https://github.com/AFLplusplus/AFLplusplus AFL_AF
cd AFL_AF && git reset --hard 70a67c && cd -

# Link AFL-specific files
echo "Patching afl-fuzz.c..."
rm AFL_AF/src/afl-fuzz.c
ls -lh `pwd`/../patches/afl/afl-fuzz.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz.c AFL_AF/src || exit 1

echo "Patching afl-fuzz-queue.c..."
rm AFL_AF/src/afl-fuzz-queue.c
ls -lh `pwd`/../patches/afl/afl-fuzz-queue.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz-queue.c AFL_AF/src || exit 1

echo "Patching afl-fuzz-globals.c..."
rm AFL_AF/src/afl-fuzz-globals.c
ls -lh `pwd`/../patches/afl/afl-fuzz-globals.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz-globals.c AFL_AF/src || exit 1

echo "Patching afl-fuzz-run.c..."
rm AFL_AF/src/afl-fuzz-run.c
ls -lh `pwd`/../patches/afl/afl-fuzz-run.c || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz-run.c AFL_AF/src || exit 1

echo "Patching afl-fuzz.h..."
rm AFL_AF/include/afl-fuzz.h
ls -lh `pwd`/../patches/afl/afl-fuzz.h || exit 1
ln -s `pwd`/../patches/afl/afl-fuzz.h AFL_AF/include || exit 1

echo "Patching afl-sharedmem.c..."
rm AFL_AF/src/afl-sharedmem.c
ls -lh `pwd`/../patches/afl/afl-sharedmem.c || exit 1
ln -s `pwd`/../patches/afl/afl-sharedmem.c AFL_AF/src || exit 1

echo "Patching config.h..."
rm AFL_AF/include/config.h
ls -lh `pwd`/../patches/afl/config.h || exit 1
ln -s `pwd`/../patches/afl/config.h AFL_AF/include || exit 1

echo "Adding helper.h..."
if [ ! -f AFL_AF/include/helper.h ]; then
ls -lh `pwd`/../patches/afl/helper.h || exit 1 
ln -s `pwd`/../patches/afl/helper.h AFL_AF/include || exit 1
fi

echo "Adding utarray.h..."
if [ ! -f AFL_AF/include/utarray.h ]; then
ls -lh `pwd`/../patches/afl/utarray.h || exit 1 
ln -s `pwd`/../patches/afl/utarray.h AFL_AF/include || exit 1
fi

echo "Patching Makefile in AFL_AF/llvm_mode..."
rm AFL_AF/llvm_mode/Makefile
ls -lh `pwd`/../patches/afl/Makefile_AFL_llvm_mode || exit 1
ln -s `pwd`/../patches/afl/Makefile_AFL_llvm_mode AFL_AF/llvm_mode/Makefile || exit 1

echo "Patching Makefile in AFL_AF..."
rm AFL_AF/Makefile
ls -lh `pwd`/../patches/afl/Makefile_AFL || exit 1
ln -s `pwd`/../patches/afl/Makefile_AFL AFL_AF/Makefile || exit 1

echo "Patching afl-llvm-pass.c..."
rm AFL_AF/llvm_mode/afl-llvm-pass.so.cc
ls -lh `pwd`/../patches/afl/afl-llvm-pass.so.cc || exit 1 
ln -s `pwd`/../patches/afl/afl-llvm-pass.so.cc AFL_AF/llvm_mode/afl-llvm-pass.so.cc || exit 1

echo "Patching afl-llvm-rt.o.c..."
rm AFL_AF/llvm_mode/afl-llvm-rt.o.c
ls -lh `pwd`/../patches/afl/afl-llvm-rt.o.c || exit 1 
ln -s `pwd`/../patches/afl/afl-llvm-rt.o.c AFL_AF/llvm_mode/afl-llvm-rt.o.c || exit 1

echo "Patching fn_bit.txt..."
if [ ! -f AFL_AF/llvm_mode/fn_bit.txt ]; then
ln -s `pwd`/../patches/afl/fn_bit.txt AFL_AF/llvm_mode/fn_bit.txt || exit 1
fi

echo "Building AFL_AF..."
cd AFL_AF
rm -f /tmp/fn_indices.txt /tmp/fn_counter.txt /tmp/log.txt
AF=1 TRACE_METRIC=1 CC=clang-9 CXX=clang++-9 LLVM_CONFIG=llvm-config-9 make all -j $(nproc) || exit 1
cd llvm_mode
AF=1 TRACE_METRIC=1 CC=clang-9 CXX=clang++-9 LLVM_CONFIG=llvm-config-9 make all -j $(nproc) || exit 1
cd ../../
fi
