#!/usr/bin/env bash

set -e

# Root cb-multios directory
DIR=$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)
TOOLS="$DIR/tools"

echo "Creating build directory"
mkdir -p ${DIR}/build
cd ${DIR}/build

echo "Creating Makefiles"
CMAKE_OPTS="${CMAKE_OPTS} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"

# Honor CC and CXX environment variables, default to clang otherwise
CC=${CC:-clang}
CXX=${CXX:-clang++}

CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_C_COMPILER=$CC"
CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_ASM_COMPILER=$CC"
CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_CXX_COMPILER=$CXX"

LINK=${LINK:-SHARED}
case $LINK in
    SHARED) CMAKE_OPTS="$CMAKE_OPTS -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF";;
    STATIC) CMAKE_OPTS="$CMAKE_OPTS -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON";;
esac

# Prefer ninja over make, if it is available
if which ninja 2>&1 >/dev/null; then
  CMAKE_OPTS="-G Ninja $CMAKE_OPTS"
  BUILD_FLAGS=
else
  # BUILD_FLAGS="-- -j$(getconf _NPROCESSORS_ONLN)"
  BUILD_FLAGS=
fi

cmake $CMAKE_OPTS ..

cmake --build . $BUILD_FLAGS -- -j 1
