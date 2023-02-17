#!/bin/bash

cd SVF && source ./setup.sh && cd -
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/sievefuzz/third_party/SVF/Release-build
