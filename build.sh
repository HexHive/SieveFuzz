#!/bin/bash

# Being run inside a VM/userspace and not inside docker
if [ "$EUID" -ne 0 ]; then
    AF_ROOT=`pwd`
else
    AF_ROOT="/root/sievefuzz"
fi

# Get third_party tools
cd $AF_ROOT/third_party
./install_svf.sh
./install_sievefuzz.sh
