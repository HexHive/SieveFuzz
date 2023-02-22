#!/bin/bash

# Pre-requisites for setting up  environment for the fuzzers 
sudo bash -c "echo core >/proc/sys/kernel/core_pattern"
cd /sys/devices/system/cpu

# If running inside a VM there will be no scaling governor
if [ -f cpu0/cpufreq/scaling_governor ]; then
    sudo bash -c "echo performance | tee cpu*/cpufreq/scaling_governor"
fi

echo "[X] Runtime environment for fuzzers setup successfully"

cd -
