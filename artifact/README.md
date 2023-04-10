This folder holds all the instructions pertaining to reproducing the results in our paper.

# Setup

## Setup docker

- Install docker by following instructions for Ubuntu [here](https://docs.docker.com/engine/install/ubuntu/)
- After installation, configure Docker to make it run as a non-root user using instructions [here](https://docs.docker.com/engine/install/linux-postinstall/)

## Acquiring the image

- Pull the docker image from docker-hub
```
docker pull prashast94/sievefuzz:artifact
```
- Download the raw campaign results (`results_raw` folder) from the google drive folder listed [here](https://drive.google.com/drive/folders/1ZnHr28Quk7OiGv8c-o63aecr0KS-GOUh).

- After downloading the folder, in its parent directory run the image with the option to mount the folder containing the results into the docker image using the below command
```
docker run -d --name="sievefuzz_artifact" -it -v $PWD/results_raw:/root/areafuzz/results --network='host' --cap-add=SYS_PTRACE prashast94/sievefuzz:artifact /bin/bash
```
- Connect to the named image
```
docker exec -it sievefuzz_artifact /bin/bash
```

# Reproducing results from the paper (Estimated Time: 3.5 hours) 

We provide scripts and raw data that can be used to reproduce the results from the paper

- Untar the provided raw data
```
cd results
tar -xf aflxgo_paperexp.tar.gz
tar -xf beacon_paperexp.tar.gz
```

- Build the fuzz targets that would be used to validate the results in the evaluation section (Estimated Time: 2.5 hours)
```
# Un-tar the source code of all the fuzz targets
cd /root/areafuzz/eval 
./get_targets.sh

# Create all targets corresponding to experimental evaluation of SieveFuzz against AFLGo and AFL++ (Estimated time: 1h 45 mins)
./create_all.sh

# Create all targets corresponding to experimental evaluation of SieveFuzz against BEACON (Estimated time: 25 minutes)
./create_all_beacon.sh
```

## RQ1: Tripwiring Search Space Restriction (Estimated Time: 2 minutes) 

- Generate the timing data for the tripwiring algorithm from scratch as well as
some of the raw data to calculate the amount of state space tripwired.
```
cd /root/areafuzz/post_eval
./get_analysis_times.sh
```

- Run the below command to generate the `Reduction %` in Table 2
```
cd /root/areafuzz/post_eval  
python3.5 retrieve_results.py -c aflxgo_config.json -m percfunctions -b CROMU_00039 KPRCA_00038 KPRCA_00051 gif2tga jasper listswf mjs tidy tiffcp -o out_percfunctions_aflxgo.json
```

- Run the below command to generate the results corresponding to time spent running the tripwiring algorithm in Table 2
```
cd /root/areafuzz/post_eval
python3.5 retrieve_results.py -c aflxgo_config.json -m analysis -b CROMU_00039 KPRCA_00038 KPRCA_00051 gif2tga jasper listswf mjs tidy tiffcp -o out_analysis_aflxgo.json
```

## RQ2: Targeted Defect Discovery (Estimated time: 1 hour)

- Use the provided raw data to reproduce the timing results presented in Table
3 representing the comparative evaluation of SieveFuzz against AFL++ and
AFLGo. The table should be output at the end. (Estimated time: 45 minutes)
```
cd /root/areafuzz/post_eval
python3.5 retrieve_results.py -c aflxgo_config.json -m time -b CROMU_00039 KPRCA_00038 KPRCA_00051 gif2tga jasper listswf mjs tidy tiffcp-1 tiffcp-2 -o out_time_aflxgo.json
```
- Use the provided raw data to reproduce the timing results presented in Table
4 representing the comparative evaluation of SieveFuzz against Beacon. The
table should be output at the end. (Estimated time: 15 minutes)
```
cd /root/areafuzz/post_eval
# Copy over ASAN-enabled binaries where the original fuzz targets were there to enable accurate bug triaging
./copy_over.sh
# Run the script
python3.5 retrieve_results.py -c beacon_config.json -m time -b CROMU_00039 KPRCA_00038 gif2tga jasper listswf tiffcp-1 tiffcp-2 -o out_time_beacon.json
```

- Use the provided raw data to reproduce the throughput comparison results against Beacon in Table 5. The table itself should be output at the end of the script.
```
python3.5 retrieve_results.py -c beacon_config.json -m throughput -b CROMU_00039 KPRCA_00038 gif2tga jasper listswf tiffcp-1 tiffcp-2 -o out_throughput_beacon.json
```

## RQ3: Target Location Feasibility for Tripwiring 

- Use the provided raw data to output the Figure 5 (`correlation.pdf`) and calculate the Spearman's rank order correlation which should be output at the end of the script. 
```
python3.5 retrieve_results.py -c aflxgo_config.json -m correlation -o out_correlation.json
```

# Run limited version of fuzzing campaigns to sanity check evaluation pipeline (Estimated time: 5 minutes)

Since running the entire gamut of experiments as described below would take
more than a years' worth of CPU time, we provide a small-scale run of the
evaluation to just sanity-check that the fuzzers and the evaluation pipeline is
setup successfully.

- Deploy the beanstalk server which will act as the job queue manager
```
beanstalkd &
```
- Run a sanity-check configuration deploying campaigns for one of the evaluation targets
with three fuzzers (AFL++, AFLGo, and SieveFuzz) for 5 minutes.  While
following the below instructions do note the advisory we place around the `-n`
arguments which tells the number of cores that are to be used for the fuzzing
campaign. We recommend setting this number to roughly 95% of the available #
cores.  So if you have 16 cores, we recommend using 15.  Do not put `-n`
greater than the number of cores that you may have available.
```
cd /root/areafuzz/eval

# Create directories where the results will be held
./make_dirs.sh /root/areafuzz/results/exp_sanity

# Flush the job queue thrice to ensure that there are no stale jobs in the queue
python3 create_fuzz_script.py -c sanitycheck.config -n 15 --flush  
python3 create_fuzz_script.py -c sanitycheck.config -n 15 --flush  
python3 create_fuzz_script.py -c sanitycheck.config -n 15 --flush  

# Put the jobs in the queue
python3 create_fuzz_script.py -c sanitycheck.config -n 15 --put

# Get the jobs in the queue. 
# WARNING: `-n` represents the number of cores that # are available for #
# fuzzing. We recommend setting this number to roughly 95% of the available #
# cores.  So if you have 16 cores, we recommend using 15.
# Do not put `-n` greater than the number of cores that you may have available.
python3 create_fuzz_script.py -c sanitycheck.config -n 15 --get  
```

- Validate that the fuzzers and the deployment scripts are working as expected
by running the below script which validates that the fuzzers are working as
expected by checking that its generating new inputs.
```
cd /root/areafuzz/eval
./sanitycheck_run.sh
```


# Run all fuzzing campaigns from scratch (Estimated time: 410 CPU days) 

If you would like to run all the fuzzing campaigns from scratch using the
configuration described in the paper, the following instructions can be
followed: 

In case beanstalk server is not already setup as specified previously in the sanity-check section, please do
so by running the following command:
```
beanstalkd &
```
## Comparative evaluation against AFL++ and AFLGo (Estimated time: 280 CPU days) 

- Run the fuzzing campaigns for all targets corresponding to the experimental
evaluation against AFL++ and AFLGo. Do note that this set of experiments
requires 6720 CPU hours to run. The reason is we will need to run 10 24-hour
campaigns for three fuzzers against 10 targets. While following the below instructions
do note the advisory we place around the `-n` arguments which tells the number of cores that are to be used for the fuzzing campaign 
```
# Create directories where the results will be held
./make_dirs.sh /root/areafuzz/results/exp_aflxgo_new

# Flush the job queue thrice to ensure that there are no stale jobs in the queue
python3 create_fuzz_script.py -c aflxgo.config -n 15 --flush  
python3 create_fuzz_script.py -c aflxgo.config -n 15 --flush  
python3 create_fuzz_script.py -c aflxgo.config -n 15 --flush  

# Put the jobs in the queue
python3 create_fuzz_script.py -c aflxgo.config -n 15 --put

# Get the jobs in the queue. 
# WARNING: `-n` represents the number of cores that # are available for #
# fuzzing. We recommend setting this number to roughly 95% of the available #
# cores.  So if you have 16 cores, we recommend using 15.
# Do not put `-n` greater than the number of cores that you may have available.
python3 create_fuzz_script.py -c aflxgo.config -n 15 --get  
```
- Once the campaigns are finished, they can be analyzed to generate the time to
discovery results in Table 3 using the below command: 
```
cd /root/areafuzz/post_eval
python3.5 retrieve_results.py -c aflxgo_config_new.json -m time -b CROMU_00039 KPRCA_00038 KPRCA_00051 gif2tga jasper listswf mjs tidy tiffcp-1 tiffcp-2 -o out_time_aflxgo_new.json
```
## Comparative evaluation against BEACON (Estimated time: 130 CPU days) 

- Re-create the binaries without ASAN for comparison against BEACON since you
  might have replaced them when reproducing the results from the paper using
  the provided raw data.
  ```
  ./create_all_beacon.sh
  ```

- Run the fuzzing campaigns for all targets corresponding to the experimental
evaluation against BEACON. Do note that this set of experiments
requires 3120 CPU hours to run. The reason is we will need to run 10 24-hour
campaigns for two fuzzers against 7 targets. While following the below instructions
do note the advisory we place around the `-n` arguments which tells the number of cores that are to be used for the fuzzing campaign 
```
# Create directories where the results will be held
./make_dirs.sh /root/areafuzz/results/exp_beacon_new

# Flush the job queue thrice to ensure that there are no stale jobs in the queue
python3 create_fuzz_script.py -c beacon.config -n 15 --flush  
python3 create_fuzz_script.py -c beacon.config -n 15 --flush  
python3 create_fuzz_script.py -c beacon.config -n 15 --flush  

# Put the jobs in the queue
python3 create_fuzz_script.py -c beacon.config -n 15 --put

# Get the jobs in the queue. 
# WARNING: `-n` represents the number of cores that # are available for #
# fuzzing. We recommend setting this number to roughly 95% of the available #
# cores.  So if you have 16 cores, we recommend using 15.
# Do not put `-n` greater than the number of cores that you may have available.
python3 create_fuzz_script.py -c beacon.config -n 15 --get  
```

- Once the campaigns are finished, they can be analyzed to generate Table 4 using the below commands
```
cd /root/areafuzz/post_eval

# This script replaces the non-asan instrumented versions of the fuzz targets with 
# asan instrumented ones to enable accurate crash triaging
./copy_over.sh

# Run the timing script
python3.5 retrieve_results.py -c beacon_config_new.json -m time -b CROMU_00039 KPRCA_00038 gif2tga jasper listswf tiffcp-1 tiffcp-2 -o out_time_beacon_new.json
```

# Naming convention

Even though the output tables by the scripts have the correct terminology as
used in the paper. There are places internally where we could not update due to
lack of time.  `AreaFuzz/F5` refers to SieveFuzz, `B1/baseline` refers to
AFL++, `aflgo and BEACON` are self-explanatory.

# Point of Contact

Prashast Srivastava (srivas41@purdue.edu)
