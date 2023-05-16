# SieveFuzz

Code repository for the ACSAC '22 paper: One Fuzz Doesn’t Fit All: Optimizing
Directed Fuzzing via Target-tailored Program State Restriction.

The instructions pertaining to the artifact used for the experiments presented
in our paper are present in `artifact/`.

We present below the instructions to pull a docker image with a standalone
release as well as instructions on how to run it on a sample target.

# Run a sample target with SieveFuzz 

- Pull the docker image and spawn a shell inside it
```
docker pull prashast94/sievefuzz:standalone
docker run -it prashast94/sievefuzz:standalone /bin/bash
```
- Setup the test target with SieveFuzz instrumentation and also prepare its
bitcode file which is used to aid the static analysis module
```
cd /root/sievefuzz/eval
# Get the target source code
./get_sample_target.sh
# Create the bitcode file
./prep_target.sh tidy bitcode 
# Create the SieveFuzz variant
./prep_target.sh tidy sievefuzz
```

- Run a sample campaign using the beanstalk job server
```
# Run the beanstalk job deployment server
beanstalkd &
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

- You can validate that the fuzzers and the deployment scripts are working as
expected by running the below script which validates that the fuzzers are
working as expected by checking that its generating new inputs.
```
cd /root/sievefuzz/eval
./sanitycheck_run.sh
```
# Setting up a new target to test with SieveFuzz 

We provide a set of helper scripts to build the target with sievefuzz
instrumentation and also run the fuzzer with the static analysis module

- Create a folder for your new target inside `eval/data/newtarget` 

- Inside the folder place a `sievefuzz_setup.sh` script that instructs on how to build the target 
    - While not a strict requirement we recommend that the build is done using a single thread. This is to
      ensure that unique ID's are assigned to each function

- Add a key-value pair in `locs` present in `prep_target.sh`. This key value pair should be listed as follows:
    ```
    locs["newtarget"]="path/to/bin"
    ```
    - The path is the relative path where the final binary is placed by the built script. The use of this script is to automate the bitcode extraction process

- Run the following set of commands to create the bitcode file and the sievefuzz-instrumented file
```
cd /root/sievefuzz/eval
# Create the bitcode file
./prep_target.sh newtarget bitcode 
# Create the SieveFuzz variant
./prep_target.sh newtarget sievefuzz
# XXX: Ensure the two output numbers at the end of the above command are within
# a delta of 1.  This is to sanity-check unique numeric ID's were assigned to each function 
# during instrumentation phase
```

- Create a copy of `eval/sanitycheck.config` and make the following modifications (annotated below) to make it run on the new target
```
 {
        "mode": "sievefuzz",
        "static": "/root/sievefuzz/third_party/SVF/Release-build/bin/svf-ex",
        "get_indirect": "true",
        "fn_indices": "/root/sievefuzz/benchmarks/out_newtarget/sievefuzz/fn_indices.txt", <- Point this to newtarget
        "bitcode": "/root/sievefuzz/benchmarks/out_newtarget/BITCODE/bin.bc", <- Point this to the location of the bitcode
        "tagdir": "/root/sievefuzz/results/tidy/sievefuzz", <- Location where the fuzzing campaign results are put
        "dump_stats": "true",
        "function": "prvTidyInsertedToken", <- Specify the target function inside the fuzz target
        "input": "/root/sievefuzz/eval/data/seeds/simple", <- The location of the initial seed to be used
        "target": "/root/sievefuzz/benchmarks/out_newtarget/sievefuzz/bin", <- The location of the sievefuzz-instrumented target 
        "cmdline": "", <- Specify the parameters with which the fuzz target is to be run. If no arguments are specified the fuzz input is passed through stdin
        "output": "/root/sievefuzz/results/tidy/sievefuzz/output", <- The prefix for the output dirs. This means that all the output fuzz campaign folder will be of the form "output_XXX" where XXX is an integer ID
        "fuzztimeout": "300", <- The max time for which the campaign is to be run
        "fuzzer": "/root/sievefuzz/third_party/sievefuzz/afl-fuzz",
        "jobcount": 1, # The number of fuzzing campaigns to run
        "start_port": 6200, <- The port to be used to deploy the static analysis server. For each job a unique port is used.
        "afl_margs": "", <- Any additional arguments to run AFL with are specified heer 
        "mem_limit": "none",
        "env": {
            "AFL_NO_UI": "1"
         }
  }
```

- After this configuration file has been appropriately modified, you can use the below set of commands to deploy your jobs
```
# Run the beanstalk job deployment server
beanstalkd &
# Flush the job queue thrice to ensure that there are no stale jobs in the queue
python3 create_fuzz_script.py -c newtarget.config -n 15 --flush  
python3 create_fuzz_script.py -c newtarget.config -n 15 --flush  
python3 create_fuzz_script.py -c newtarget.config -n 15 --flush  

# Put the jobs in the queue
python3 create_fuzz_script.py -c newtarget.config -n 15 --put

# Get the jobs in the queue. 
# WARNING: `-n` represents the number of cores that # are available for #
# fuzzing. We recommend setting this number to roughly 95% of the available #
# cores.  So if you have 16 cores, we recommend using 15.
# Do not put `-n` greater than the number of cores that you may have available.
python3 create_fuzz_script.py -c newtarget.config -n 15 --get  
```

- If instead of using the job deployment infrastructure, you want to get the raw commands that are used to run
both the static analysis server and the fuzzing module, it can be done using the commands below:
```
# Put the jobs in the queue
python3 create_fuzz_script.py -c sanitycheck.config -n 15 --put

# Get the jobs from the queue but in dry mode (does not run the command but only outputs the command that would be run) 
python3 create_fuzz_script.py -c sanitycheck.config -n 15 --get --dry
```

- As an example, the output of the above command for the sanitycheck configuration would be
    ```
    :~/sievefuzz/eval# python3 create_fuzz_script.py -c sanitycheck.config -n 15 --get --dry 
    =================
    [X] Getting job:

    screen -d -m timeout 340 /root/sievefuzz/third_party/SVF/Release-build/bin/svf-ex -p=6200 --tag=/root/sievefuzz/results/tidy/sievefuzz/output_000/000 -f=prvTidyInsertedToken --get-indirect --activation=/root/sievefuzz/benchmarks/out_tidy/sievefuzz/fn_indices.txt --stat=false --run-server --dump-stats /root/sievefuzz/benchmarks/out_tidy/BITCODE/tidy.bc
    [X] Getting job:

    screen -d -m timeout 300 /root/sievefuzz/third_party/sievefuzz/afl-fuzz -m none -P 6200  -i /root/sievefuzz/eval/data/seeds/simple-o /root/sievefuzz  /results/tidy/sievefuzz/output_000 -- /root/sievefuzz/benchmarks/out_tidy/sievefuzz/tidy
    =================
    [X] No jobs left in queue
    ```
    - The `screen -d -m timeout <timeout>` are utilities that can be stripped off safely from the raw command. The first command corresponds to setting up the static analysis server and the second command corresponds to deploying sievefuzz


# Installing SieveFuzz from scratch

If instead of using the docker file you are interested in setting up sievefuzz from scratch. You can follow
the below set of instructions:

- Clone repo and change its name from `SieveFuzz` to `sievefuzz`
- Install dependencies from `apt` and `pip` as specified in the `docker/Dockerfile`
- If you are running inside a VM or your own workstation and have not setup the runtime environment for AFL++, please run the below script with `sudo` privileges. It will rename the core file to be generated with the name `core` and changes the CPU scaling governor (if it exists) to `performance`
    ```
    cd eval/
    sudo ./setup_fuzzer_env.sh
    ```
    - If the script ran succesfully it should output the following message at the end.
    ```
    [X] Runtime environment for fuzzers setup successfully
    ```
- Setup clang-9 as the default clang using `update-alternatives`
- Run `build.sh`
    - NOTE: While building SVF, there may be certain failed tests. This is
      expected behavior since these failing tests were inherited from the base
      commit of SVF on top of which SieveFuzz builds.  The functionality of our
      static analysis module was not observed to be affected by these failing
      regression tests hence they can be safely ignored.
- Copy over binaries inside `gllvm_bins` to
  `$HOME/sievefuzz/third_party/SVF/Release-build/bin/`. These are binaries used
  to extract whole-program bitcode using `gllvm`.
- Before compiling targets with sievefuzz instrumentation update `ROOT` inside `prep_target.sh` to point to the top-level directory where `sievefuzz` repo was cloned.
- Update `TARGET_DIR`, `OUTDIR`, `DATA` from `/root` to point to the top-level dir where sievefuzz is cloned.
    - The above path modification can be done for `get_sample_target.sh` and `sanitycheck_run.sh` as well
- Make appropriate path modifications to `sanitycheck.config` if you'll be using the job deployment infra
