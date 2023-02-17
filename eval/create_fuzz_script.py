'''
This module creates a bash script to run single-core campaigns as specified by
a configuration file
'''

import argparse
import json
import os
import subprocess
import sys
import greenstalk
import time
import pprint
import psutil

# Specify where the beanstalk server is running
HOST="127.0.0.1"
PORT="11300"

# Specify the max number of single-core campaigns to be allowed
# to be run at any given time
MAX_JOBS=None
# Records the number fo server screen sessions which need to be discounted when calculating 
# the actual number of campaigns that are running
# MAX_JOBS=2
# Specify (in seconds) the polling interval for available cores
TIMEOUT=60
# Specify the time between jobs being deployed (in seconds)
JOB_INTERVAL=30
# TIMEOUT=30

def read_config(config_file):
    config_file = os.path.abspath(os.path.expanduser(config_file))

    if not os.path.isfile(config_file):
        print("Config file not found!")
        sys.exit(1)

    with open(config_file, "r") as f:
        config = json.load(f)

        return config

def afl_cmdline_from_config(config_settings, instance_number):
    # if 'aflgo' in config_settings["fuzzer"]:
    #     afl_cmdline = ['timeout %s' % (config_settings["fuzztimeout"]), config_settings["fuzzer"]]
    # else:
    #     afl_cmdline = [config_settings["fuzzer"]] 
    afl_cmdline = ['timeout %s' % (config_settings["fuzztimeout"]), config_settings["fuzzer"]]

    if "timeout" in config_settings:
        afl_cmdline.append("-t")
        afl_cmdline.append(config_settings["timeout"])

    # if "fuzztimeout" in config_settings:
    #     # AFLGo fuzzer does not have "-V" capability
    #     if 'aflgo' in config_settings["fuzzer"]: 
    #         pass
    #     else:
    #         afl_cmdline.append("-V")
    #         afl_cmdline.append(config_settings["fuzztimeout"])

    if "mem_limit" in config_settings:
        afl_cmdline.append("-m")
        afl_cmdline.append(config_settings["mem_limit"])

    if "start_port" in config_settings:
        afl_cmdline.append("-P " + str(config_settings["start_port"] + instance_number))

    if "afl_margs" in config_settings:
        afl_cmdline.append(config_settings["afl_margs"])

    if "input" in config_settings:
        afl_cmdline.append("-i")
        afl_cmdline.append(config_settings["input"])

    # Create instance-specific output directory 
    if "output" in config_settings:
        afl_cmdline.append("-o")
        afl_cmdline.append(config_settings["output"] + "_%03d" % instance_number)

    return afl_cmdline


def build_target_cmd(conf_settings):
    target_cmd = [conf_settings["target"], conf_settings["cmdline"]]
    target_cmd = " ".join(target_cmd).split()
    target_cmd[0] = os.path.abspath(os.path.expanduser(target_cmd[0]))
    if not os.path.exists(target_cmd[0]):
        print("Target binary %s not found!" % (target_cmd[0]))
        sys.exit(1)
    target_cmd = " ".join(target_cmd)
    return target_cmd


def build_fuzz_cmd(conf_settings, instance_number, target_cmd):
    # compile command-line for fuzz instance 
    # $ afl-fuzz -i <input_dir> -o <output_dir> -- </path/to/target.bin> <target_args>
    tmp_cmd = afl_cmdline_from_config(conf_settings, instance_number)
    tmp_cmd += ["--", target_cmd]
    fuzz_cmd = " ".join(tmp_cmd)
    return fuzz_cmd 

def build_static_cmd(conf_settings, instance_number):
    global JOB_INTERVAL
    # Add job interval time to static analysis server so as to ensure it does not end preemptively because fuzzer job lags behind
    # server being employed by JOB_INTERVAL seconds
    # Add a 10s buffer due to time taken for AFL to instantiate itself as well
    static_cmdline = ["timeout %s" % (str(int(conf_settings["fuzztimeout"]) + JOB_INTERVAL + 10))]
    static_cmdline.append(conf_settings["static"])
    static_cmdline.append("-p=" + str(conf_settings["start_port"] + instance_number))
    static_cmdline.append("--tag=" + os.path.join(conf_settings["tagdir"], "output_%03d" % instance_number, "%03d" % instance_number))
    static_cmdline.append("-f=" + conf_settings["function"])
    if conf_settings["get_indirect"] == "true":
        static_cmdline.append("--get-indirect")
    static_cmdline.append("--activation=" + conf_settings["fn_indices"])
    static_cmdline.append("--stat=false")
    static_cmdline.append("--run-server")
    if conf_settings["dump_stats"] == "true":
        static_cmdline.append("--dump-stats")
    static_cmdline.append(conf_settings["bitcode"])

    return " ".join(static_cmdline)

    


def main():
    parser = argparse.ArgumentParser(description="Creates bash script to run fuzzing instances in parallel")
    parser.add_argument("-c", 
            "--config", 
            dest = "config_file",
            help = "Config file for fuzzing experiment", 
            default = None
            )
    parser.add_argument("-d",
            "--dry",
            dest = "is_dry",
            action = "store_true",
            default = False,
            help = "Run in dry mode")
    parser.add_argument("-n",
            "--numcores",
            dest = "numcores",
            type = int,
            required = True,
            help = "Specify the number of cores that are available for fuzzing. We recommend setting it to `nprocs`-1")
    parser.add_argument("--put",
            action = "store_true",
            help = "Put jobs in the beanstalk queue as specified in the config file")
    parser.add_argument("--get",
            action = "store_true",
            help = "Get jobs from the beanstalk queue")
    parser.add_argument("--flush",
            action = "store_true",
            help = "Flush jobs from the beanstalk queue")
            

    args = parser.parse_args()
    global MAX_JOBS
    MAX_JOBS = args.numcores
    
    if args.config_file:
        conf_settings = read_config(os.path.abspath(os.path.expanduser(args.config_file)))
    
    if args.put:
        # Iterate through each job and put them on the queue
        for item in conf_settings:
            put(item, args.is_dry)
    elif args.get:
        get(args.is_dry)
    elif args.flush:
        flush()
    else:
        print ("[X] Unknown mode passed (get/push/flush)")
        exit(1)

def put(conf_settings, isdry):
    global HOST, PORT

    # Get the Beanstalk queue 
    queue = greenstalk.Client(
            (HOST, int(PORT)), 
            use = 'jobs', watch = ['jobs'])

    # Create jobs and put them in the queue
    conf_settings["output"] = os.path.abspath(os.path.expanduser(conf_settings["output"]))

    target_cmd = build_target_cmd(conf_settings)
    for i in range(0, conf_settings["jobcount"]):
        job = {}
        # For sievefuzz, we need to generate two commands: 1) fuzzer, and 2) static analysis server
        if conf_settings["mode"] == "sievefuzz" or conf_settings["mode"] == "sievefuzz_noasan":
            # This ordering of static analysis server before fuzzer is important to ensure that the static analysis
            # server is run before during job deployement
            job["cmd"] = [build_static_cmd(conf_settings, i), build_fuzz_cmd(conf_settings, i, target_cmd)]
        else:
            job["cmd"] = [build_fuzz_cmd(conf_settings, i, target_cmd)]
        job["env"] = conf_settings["env"]
        if isdry:
            print ("[X] Putting job:\n")
            pprint.pprint(job)
        else:
            print ("[X] Putting job:\n")
            pprint.pprint(job)
            queue.put(json.dumps(job))

def get(is_dry):
    global HOST, PORT, MAX_JOBS, TIMEOUT, JOB_INTERVAL

    # Get the Beanstalk queue 
    queue = greenstalk.Client(
            (HOST, int(PORT)), 
            use = 'jobs', watch = ['jobs'])

    while True:
        print("=================")
        active_jobs = get_running_jobs()
        assert active_jobs <= MAX_JOBS, 'More screen sessions exist than allowed to be spawned. Please investigate further'

        # If the ready queue is empty just exit
        stats = queue.stats_tube('jobs')
        if not stats["current-jobs-ready"]:
            print ('[X] No jobs left in queue')
            exit(0)

        # Check if all available cores occupied (as per MAXJOBS) and there are still jobs waiting to be finished
        if (active_jobs == MAX_JOBS):
            print ('[X] All available cores occupied..sleeping for %d seconds' % (TIMEOUT)) 
            print ('[X] Jobs remaining to be completed:', queue.stats_tube('jobs')["current-jobs-ready"])
            # Sleep and check back again
            time.sleep(TIMEOUT) 
            continue

        job = queue.reserve()
        queue.bury(job)
        current = json.loads(job.body)
        cmd_strings, env = current["cmd"], current["env"]
        for cmd in cmd_strings:
            final_cmd = " ".join(['screen -d -m', cmd])

            # Setup environment variables
            base_env = os.environ.copy()
            for key, val in env.items():
                base_env[key] = val

            # Deploy the campaign
            if is_dry:
                print("[X] Getting job:\n")
                print(final_cmd)
            else:
                print ("\nDeploying: %s" % (final_cmd))
                subprocess.Popen(final_cmd, env = base_env, shell = True)
                # Insert sleep to ensure that server has enough time to get setup before the fuzzer is run 
                time.sleep(JOB_INTERVAL)

def get_running_jobs():
    '''
    Gets the number of active fuzzcampaigns
    '''
    count = 0
    while True:
        count = 0
        try:
            for p in psutil.process_iter():
                if 'screen' in p.name() and not (any("svf-ex" in item for item in p.cmdline())):
                    count += 1
            break
        except psutil.NoSuchProcess:
            print ('[X] Error occurred...counting processes again')
            pass
    return count 

def flush():
    global HOST, PORT

    # Get the Beanstalk queue location
    queue = greenstalk.Client(
            (HOST, int(PORT)), 
            use = 'jobs', watch = ['jobs'])

    stats = queue.stats_tube('jobs')
    print (stats)
    for idx in range(0, stats['current-jobs-ready']):
        job = queue.reserve()
        queue.delete(job)
    if stats['current-jobs-buried']:
        queue.kick(stats['current-jobs-buried'])
        for idx in range(0, stats['current-jobs-ready']):
            job = queue.reserve()
            queue.delete(job)


if __name__ == "__main__":
    main()
