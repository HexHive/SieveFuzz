#!/bin/bash

# This script validates that the fuzzers are setup correctly by checking if
# there are non-empty queue directories showing that its generating new inputs

EXPDIR="/root/sievefuzz/results/tidy" # The result dir for the target for which the fuzzer is being run 
DIRS="sievefuzz" # Directories corresponding to the fuzzers

check_dir() {
	echo "Checking $1"
	if [ -d $1 ]; then
		if [ -n "$(find $1 -prune -empty -type d 2>/dev/null)" ]; then
			ISEMPTY=1
		else
			ISEMPTY=0
		fi
	else
                ISEMPTY=1
	fi
}

for DIR in $DIRS; do
	RESULTDIR=$EXPDIR/$DIR/output_000/queue
	check_dir $RESULTDIR
	# echo $ISEMPTY
	if [ $ISEMPTY -eq "1" ]; then
		echo "Empty/non-existent directory detected for queue folder, please check fuzzer configuration"
 		exit 1
	fi
done

echo "Sanity-checked the fuzz campaign folders, fuzzers and deployment pipeline setup successfully"
