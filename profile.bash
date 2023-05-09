#!/bin/bash

function ensure_exists {
    if [ ! -f $1 ]; then
	echo "$1 not found!"
	exit 1
    fi
}

psafe_bin=$1
psafe_safe=$2
psafe_pass=$3

ensure_exists $psafe_bin;
ensure_exists $psafe_safe;

log=log.profile.$$

valgrind --log-file=$log --tool=callgrind --dump-instr=yes --simulate-cache=yes --collect-jumps=yes $psafe_bin $psafe_safe "$psafe_pass"

echo $log
