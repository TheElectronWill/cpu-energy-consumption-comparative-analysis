#!/usr/bin/env zsh

set -eu
TEST=false

# like echo but to stderr
echoerr() {
    >&2 echo $@;
}

# benchmark parameters
typeset -a probes
typeset -A events
benchs=(cpu threads)
if [ $TEST = true ]; then
    probes=(none powercap-sysfs perf-event ebpf)
    freqs=(1)
    events[cpu]=10000
    events[threads]=1000
    repet=1
    WARMUP_COEFF=50
    REPET_WARMUP=1
else
    probes=(none powercap-sysfs perf-event ebpf none)
    #freqs=(1 10 100 500 1000)
    freqs=(1 100 500 1000)
    #events=(800000) #5000000 50000000) # 200_000 lasts approximately 30 seconds on a Thinkpad L15 Gen2
    events[cpu]=1000000
    events[threads]=40000
    repet=200
    WARMUP_COEFF=20000
    REPET_WARMUP=2
fi

# checks
if ! command -v sysbench &> /dev/null; then
    echoerr "sysbench is not installed, the benchmark will fail"
    exit 1
fi

# find binary
BINARY=$(echo ./userspace*)
if [ ! -f "$BINARY" ]; then
    BINARY="./target/release/userspace"
    if [ ! -f "$BINARY" ]; then
        echoerr "Could not find the `userspace` binary."
        exit 1
    fi
fi
chmod +x "$BINARY"

# print info
echoerr "userspace binary: $BINARY"
echoerr "benchmark types : $benchs"
echoerr "benchmark events: $events"
echoerr "repetitions     : $repet"
echoerr "rapl probes     : $probes"
echoerr "frequencies (Hz): $freqs"

# switch to performance mode
echoerr "enable performance mode"
if command -v powerprofilesctl &> /dev/null; then
    echoerr "using powerprofilesctl"
    powerprofilesctl set performance 1>&2
else
    echoerr "using x86_energy_perf_policy + cpupower"
    x86_energy_perf_policy performance 1>&2 || true
    cpupower frequency-set -g performance 1>&2
fi

# write csv header
echo "bench;probe;freq;n_events;"

# warm up to increase cpu temperature, and test that all probes work
n_cores=$(grep -c ^processor /proc/cpuinfo)
echoerr "======== Warming up ========"
for p in "$probes[@]"; do
    echoerr "Warming up with probe $p"
    n=$(($n_cores * $WARMUP_COEFF))
    "$BINARY" "$p" -b "cpu" -f 1 -n "$n" -r "$REPET_WARMUP" 1>&2
done

# HERE is the actual benchmark
repeat_bench() {
    "$BINARY" "$p" -b "$b" -f "$f" -n "$n" -r "$repet"
}

# bench loop to test all the modalities
for b in "$benchs[@]"; do
    echoerr "======== Benchmark $b ========"
    for p in "$probes[@]"; do
        echoerr "===== Probe $p ====="
	    n=${events[$b]}
        if [ "$p" = "none" ]; then
            f=1
            repeat_bench
        else
            for f in "$freqs[@]"; do
                repeat_bench
            done
        fi
    done
done

# disable performance mode
echoerr "disable performance mode"
if command -v powerprofilesctl &> /dev/null; then
    echoerr "using powerprofilesctl"
    powerprofilesctl set balanced 1>&2
else
    x86_energy_perf_policy default 1>&2 || true
    cpupower frequency-set -g ondemand 1>&2
fi
