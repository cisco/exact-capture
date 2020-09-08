# Performance Tuning

Ensuring that the correct options and server settings ensures that exact-capture is running in an optimal manner. This document will detail a number of performance tuning techniques that can be used to improve the behaviour of exact-capture.

## Getting started

The ExaNIC documentation covers a number of useful tuning techniques in order to ensure that ExaNICs are being used in an optimal manner. Many of these optimizations will also improve capture performance. The user should consult the following sections of the ExaNIC benchmarking guide before reading on:

- [BIOS Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#bios-configuration)
- [Kernel Build Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#kernel-build-configuration)
- [Kernel Boot Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#kernel-build-configuration)
- [Hardware Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#hardware-configuration)

## NUMA systems

On multi-socket systems, users should take care to ensure that capture hardware is local to a single socket. Pushing capture traffic over a CPU interconnect will lead to suboptimal capture performance, as traffic may be bottlenecked by this inter-CPU connection.

The output of `lspci` can be used to determine the NUMA locality of installed hardware. On a server which has two ExaNICs and one ExaDisk installed, the NUMA locality can be quickly determined:

```
[root@capture ~]# lspci -d 1ce4: -vvv |grep NUMA
        NUMA node: 1
        NUMA node: 1
        NUMA node: 1
        NUMA node: 1
        NUMA node: 1
        NUMA node: 1
        NUMA node: 1
        NUMA node: 1
```

Once the node of the installed hardware is known, the user should note which logical CPU cores are part of this node. This can be determined by the `lspcu` command:

```
[root@capture ~]# lscpu |grep NUMA
NUMA node(s):          2
NUMA node0 CPU(s):     0,2,4,6,8,10
NUMA node1 CPU(s):     1,3,5,7,9,11
```

On this system, the only cores that should be used for listen/write threads are 1,3,5,7,9,11 which are local to the same NUMA node as the hardware that will be used for packet capture.

## CPU configuration

Ensuring that the user's CPU is correctly configured is vital to ensuring the performance of exact-capture. Any CPU cores that are used for listen/write threads should be configured as part of the [Kernel Build Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#kernel-build-configuration) guide referenced earlier. These cores need to be specified in the `isolcpus`, `nohz_full` and `rcu_nocbs` parameters. The user should also steer interrupts away from these cores via the `irqaffinity` parameter.

Both ExaNICs and capture disks can raise interrupts which will impact the performance of the capture server, if they are not steered away from cores used for listen/write threads. Check the output of `cat /proc/interrupts` to determine whether the selected cores are servicing interrupts and adjust the `irqaffinity` boot parameter if the counter for a chosen CPU is incrementing.

## CPU core selection

Exact-capture's `--cpus` option allows the user to select which CPU cores are allocated for management, listen and write threads (see the [Configuration Guide](./config.md) and [Internal Architecture](./arch.md) for more information). The cores chosen for listen/write threads should be configured per the [CPU configuration](#cpu-configuration) section. The core chosen for management does not need to be isolated, but it should not be shared with the cores used for listen/write threads.

## Troubleshooting

The `--perf-test` option offers a number of utilities useful for diagnosing performance bottlenecks in a given system. These options can be conbined with the `--verbose` and `--more-verbose 2` to assess whether a server has been optimally configured. Check the [Configuration Guide](./config.md) for the list of supported performance testing options.

For example, the `--perf-test 3` can be used to evaluate the write performance of a given system:

```
./bin/exact-capture -i exanic0:0 -i exanic0:1 -o /mnt/exadisk0/test0 -o /mnt/exadisk1/test1 -o /mnt/exadisk2/test2 -o /mnt/exadisk3/test3 -c 0:1,3:5,7,9,11 -k -v -V 2 -p 2
...
[20200908T112533.543]: Listener:00 exanic0:0 (0.0) -- 0.00Gbps 0.00Mpps (HW:0.00iMpps) 0.00MB 0 Pkts (HW:0 Pkts) [lost?:0] (4569.582M Spins1 0.000M SpinsP ) 0errs 0drp 0swofl 0hwofl
[20200908T112533.543]: Listener:01 exanic0:1 (0.1) -- 0.00Gbps 0.00Mpps (HW:0.00iMpps) 0.00MB 40 Pkts (HW:40 Pkts) [lost?:0] (4562.232M Spins1 0.000M SpinsP ) 0errs 0drp 0swofl 0hwofl
[20200908T112533.543]: Total - All Listeners       -- 0.00Gbps 0.00Mpps (HW:0.00iMpps) 0.00MB 40 Pkts (HW:40 Pkts) [lost?:0] (9131.814M Spins1 0.000M SpinsP ) 0errs 0drp 0swofl 0hwofl
[20200908T112533.543]: Writer:00 .t/exadisk0/test0 -- 6.55Gbps (6.55Gbps wire 9.82Gbps disk) 12.79Mpps 16212.34MB (16212.34MB 24320.00MB) 265623040 Pkts 0.000M Spins
[20200908T112533.543]: Writer:01 .t/exadisk0/test0 -- 5.41Gbps (5.41Gbps wire 8.12Gbps disk) 10.57Mpps 13397.85MB (13397.85MB 20098.00MB) 219510356 Pkts 0.000M Spins
[20200908T112533.543]: Writer:02 .t/exadisk0/test0 -- 6.00Gbps (6.00Gbps wire 9.00Gbps disk) 11.72Mpps 14851.09MB (14851.09MB 22278.00MB) 243320316 Pkts 0.000M Spins
[20200908T112533.543]: Writer:03 .t/exadisk0/test0 -- 6.05Gbps (6.05Gbps wire 9.08Gbps disk) 11.83Mpps 14989.75MB (14989.75MB 22486.00MB) 245592092 Pkts 0.000M Spins
[20200908T112533.543]: Total - All Writers         -- 24.01Gbps (24.01Gbps wire 36.02Gbps disk) 46.90Mpps 59451.04MB (59451.04MB 89182.00MB) 974045804 Pkts 0.000M Spins
Exact Capture finished
    HW Received:        40 packets (  0.000 MP/s )
    SW Received:        40 packets (  0.000 MP/s )
                         0 MB      (  0.000 Gb/s )
       SW Wrote: 974045804 packets ( 46.902 MP/s )
                     59451 MB      ( 24.014 Gb/s )
 Lost HW/SW (?):         0 packets (  0.000 MP/s )
     Lost RX/WR:         0 packets (  0.000 MP/s )
                         0 MB      (  0.000 Gb/s )
        Dropped:         0 packets (  0.000 MP/s )
    SW Overflows:         0 times   (  0.000 /s   )

```

We can observe that this system is capable of writing ~36.02Gbps to the disks specified.
