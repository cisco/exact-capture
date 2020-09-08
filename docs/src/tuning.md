# Performance Tuning

Ensuring that the correct options and server settings ensures that exact-capture is running in an optimal manner. This document will detail a number of performance tuning techniques that can be used to improve the behaviour of exact-capture.

## Getting started

The ExaNIC documentation covers a number of useful tuning techniques in order to ensure that ExaNICs are being used in an optimal manner. Many of these optimizations will also improve capture performance. The user should consult the following sections of the ExaNIC benchmarking guide before reading on:

- [BIOS Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#bios-configuration)
- [Kernel Build Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#kernel-build-configuration)
- [Kernel Boot Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#kernel-boot-configuration)
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

Ensuring that the user's CPU is correctly configured is vital to ensuring the performance of exact-capture. Any CPU cores that are used for listen/write threads should be configured as part of the [Kernel Boot Configuration](https://exablaze.com/docs/exanic/user-guide/benchmarking/#kernel-boot-configuration) guide referenced earlier. These cores need to be specified in the `isolcpus`, `nohz_full` and `rcu_nocbs` parameters.

## CPU core selection

Exact-capture's `--cpus` option allows the user to select which CPU cores are allocated for management, listen and write threads (see the [Configuration Guide](./config.md) and [Internal Architecture](./arch.md) for more information). The cores chosen for listen/write threads should be configured per the [CPU configuration](#cpu-configuration) section. The core chosen for management does not need to be isolated, but it should not be shared with the cores used for listen/write threads.

## Interrupt configuration

Both ExaNICs and capture disks can raise interrupts which will impact the performance of the capture server, if they are not steered away from cores used for listen/write threads. The output of `cat /proc/interrupts` to determine whether the selected cores are servicing interrupts:

```
[root@capture ~]# cat /proc/interrupts | grep -E 'CPU|exanic|nvme'
            CPU0       CPU1       CPU2       CPU3       CPU4       CPU5       CPU6       CPU7       CPU8       CPU9       CPU10      CPU11
  57:      50931      29339          0          0          0         40          0          0          0          0          0          0   PCI-MSI-edge      nvme0q0, nvme0q1
  59:      52418      29480          0          0          0         56          0          0          0          0          0          0   PCI-MSI-edge      nvme1q0, nvme1q1
  ...
 116:      21370      33252          0          0          0          0          0          0          0          0          0          0   PCI-MSI-edge      nvme4q7
 117:          0          0          0          0          0          0          0          0          0          0          0          0   PCI-MSI-edge      nvme4q8
 143:     205804      16367          0          0          0          0          0          0          0          0          0          0   PCI-MSI-edge      exanic0
 145:     108387      15031          0          0          0          0          0          0          0          0          0          0   PCI-MSI-edge      exanic1

```

Note the IRQ number in the leftmost column. On this server, CPU1 is still servicing interrupts for both NVMe storage drivres and the ExaNICs (there may be other devices also raising interrupts on these cores). This will impede the performance of exact-capture, if listen threads are started on CPU0 or CPU1.

The performance of exact-capture can be improved by first steering all interrupts away from CPU1:

```
echo 1 > /proc/irq/default_smp_affinity
for i in $(ls /proc/irq/); do echo 1 > /proc/irq/$i/smp_affinity ; done
```

Ensuring that interrupts raised by the disks used with exact-capture are serviced by the same cores as writer threads can improve caching performance. On this server, exact-capture is configured to use cores 1 and 3 for listen threads, and cores 5,7,9 and 11 for writer threads:

```
./bin/exact-capture --cpus 0:1,3:5,7,9,11 ...
```

Setting the `smp_affinity` bitmask in procfs will cause the interrupts (IRQ numbers 57-117) raised by the NVMe drives to be serviced by cores 5,7,9 and 11. The core used for the management thread can also be allowed to service interrupts generated by capture drives.

```
for i in {57..117}; do echo AA1 > /proc/irq/$i/smp_affinity ; done
```

The kernel documentation for [IRQ affinity](https://www.kernel.org/doc/Documentation/IRQ-affinity.txt) offers a detailed guide for configuring `smp_affinity` values.


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
