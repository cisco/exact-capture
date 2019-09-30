You are free to run Exact Capture on any system hardware.
The following table describes our recommendations for the minimum system hardware requirements.
For general guidance, we have successfully run the system on suitably configured Dell R230 and R730 machines.
Any of the Dell R*30 and R*40 machines are likely to be excellent candidates.

## CPUs
<h3>Core Count</h3>
The number of CPU cores required depends on:

1. The number of interfaces that you wish to capture on
2. The type and speed of the disk drives
3. The maximum capture rate you need to sustain

Assuming that **ExaDisks** are the target drives, each drive slice is capable of writing at a sustained rate of 10Gb/s.

As an example, a minimal 10Gb/s Exact Capture installation will require 3 CPU cores.
One core for a (hot) listener thread, one core for a (cold) disk writer thread and one management core.
The management core is low priority and can be safely shared with other general purpose system cores.
The listener thread should not be shared with any other process (i.e. be sure to make use of the isolcpus kernel parameter).

In general, for n line-rate 10G ports, the system requires 2n + 1 CPU cores. e.g a 4x10G capture system will require 9 cores in total.  

!!! warning
    CPU core counts are based on actual cores, rather than hyperthreads.
    In general, we recommend disabling hyperthreads on CPUs that support them.

!!! tip
    We have had good results with Intel Xeon E5-26xx range CPUs with a 3Ghz+ clock speed. For example the Intel Xeon E5-2643.


<h3>Speed</h3>
The minimum required CPU speed depends on the maximum capture rate required.
For the purposes of this document, we assume that 10G line rate, at minimum sized (64B) frames is the capture rate requirement (i.e. approx. 14 million packets per second ).

!!! tip
    We have found that 3Ghz+ CPUs are sufficient.


##RAM
RAM usage will vary based on the number of NICs and disks that you are using.
By default, each memory queue is organised into 256x 2MB slots for a total memory usage of approximately 512MB per queue.
The total number of memory queues the product of the number of hot (ExaNIC) and cold (ExaDisk) threads.
For a minimal 10Gb/s capture solution, with a single ExaNIC and ExaDisk, only 1 memory queue is required for a total of approximately 512MB of memory.
For 4x10Gbs system, with 4 disks, 4x4 = 16 queues will be required, for a minimum memory usage of  ~8GB.

!!! tip
    We recommend at least 16GB of DDR IV RAM in your machine.


##PCIe
For sustained, minimum sized packet capture, each 10Gb/s ExaNIC interface requires approximately 4x PCIe Gen 3 lanes.
The hot threads must run on the CPU socket directly connected to these PCIe lanes.

For sustained high performance writing, each ExaDisk interface requires 2x PCIe Gen 3 lanes.  
The cold threads must run on the CPU socket directly connected to these PCIe lanes.

!!! tip
    For optimal performance, w recommend running PCIe Gen3x8 for all cards connected.


##ExaNIC
All ExaNIC network cards will work with Exact Capture.
Following is a summary of the features, requirements and limitations of each card:

- **ExaNIC X10 / GM (2x 10GbE)** - these cards can be used without restriction on suitable PCIe Gen 3x8 slots.
  Timestamp resolution is 6.2ns.
- **ExaNIC HPT (2x 10GbE)**  - these cards can be used without restriction on suitable PCIe Gen 3x8 slots.
  Timestamp resolution is 0.25ns (250ps)
- **ExaNIC X40 / VXP (8x 10GbE)** - Only 2 ports can be used at line rate for all packet sizes. Up to 4 ports can be used at larger (average) packet sizes (e.g. 512B+).
  Timestamp resolution is 6.2ns.
- **ExaNIC X40 (2x 40GbE)** - Speeds up to 20Gb/s are likely to work out of the box on any single interface (though this is untested).
  Load balancing/packet spraying across multiple receive rings is also likely to assist line rate capture, though this is feature is not (yet) implemented.

!!! tip
    ExaNIC X10 and ExaNIC HPT devices are currently optimal.



##Disk Drives
Exact Capture is tested and optimized to run on *ExaDisk FX1* NVMe SSD drives.
Each ExaDisk is capable of running 40Gb/s sustained write speed to disk in a PCIe Gen 3x 8 slot.
The drives are currently available in 4TB and 8TB capacities.

The system will (in principle) operate with any disks.
High speed flash drives, especially NVMe disks are highly recommended to keep the number of threads and memory usage down.
For slower disks (e.g. SATA based flash disks) sharing CPU cores for writer threads is likely to reduce the CPU core count requirements without affecting overall performance.
This is untested.

!!! tip
    ExaDISK FX1 (8TB) is the recommended disk drive
