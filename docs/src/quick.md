To run Exact Capture on a single 10GbE interface, writing to a single disk slice, the following command line is sufficient:

```bash
$ exact-capture --input=exanic0:0 --output=/data0/ --cpus=0:1:2
```

!!! note
    Canonical Linux interface names such as “eth1” or “enp0s1” can be freely used in place of Exablaze ExaNIC device names (e.g. “exanic0:0”).
    The interface must however be an ExaNIC.

!!! note
    The CPU specification is a colon (“:”) separated list containing the management CPU, the ExaNIC listener thread CPU(s), and the ExaDisk writer thread CPU(s).
    It is assumed that CPU cores have been isolated according to the System Configuration instructions above.
    For more details see [configuration options](config.md#cpus)

To run exact capture on a pair of 10GbE interfaces, writing to a two disk slices, using 5 cpu cores (management core = 0, NIC listener cores = 1,2, disk writer cores = 3,4):

```bash
$ exact-capture --input=exanic0:0 --input=exanic0:1 --output=/data0/ --output=/data1/ --cpus=0:1,2:3,4
```
