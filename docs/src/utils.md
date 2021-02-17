# Overview

Exact Capture is supplied with a collection of tools for operating on expcap files.
These are:

* **[exact-pcap-extract](./extract.md)** - This tool is used to extract packets from expcap files and write them to another format. 
It can be used to extract the timestamps present in expcap files and Fusion HPT trailers. 
It can also steer packets to separate files based on the packet contents.

* **[exact-pcap-match](./match.md)** - A common use case of is for Exact Capture is latency calculations. 
This tool can be used to match identical frames from two pcap or expcap files and calculate the latency between them. 
It can be easily extended to support matching frames that are not identical (e.g. tick-to-trade latency calculations).

* **[exact-pcap-modify](./modify.md)** - This tool can be used to filter and modify header values (Ethernet/IPv4/L4) in pcap/expcap files.

* **[exact-pcap-parse](./parse.md)**  - This tool is useful for creating ASCII text dumps of pcap and expcap files and for working with picosecond timestamps.

* **[exact-pcap-analyze](./analyze.md)** - This tool prints statistics about the packet rates/throughput for a given capture file.

![The Exact Capture toolchain](img/toolchain.png)

## Usage

Once a packet capture has been produced by exact-capture, users may need to process this capture in another application. 
This guide will walk through a basic usage of the full exact-capture toolchain.

This guide will assume that packets have been sent to and received from another device.
It will demonstrate how to utilise the full Exact Capture toolchain to capture traffic, extract latency statistics and validate correctness.

!!!Note
	In order to acheive the desired outcome, the capture will need to contain traffic in both directions (sent to the device and received from the device).
	Exact Capture can only capture **ingress** traffic, so an external device (such as a Fusion HPT) will need to be used to capture traffic as it is sent to the device under test.

## Capture

First, packets are captured via exact-capture. See the [configuration guide](./config.md) for more information on the parameters for exact-capture.

```
$ exact-capture -i exanic0:0 -i -exanic1:0 -o ./cap0 -o ./cap1 -c 0:1:2,3 -k -S
Exact-Capture 1.0 (00200000-00000080)
Copyright Exablaze Pty Ltd 2018
...
Exact Capture finished
    SW Received: 400011 packets ( 0.007 MP/s )
                     30 MB      ( 0.005 Gb/s )
       SW Wrote: 400011 packets ( 0.007 MP/s )
                     30 MB      ( 0.005 Gb/s )
     Lost RX/WR:      0 packets ( 0.000 MP/s )
                      0 MB      ( 0.000 Gb/s )
        Dropped:      0 packets ( 0.000 MP/s )
   SW Overflows:      0 times   ( 0.000 /s   )
```

This capture contains picosecond timestamps that were produced by the ExaNIC used for capture.
With the initial capture saved on disk, we can begin to process the capture with the utility toolchain.

## Extract

Before any other analysis is performed, the captures produced by `exact-capture` should be "extracted" by `exact-pcap-extract`.
As exact-capture has produced two separate captures in this example, this tool will merge the separate captures and ensure that the timestamps in the extracted capture are in order.

Note that when `exact-capture` was executed, it was listening on two interfaces and writing to two destinations.
`exact-capture` will spread packets from both ports across both files.
`exact-pcap-extract` can also be used to extract the original ports from both captures, so that packets arriving on a given device/port are in a separate file:

```
$ exact-pcap-extract -i cap0-0.expcap -i cap1-0.expcap -w cap_ext -W ./extracted -a -f expcap -s expcap
```

This will steer packets arriving on each unique port in the capture to separate files.
After this stage, there should now be two separate files, `./extracted/cap_ext_device_0_port_0.pcap` and `./extracted/cap_ext_device_1_port_0.pcap`.

## Modify

Now that we have split the raw capture into two separate files, we could attempt to match packets and derive analyitcs from the extracted captures.
However, the traffic in the extracted captures may not be identical (as the device they were sent to could have transformed them).
Exact PCAP Match will attempt to match packets across the entire packet, so if there are any differences between the two captures passed to `exact-pcap-match` it will not be able to match these correctly.

The `exact-pcap-modify` tool can be used to modify packets in capture files.
We will use it to modify the capture taken before transofmration so that the packets in that capture match the packets captured after transformation.

Suppose that traffic before transformation is located in `./extracted/cap_ext_device_0_port_0.pcap` and traffic captured after the transformation is located in `./extracted/cap_ext_device_1_port_0.pcap`.
For this example, assume that before traffic traversed the device, the SRC IP of outgoing packets was 1.1.1.1 and that the device changed this to 2.2.2.2.
So we will need to use `exact-pcap-modify` to modify packets in `./extracted/cap_ext_device_0_port_0.pcap` such that any frames with SRC IP are modified such that the SRC IP becomes 2.2.2.2:

```
$ exact-pcap-modify -i ./extracted/cap_ext_device_0_port_0.pcap -w ./input -a 1.1.1.1,2.2.2.2 -f expcap
```

This will produce the file `./post_mod_0.pcap`, where any packets in `./extracted/cap_ext_device_0_port_0.pcap` which had SRC IP 1.1.1.1 will now have SRC IP 2.2.2.2.

## Match

Once two captures have been produced which contain matching packets, `exact-pcap-match` can be used to determine the latency delta between matching packets.
It will also indicate which packets failed to match, which can be used as a test for correctness.

```
$ exact-pcap-match -r ./extracted/cap_ext_device_1_port_0.pcap -i ./post_mod_0.pcap -c matches.csv -f expcap
```

`matches.csv` will contain the timestamps, timestamp deltas (latency) and packet data from the matching packets in `./extracted/cap_ext_device_1_port_0.pcap` `./post_mod_0.pcap`.
From this point, additional statistics/analytics can be gathered from the current capture files as required.

## Parse

Sometimes, it may be convenient to parse packet data in external tooling.
The `exact-pcap-parse` utility can enable this by extracting packet timestamps and packet data to `.csv` files.
It can be invoked via:

```
$ exact-pcap-parse -i ./post_mod_0.pcap -c ./parsed.csv -f expcap
```

## Analyze

Statistics other than traffic latency can be retrieved via the `exact-pcap-analyze` utility.
This tool will print statistics such regarding the packet sizes, throughput, inter-frame gaps and packets per second of a given capture.
It can be invoked via:

```
$ exact-pcap-analyze -i ./post_mod_0.pcap -f expcap -r 10
```
