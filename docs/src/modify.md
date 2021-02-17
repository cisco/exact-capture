# Exact PCAP Modify

Exact PCAP Modify (`exact-pcap-modify`) is a tool which can be used to filter and modify Ethernet packets.
Where modifications occur which would invalidate a checksum, Exact PCAP Modify will recalculate a correct checksum in the output file.

It can perform modify/filter operations on the following fields:

* Ethernet header:
    * Destination MAC address (DST MAC)
    * Souce MAC address (SRC MAC)
* 8021.Q tag:
    * VLAN ID
* IPv4 header:
    * Source address (SRC IP)
    * Destination address (DST IP)
    * Time-to-live (IP TTL)
* UDP/TCP headers:
    * Source port (SRC PORT)
    * Destination port (DST PORT)
    
```
$ exact-pcap-modify -i capture.pcap -f expcap -w modified -a 1.1.1.1,2.2.2.2
```

# Configuration

Options which operate on the fields of a header are to be supplied in the form <code>filter,modify</code>. 
For example, if Exact PCAP Modify should filter a capture such that only packets with the SRC IP of 1.1.1.1 are present written to the output, it should be invoked with the `--src-ip 1.1.1.1` option.

If the user wishes to modify all packets which have the SRC IP 1.1.1.1 to produce an output where the SRC IP becomes 2.2.2.2, it should be invoked with the `--src-ip 1.1.1.1,2.2.2.2` option.

When multiple filters are used, packets will need to match **all** of the specified filters to be present in the output capture.

The following table lists all commands available:

<table>
  <tr>
    <th>Short</th>
    <th>Long</th>
    <th>Default</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>i</td>
    <td>input</td>
    <td><em>(required)</em></td>
    <td>
      The <code>.pcap</code>/<code>.expcap</code> file to filter/modify.
    </td>
  </tr>
  <tr>
    <td>w</td>
    <td>write</td>
    <td><em>(required)</em></td>
    <td>
      The destination file where packets which match the specified filter will be written to.
    </td>
  </tr>
  <tr>
    <td>W</td>
    <td>write-filtered</td>
    <td><em>(optional)</em></td>
    <td>
      The destination file where all packets which do not match all specified filters will be written to.
    </td>
  </tr>
  <tr>
    <td>v</td>
    <td>verbose</td>
    <td><em>(flag)</em></td>
    <td>
      Enables verbose output printing.
    </td>
  </tr>
  <tr>
    <td>f</td>
    <td>format</td>
    <td><em>expcap</em></td>
    <td>
      The file format to use when writing out packets. Valid options are <code>.pcap</code> and <code>.expcap</code>.
    </td>
  </tr>
  <tr>
    <td>o</td>
    <td>offset</td>
    <td><em>0</em></td>
    <td>
      Jump to the specified packet offset and start processing filter/modify operations from there.
    </td>
  </t>
  <tr>
    <td>t</td>
    <td>time</td>
    <td><em>0 (Epoch time in ns)</em></td>
    <td>
      Skip all packets that are older than this time.
    </td>
  </t>
  <tr>
    <td>m</td>
    <td>max</td>
    <td><em>0 (no limit)</em></td>
    <td>
      The maximum number of packets to write out in total.
    </td>
  </t>
  <tr>
    <td>n</td>
    <td>num-chars</td>
    <td><em>64</em></td>
    <td>
      For use with <code>--verbose</code>. Limit the amount of characters written when dumping packets.
    </td>
  </t>
  <tr>
    <td>e</td>
    <td>--dst-mac</td>
    <td><em>(null)</em></td>
    <td>
      Filter/modify based on the DST MAC. 
	  Accepts arguments in the form <code>0x001122334455</code> for filtering and <code>0x001122334455,0xAABBCCDDEEFF</code> for filtering and modifying.
    </td>
  </t>
  <tr>
    <td>E</td>
    <td>--src-mac</td>
    <td><em>(null)</em></td>
    <td>
	  Fitler/modify based on the SRC MAC. 
	  Accepts arguments in the form <code>0x001122334455</code> for filtering and <code>0x001122334455,0xAABBCCDDEEFF</code> for filtering and modifying.
    </td>
  </t>
  <tr>
    <td>l</td>
    <td>vlan</td>
    <td><em>(null)</em></td>
    <td>
	  Filter/modify based on the VLAN ID.
	  Accepts arguments in the form <code>100</code> for filtering and <code>100,200</code> for filtering and modifying.
	  <br><br>
	  The <code>--vlan</code> option also allows users to strip and add 8021.Q tags in addition to filtering and modifying based on these tags. 
	  For example if <code>--vlan 0,100</code> is specified, that will cause Exact PCAP Modify to add an 8021.Q header with a VLAN ID of 100 to all non-8021.Q frames.
	  <br><br>
	  The inverse usage, <code>--vlan 100,0</code> will cause Exact PCAP Modify to strip all 8021.Q frames which have VLAN ID 100 and set the Ethertype to IPv4.
    </td>
  </t>
  <tr>
    <td>a</td>
    <td>src-ip</td>
    <td><em>(null)</em></td>
    <td>
	  Fitler/modify based on the SRC IP.
	  Accepts arguments in the form <code>1.1.1.1</code> for filtering and <code>1.1.1.1,2.2.2.2</code> for filtering and modifying.
    </td>
  </t>
  <tr>
    <td>A</td>
    <td>dst-ip</td>
    <td><em>(null)</em></td>
    <td>
	  Fitler/modify based on the DST IP.
	  Accepts arguments in the form <code>1.1.1.1</code> for filtering and <code>1.1.1.1,2.2.2.2</code> for filtering and modifying.
    </td>
  </t>
  <tr>
    <td>T</td>
    <td>ip-ttl</td>
    <td><em>(null)</em></td>
    <td>
	  Fitler/modify based on the IP TTL. 
	  Accepts arguments in the form <code>10</code> for filtering and <code>10,64</code> for filtering and modifying.
    </td>
  </t>
  <tr>
    <td>p</td>
    <td>src-port</td>
    <td><em>(null)</em></td>
    <td>
	  Fitler/modify based on the SRC PORT of the TCP/UDP header. 
	  Accepts arguments in the form <code>1000</code> for filtering and <code>1000,2000</code> for filtering and modifying.
    </td>
  </t>
  <tr>
    <td>P</td>
    <td>dst-port</td>
    <td><em>(null)</em></td>
    <td>
	  Fitler/modify based on the DST PORT of the TCP/UDP header. 
	  Accepts arguments in the form <code>1000</code> for filtering and <code>1000,2000</code> for filtering and modifying.
    </td>
  </t>
  <tr>
    <td>d</td>
    <td>device-type</td>
    <td><em>nexus3548</em></td>
    <td>
	  When modifying frames, emulate the behaviour of the specified device. 
	  Valid values are: <code>nexus3548</code>, <code>fusion</code>, <code>triton</code>, <code>arista7150</code>.
    </td>
  </t>
</table>
