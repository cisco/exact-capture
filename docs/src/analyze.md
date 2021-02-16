# Exact PCAP Analyze

Exact PCAP analyze (`exact-pcap-analyze`) is a tool used to analyze `.pcap` files and derive a number of statistics concerning a given capture.
It will determine the total length of the capture (in nanoseconds, microseconds and seconds), the average packet rate (in pps, packets per second), the minimum/maximum inter-frame gaps (IFGs) and the throughput rate (in gigabits per second).

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
	  The input <code>.pcap</code> file to analyze.
    </td>
  </tr>
  <tr>
    <td>f</td>
    <td>format</td>
    <td><em>(required)</em></td>
    <td>
      The input file format. Valid values are <code>pcap</code> or <code>expcap</code>.
    </td>
  </tr>
  <tr>
    <td>r</td>
    <td>line-rate</td>
    <td><em>(required)</em></td>
    <td>
      The line rate of traffic in the input capture. This value is in Gbps, e.g. 10 = 10Gb/s.
    </td>
  </tr>
  <tr>
    <td>o</td>
    <td>offset</td>
    <td><em>0</em></td>
    <td>
	  Start analyzing packets from this packet offset into the input file.
    </td>
  </tr>
  <tr>
    <td>m</td>
    <td>max</td>
    <td><em>-1 (no limit)</em></td>
    <td>
	  Limit the number of packets to analyze.
    </td>
  </tr>
  <tr>
    <td>w</td>
    <td>window</td>
    <td><em>100</em></td>
    <td>
	  Analyze packets within this window. Analysis occurs each time this window is exceeded in the input capture.
    </td>
  </tr>
</table>

