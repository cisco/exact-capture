# Exact PCAP Match

Exact PCAP Match is a tool used to match packets in two separate files.
It outputs timestamps, timestamp deltas (latency) and the packet data of matched packets in a `.csv` file.

Where timestamp deltas are shown, they are produced from `reference_file.timestamp minus input_file.timestamp`.

The following table lists all commands available:

<table>
  <tr>
    <th>Short</th>
    <th>Long</th>
    <th>Default</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>r</td>
    <td>reference</td>
    <td><em>(required)</em></td>
    <td>
	  The reference file to use for matching.
    </td>
  </tr>
  <tr>
    <td>i</td>
    <td>input</td>
    <td><em>(required)</em></td>
    <td>
      The file to compare against the reference file.
    </td>
  </tr>
  <tr>
    <td>c</td>
    <td>csv</td>
    <td><em>(required)</em></td>
    <td>
      The <code>.csv</code> file to write matching packet statistics to.
    </td>
  </tr>
  <tr>
    <td>R</td>
    <td>ref-miss</td>
    <td><em>(optional)</em></td>
    <td>
	  The <code>.csv</code> file to store reference packet misses.
	  These are packets which were present in the reference file but were not found in the input file.
    </td>
  </tr>
  <tr>
    <td>I</td>
    <td>inp-miss</td>
    <td><em>(optional)</em></td>
    <td>
	  The <code>.csv</code> file to store input packet misses.
	  These are packets which were present in the input file but were not found in the reference file.
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
    <td>O</td>
    <td>offset-ref</td>
    <td><em>0</em></td>
    <td>
      Start matching packets in the reference file from this packet offset onwards.
    </td>
  </tr>
  <tr>
    <td>o</td>
    <td>offset-inp</td>
    <td><em>0</em></td>
    <td>
      Start matching packets in the input file from this packet offset onwards.
    </td>
  </t>
  <tr>
    <td>M</td>
    <td>max-ref</td>
    <td><em>-1 (no limit)</em></td>
    <td>
	  Limit the amount of packets in the reference file to match.
    </td>
  </t>
  <tr>
    <td>n</td>
    <td>num-chars</td>
    <td><em>64</em></td>
    <td>
      The number of bytes from matched packets to output in the packet data field of the <code>.csv</code> file.
    </td>
  </t>
  <tr>
    <td>v</td>
    <td>verbose</td>
    <td><em>(flag)</em></td>
    <td>
	  Enables verbose output printing.
    </td>
  </t>
</table>
