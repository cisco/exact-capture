# Exact PCAP Parse

Exact PCAP Parse (`exact-pcap-parse`) is a tool used to create ASCII dumps from `.pcap` and `.expcap` files. It outputs timestamps and packet data in `.csv` files.

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
	  The input `.pcap` file to parse and dump.
    </td>
  </tr>
  <tr>
    <td>c</td>
    <td>csv</td>
    <td><em>(required)</em></td>
    <td>
      The `.csv` file to write out the dumped timestamps and packet data.
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
    <td><em>(required)</em></td>
    <td>
	  The input file format. Valid values are <code>pcap</code> or <code>expcap</code>.
    </td>
  </tr>
  <tr>
    <td>o</td>
    <td>offset</td>
    <td><em>0</em></td>
    <td>
	  Start parsing packets from this packet offset into the input file.
    </td>
  </tr>
  <tr>
    <td>m</td>
    <td>max</td>
    <td><em>-1 (no limit)</em></td>
    <td>
      Limit the number of packets to parse.
    </td>
  </tr>
  <tr>
    <td>n</td>
    <td>num-chars</td>
    <td><em>64</em></td>
    <td>
	  The number of bytes parse and output in the packet data field of the <code>.csv</code> file.
    </td>
  </tr>
</table>
