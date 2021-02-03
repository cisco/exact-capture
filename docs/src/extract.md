# Exact Extract

Exact Extract is a utility that extracts packets from expcap files and writes them out into the user-specified format. It outputs capture files that are 
ordered by the expcap timestamps present in the original capture.
    
```
$ exact-pcap-extract -i cap0-0.expcap -w extracted -a -f expcap
```

!!! Note
    Exact Extract can take multiple expcap files as its input. It will search for the earliest timestamp in all of the input capture files. This means
    that the first packet written out will be the packet with the earliest timestamp across all of the input files.
    
Depending upon the options specified by the user, Exact Extract may attempt to keep more files open simultaneously than is allowed the OS. If it is unable to 
override this limit, it will need to close and open outputs each time a packet is written in order to ensure that it does not exceed this limit. This can
degrade the performance of Exact Extract, due to the additional overhead of repeatedly opening and closing output files.

On Linux, it is possible to override this limit by giving Exact Extract the "CAP_SYS_RESOURCE" capability to the binary. This can be accomplished by running:

```
$ sudo setcap cap_sys_resouce+ep exact-pcap-extract
```

The full list of permissions granted by CAP_SYS_RESOURCE is available on the [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
man page. Granting Exact Extract this permission should improve its performance, however it is not a requirement. Users will receive the warning "Could not 
raise the limit on concurrently open files" if they are exceeding the open file limit.

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
        The expcap files to extract packets from.
    </td>
  </tr>
  <tr>
    <td>w</td>
    <td>write</td>
    <td><em>(required)</em></td>
    <td>
      The filename used for extracted packets. Exact Extract will automatically append .pcap to the filename.
    </td>
  </tr>
  <tr>
    <td>W</td>
    <td>write-dir</td>
    <td><em>(none)</em></td>
    <td>
      The directory used to write extracted packets. If used in conjunction with '--write', packets are extracted to {write-dir}/{write}.pcap. 
      It must be specified if steering options (--steer) are in use.
    </td>
  </tr>
  <tr>
    <td>p</td>
    <td>port</td>
    <td><em>-1</em></td>
    <td>
      Only extract packets that were captured on the specified port number. If this is not specified and '--device' is not set, the user must use '--all' to 
      extract packets that were captured on all ports.
    </td>
  </tr>
  <tr>
    <td>d</td>
    <td>device</td>
    <td><em>-1</em></td>
    <td>
      Only extract packets that were captured on the specified device number (i.e., 0 corresponds to exanic0). If this is not specified and '--port' is not
      set, the user must use '--all' to extract packets that were captured on all ports.
    </td>
  </tr>
  <tr>
    <td>a</td>
    <td>all</td>
    <td><em>(flag)</em></td>
    <td>
      Extract packets that were captured on all ports and all devices. This flag must be set if neither '--port' or '--device' are specified.
    </td>
  </tr>
  <tr>
    <td>f</td>
    <td>format</td>
    <td><em>expcap</em></td>
    <td>
      The file format to use when writing out packets. Valid options are 'pcap' and 'expcap'.
    </td>
  </tr>
  <tr>
    <td>c</td>
    <td>count</td>
    <td><em>0 (no limit)</em></td>
    <td>
      The maximum number of files to write out in total.
    </td>
  </t>
  <tr>
    <td>M</td>
    <td>maxfile</td>
    <td><em>0 (128MB)</em></td>
    <td>
      The maximum file size for output files, in MB. Output files will never exceed 128MB, regardless of the value specified with this option.
      If the output must be spread over multiple files, Exact Extract will append _n to the filename, where n is the current segment being written out
      (starting from 1).
    </td>
  </t>
  <tr>
    <td>u</td>
    <td>usepcap</td>
    <td><em>(flag)</em></td>
    <td>
      If set, Exact Extract will write pcap timestamps in the microsecond format.
    </td>
  </t>
  <tr>
    <td>S</td>
    <td>snaplen</td>
    <td><em>1518</em></td>
    <td>
      The limit in bytes for each individual packet in the output file.
    </td>
  </t>
  <tr>
    <td>r</td>
    <td>skip-runts</td>
    <td><em>(flag)</em></td>
    <td>
      If this flag is set, runt frames will not be written to the output
    </td>
  </t>
  <tr>
    <td>D</td>
    <td>allow-duplicates</td>
    <td><em>(flag)</em></td>
    <td>
      By default, Exact Extract will write over files which have the same name as specified by '--write'. If this flag is set, it will instead create a file
      with a duplicate name, and append __n to the duplicate file, where n is the current number of files with the same name.
    </td>
  </t>
  <tr>
    <td>t</td>
    <td>hpt-trailer</td>
    <td><em>(flag)</em></td>
    <td>
        If this flag is set, Exact Extract will assume that each packet terminates in a Fusion HPT timestamp trailer. It will extract the timestamp from this
        trailer and write it to the pcap header (in microsecon/nanosecond format) and to the expcap trailer (in picosecond format) for all output files.
        <br><br><strong>Note:</strong> this option assumes <strong>all</strong> packets in the input captures have Fusion HPT trailers. If this is not 
        true, the pcap/expcap timestamp fields will contain invalid values in the output file(s).
    </td>
  </t>
  <tr>
    <td>s</td>
    <td>steer</td>
    <td><em>(null)</em></td>
    <td>
        --steer accepts one of the following values as valid options: hpt, vlan, expcap.
        A directory must be specified when using this option (via '--write-dir')
        If this option is set, Exact Extract will steer packets to separate files depending upon their content.
        <br><br>
        Specifying '--steer vlan' will cause packets to be steered to separate files depending upon their VLAN ID. For example, packets with VLAN ID 100 will
        be steered to the file {write-dir}/{write}_vlan_100.pcap. Packets which do not have an 8021.Q tag will be written to the file named 
        {write-dir}/{write}.pcap.
        <br><br>
        Specifying '--steer hpt' will cause packets to be steered to separate files depending upon their Fusion HPT trailer, using the device ID and port
        number. For example, files with device ID 0 and port number 10 will be steered to the file {write-dir}/{write}_device_0_port_10.pcap.
        <br><strong>Note:</strong> use of this option assumes that <strong>all</strong> packets in the input file(s) have a Fusion HPT trailer.
        <br><br>
        Specifying '--steer expcap' will cause packets to be steered to separate files depending upon their expcap footer, using the device ID and port
        number. For example, files with device ID 0 and port number 10 will be steered to the file {write-dir}/{write}_device_0_port_10.pcap.
        <br><strong>Note:</strong> use of this option assumes that <strong>all</strong> packets in the input file(s) have an expcap footer.
    </td>
  </t>
</table>
