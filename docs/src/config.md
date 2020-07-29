
The Exact Capture application supports a number of configuration options in both short and long form.
For example:
```
$ exact-capture -i exanic0:0 --log-report-int 10 ....
```

A [quick start](quick.md) guide is available for getting started.
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
        The ExaNIC interface(s) to capture on
    </td>
  </tr>
  <tr>
    <td>o</td>
    <td>output</td>
    <td><em>(required)</em></td>
    <td>
      The destination directory and filename stub to output to.
      Filenames will be output in the following format /output/dir/base_xx.expcap.
      Where xx is a unique file index.
      For details on the expcap format please see the Exact Capture Output Format (expcap) section later in this document.
    </td>
  </tr>
  <tr>
    <td>c</td>
    <td><a name="cpus">cpus</a></td>
    <td><em>(required)</em></td>
    <td>
      The list of CPUs to assign threads to for management, listening and writing threads.
      This is specified in the the following format, <code>m:ls,ls,ls:ws,ws,ws</code>.
      Where m is the core number for management, and ls/ws are comma separated lists of listener and writer CPU core numbers.
      For example <code>--cpus=5:2,3:7,6,1</code> would configure Exact Capture to run the management thread on CPU 5, with two NIC listener threads on on CPUs 2 and 3 respectively, and three (or more) disk writer threads on cores 1,6 &amp; 7 respectively.
      </br></br>
      <strong>Note:</strong> the number of listener CPUs must be exactly equal to the number of ExaNIC <code>--interfaces</code> in use.
      Furthermore listener threads cannot share CPUs with management or writer threads.
      If there are fewer writer threads than <code>--outputs</code>, writer threads will be reused.
    </td>
  <tr>
    <td>s</td>
    <td>snaplen</td>
    <td>2048B</td>
    <td>      
      In some cases it is not necessary / useful to capture the entire packet.
      Set the snap length to determine the maximum size of packet that can be captured.
      This value cannot be 0 or less.
    </td>      
  </tr>
  <tr>
    <td>m</td>
    <td>maxfile</td>
    <td>0 <em>(unlimited)</em></td>
    <td>          
      High rate capture can produce very large file sizes.
      To reduce the file sizes, Exact Capture can cap the file size to a maximum, and will start a new file each time it is reached.
      A value of 0 or less puts no limit on the output file size.  
    </td>      
  </tr>
  <tr>
    <td>l</td>
    <td>logfile</td>
    <td><em>(none)</em></td>
    <td>              
        Exact capture can optionally write log messages to a log file specified.
    </td>      
  </tr>
  <tr>
    <td>t</td>
    <td>log-report-int</td>
    <td>1.0</td>
    <td>              
        This sets the statistics calculation and logging interval in seconds.
    </td>      
  </tr>
  <tr>
    <td>v</td>
    <td>verbose</td>
    <td><em>(flag)</em></td>
    <td>                  
      Enabling verbose mode will produce 2 output log lines every log interval (see above).
      These log lines will include summary statistics of the performance of all listener threads and all writer threads.
    </td>      
  </tr>
  <tr>
    <td>V</td>
    <td>more-verbose</td>
    <td><em>(flag)</em></td>
    <td>                      
      Enabling more verbose mode will produce 1 output log line for every listener and writer thread.
      Each log line will include per-thread statistics counters/statistics.
      This can be combined with <code>--verbose</code> mode above.
    </td>      
  </tr>
  <tr>
    <td>d</td>
    <td>debug-logging</td>
    <td><em>(flag)</em></td>
    <td>                      
      Debug logging mode enables display of the full file path, process ID and thread ID in each output log line.
      This is useful to track where a given log message originated.
    </td>      
  </tr>
  <tr>
    <td>T</td>
    <td>no-log-ts</td>
    <td><em>(flag)</em></td>
    <td>                          
      By default, logs include a timestamp.
      This can make the output overly verbose.
      Use this flag to disable timestamps.
    </td>      
  </tr>
  <tr>
    <td>w</td>
    <td>no-warn-overflow</td>
    <td><em>(flag)</em></td>
    <td>                          
      Software overflows will produce a warning.
      This may be problematic if the system is underperforming and these happen often.
      The flag disables these warnings.
    </td>      
  </tr>
  <tr>
    <td>S</td>
    <td>no-spin</td>
    <td><em>(flag)</em></td>
    <td>                          
      By default Exact Capture outputs a progress “spinner” to the console.
      This flag disables it.
    </td>      
  </tr>
  <tr>
    <td>n</td>
    <td>no-promisc</td>
    <td><em>(flag)</em></td>
    <td>                          
      By default Exact Capture puts the NIC into promiscuous mode.
      This flag disables it.
    </td>      
  </tr>
  <tr>
    <td>p</td>
    <td>perf-test</td>
    <td><em>(flag)</em></td>
    <td>                          
      Exact Capture supports several performance testing modes.
      These can be used to give a sense of the best possible performance that you can expect from your system configuration.
      The modes are as follows:
      <ol start="0">
        <li> No performance testing </li>
        <li>
          Replace all ExaNIC interfaces with a dummy interface.
          ExaNICs are no longer a performance limitation.
          This tests the maximum possible receive rate that your system can achieve for 64B frames.
          <strong>Note that 10GbE line-rate with 64B frames is about 7Gb/s (due to Ethernet interfame gap overheads).</strong>          
        </li>
        <li>
          Replace the internal memory queue with a dummy interface on both sides.
          This tests the maximum performance possible when when system memory is not the bottleneck.
          This is also a good test of disk writing speed (for minimum sized packets).
        </li>
        <li>
          Replace the ExaDisk interface with a dummy.
          This tests the performance through the system when disk writing speed is not a limitation.
          This may be helpful to debug cases where your disks are not configured/performing correctly.
        </li>
        <li>
          Replace both the ExaNIC and the internal memory ring with dummies.
          Can be used to measure the absolute best performance possible when NICs and memory are not the limitations.
          Can also help to find interference bugs between ExaNICs and ExaDisks sharing limited PCIe bandwidth.
        </li>
        <li>
          Replace the ExaNIC and ExaDisk with dummies.
          This is useful for testing the maximum achievable application throughput, including through system memory, but excluding reading from and writing to real hardware.
        </li>
        <li>
          Replace the memory queues and ExaDisk with dummies.
          Can be help to find interference bugs between ExaNICs and ExaDisks sharing limited PCIe bandwidth.
        </li>
        <li>
          Replace the ExaNIC, memory queue and ExaDisk interfaces with dummies.
          Useful for determining the overheads within the application (i.e. CPU speed) issues.
        </li>
    </td>
  </tr>

</table>
