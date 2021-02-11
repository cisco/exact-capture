# Exact PCAP Match

Exact PCAP match is a tool used to compare and match packets in `.pcap` files.

Required  (String     ) -r  --reference       ref PCAP file to read 
Required  (String     ) -i  --input           cmp PCAP file to read 
Required  (String     ) -c  --csv             Output CSV 
Optional  (String     ) -R  --ref-miss        Reference misses [(null)]
Optional  (String     ) -I  --inp-miss        Input misses [(null)]
Required  (String     ) -f  --format          Input format [pcap | expcap] 
Optional  (Integer    ) -O  --offset-ref      Offset into the reference file to start  [0]
Optional  (Integer    ) -o  --offset-inp      Offset into the input file to start  [0]
Optional  (Integer    ) -M  --max-ref         Max items in the reference file to match  (<0 means all) [-1]
Optional  (Integer    ) -m  --max-inp         Max items in input file to match (<0 means all) [-1]
Optional  (Integer    ) -n  --num-chars       Number of bytes from matched packets to output (<0 means all) [64]
Flag      (Boolean    ) -v  --verbose         Printout verbose output
