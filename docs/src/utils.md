Exact Capture is supplied with a small collection of tools for operating on expcap files.
These are:

* **exact-pcap-extract** -  This tool has two purposes. Firstly, it is used to extract all packets associated with a given port and device number from a collection of expcap files. Secondly, it can be used to convert from expcap format into standard pcap format.
* **exact-pcap-parse**  - This tool is useful for creating ASCII text dumps of pcap and expcap files and for working with picosecond timestamps.
* **exact-pcap-match** - A common use case of is for Exact Capture is latency calculations. This tool can be used to match identical frames from two pcap or expcap files and calculate the latency between them. It can be easily extended to support matching frames that are not identical (e.g. tick-to-trade latency calculations). (edited)
