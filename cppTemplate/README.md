### A templace c++ program for simple packet processing. ###

This is a simple c++ packet processor that tracks per-flow packet counts.

#### Usage: ####

- Compile with makefile ```make packetProcessor```
- Run ```./packetProcessor ~jsonch/datasets/caida2015/caida2015_02_dirA.pcap```

#### Notes: ####

Contains the minimal logic needed to analyze pcaps:

- Parse and extract packets.
- Map packets to flows. 
- Print hex dumps of packet data. 
- Track timestamps. 
