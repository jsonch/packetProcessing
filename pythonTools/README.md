# tools for generating and replaying packets into the network. 

- testPacketGenerator.py -- generate a pcap with random flows and a fixed inter-arrival time. 
- packetListener.py -- print packets that arrive on a port. 
- pps.sh -- print packet rx / tx on a port, updated in real time. 
- sendPackets.sh -- send pcap with tcpreplay.