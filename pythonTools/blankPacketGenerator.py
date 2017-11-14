"""
Generate empty packets.
"""
import sys, time, random, socket, os, struct
import threading
import binascii
import dpkt
import subprocess

default_pktTmpFile = 'emptyPackets.pcap'

def main():
	generateEmptyPackets()

pktId = 1
def generateEmptyPackets(duration = 1, rate = 1000, dumpFile = default_pktTmpFile):
	"""
	Generates empty packets.
	"""
	eth_src = '\x22\x22\x22\x22\x22\x11'
	eth_dst = '\x22\x22\x22\x22\x22\x22'

	payload = "\x00"*50
	f = startPcapFile(dumpFile)
	current_time = 0
	for i in range(duration*rate):	
		eth_dst = '\x22\x22'+struct.pack("I", i)
		ethOut = dpkt.ethernet.Ethernet(src=eth_src, dst = eth_dst, \
			type = dpkt.ethernet.ETH_TYPE_IP, data = payload)
		ethOutStr = ethOut	
		writePktToFile(ethOutStr, current_time, f)
		current_time += 1.0 / rate
	f.close()
	


# pcap helpers.
#Global header for pcap 2.4
pcap_global_header="d4c3b2a1".decode("hex") + struct.pack("H",2) + struct.pack("H",4) + struct.pack("I", 0) + struct.pack("I", 0) + struct.pack("I", 1600) + struct.pack("I", 1)
pcap_packet_header = "AA779F4790A20400".decode("hex") # then put the frame size twice in little endian ints.

def appendByteStringToFile(bytestring, f):
	f.write(bytestring)

def startPcapFile(filename):
	f = open(filename, "wb")
	f.write(pcap_global_header)
	return f

def writePktToFile(pkt, ts, f):
	"""
	Writes an ethernet packet to a file. Prepends the pcap packet header.
	"""
	pcap_len = len(pkt)
	seconds = int(ts)
	microseconds = int((ts - int(ts)) * 1000000)
	bytes = struct.pack("<i",seconds) + struct.pack("<i",microseconds) + struct.pack("<i", pcap_len) + struct.pack("<i", pcap_len) + str(pkt)
	# bytes = pcap_packet_header + struct.pack("<i", pcap_len) + struct.pack("<i", pcap_len) + pkt
	appendByteStringToFile(bytes, f)


if __name__ == '__main__':
	main()
