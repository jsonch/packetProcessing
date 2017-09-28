"""
Listens on a port and prints info about all the packets that arrive.
"""
import sys
import socket
from dpkt import ethernet
from dpkt import ip
from dpkt import udp
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.udp import UDP
from dpkt.tcp import TCP
from threading import Thread
import time
import binascii
import struct
import random
import cPickle as pickle
import numpy as np
import time


lastTs = 0

def printPacketInfo(pkt):
    global lastTs
    outLines = []
    eth = Ethernet(pkt)
    ip = eth.ip
    tcp = ip.tcp
    content = tcp.data
    debug16 = content[0:2]
    debug32s = []
    cur = 2
    print ("packet: %s"%binascii.hexlify(pkt))


def debugPackets(interface):
    """
    print all the packets that arrive on an interface, with debugging data.
    """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        # s.settimeout(3)
        s.bind((interface, 0))
        pktCt = 0

        while (True):
            pkt, addr = s.recvfrom(2048)
            pktCt += 1
            printPacketInfo(pkt)
    except socket.timeout:
        print ("data plane: timed out.") 


def main():
    listenIf = "vf0"
    debugPackets(listenIf)
    # for t in threads:
    #     t.join()


if __name__ == "__main__":
    main()