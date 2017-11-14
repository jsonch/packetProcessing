"""
Listens on a port and prints info about all the packets that arrive.
"""
import dpkt
import struct
from matplotlib import pyplot as plt

def main():
    f = open('in.pcap')
    pcap = dpkt.pcap.Reader(f)
    pktCt = 0
    inconsistencyCt = 0
    lastC2 = 0

    egress_counter = []
    ingress_counters = [[],[]]
    stime = 0
    for ts, buf in pcap:
        if stime == 0:
            stime = ts
        ts = ts - stime
        pktCt+=1
        # unpack. 
        pathVal, counter1Val, counter2Val = struct.unpack("!III", buf[14:14+12])
        # put into lines
        egress_counter.append([ts, counter1Val])
        if (pathVal == 20):
            ingress_counters[0].append([ts,counter2Val])
        else:
            ingress_counters[1].append([ts,counter2Val])
        if (pktCt > 10000):
            break
    plt.figure(figsize=(4.5, 3))
    X, Y = zip(*egress_counter)
    Y = [y - min(Y) for y in Y]
    plt.plot(X, Y, label="egress counter\n(true value)")
    X, Y = zip(*ingress_counters[0])
    Y = [y - min(Y) for y in Y]
    plt.plot(X, Y, label="ingress counter\n(port 1's view)")
    X, Y = zip(*ingress_counters[1])
    Y = [y - min(Y) for y in Y]
    plt.plot(X, Y, label="ingress counter\n(port 2's view)", linestyle="-.")
    plt.legend()
    plt.xlabel("Timestamp")
    plt.ylabel("Packet Count")
    plt.tight_layout()

    plt.show()
if __name__ == "__main__":
    main()