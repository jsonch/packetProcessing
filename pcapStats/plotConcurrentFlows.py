# plot concurrent flows

import os, glob, argparse
import numpy as np
from matplotlib import pyplot as plt

parser = argparse.ArgumentParser()
parser.add_argument('--i', action='store', type=str, help='input pcap')
parser.add_argument('--o', action='store', type=str, help='base name for intermediate / plot files', default = "tmp")
parser.add_argument("--parse", action="store_true", help = "parse pcap into intermediate format", default = False)
parser.add_argument("--plot", action="store_true", help = "plot intermediate format file", default = False)
args = parser.parse_args()
def main():
	if (args.o!= None):
		try:
			print "making directory: %s"%os.path.dirname(args.o)
			os.mkdir(os.path.dirname(args.o))
		except:
			pass
	if (args.parse):
		parse(args.i, args.o)
	if (args.plot):
		plot(args.o)


# parse pcap and save intermediate data.
def parse(pcapFn, imBaseFn):
	imFn = imBaseFn + ".csv"
	cmd = "./concurrentFlows %s > %s"%(pcapFn, imFn)
	print ("running: %s"%cmd)
	os.system(cmd)

# plot intermediate data.
def plot(imBaseFn):
	imFn = imBaseFn + ".csv"
	pdfFn = imBaseFn + ".pdf"
	npLines = np.genfromtxt(open(imFn, "r"), delimiter=",", names=True)
	plt.plot(npLines['ts'], npLines['activeFlows'])
	plt.savefig(pdfFn)
	plt.show()



if __name__ == '__main__':
	main()