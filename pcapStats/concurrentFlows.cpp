#include <unordered_map>
#include "pcapProcessor.h"
using namespace std;
/**
 *
 * Minimal pcap processor.
 *
 */
// Local variables.
uint64_t pktCt = 0;
uint64_t byteCt = 0;

#define LOGINTERVAL 1000
uint64_t lastLogTs = 0;
std::unordered_map<std::string, int> flowTable;

// Parse the file.
int main(int argc, char *argv[]){
  if (argc != 2){
    cout << "incorrect number of arguments. Need 1. (filename)." << endl;
    exit(0);
  }
  char * inputFile = argv[1];

  cout << "ts, activeFlows, packets, bytes" << endl;
  parseFile(inputFile);
  cout << curTs << "," << flowTable.size() << "," << pktCt << "," << byteCt << endl;
  return 0;
}

// Do custom analysis.
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  PacketMetadata pkt = getPktMetadata(userData, pkthdr, packet);
  if (pkt.isTcp){
    pktCt++;
    byteCt+= pkt.payloadLen;
    if (pkt.tcpHeader->th_flags & TH_SYN){
      flowTable[pkt.keyStr] = 1;
    }
    else if (pkt.tcpHeader->th_flags & TH_FIN){
      flowTable.erase(pkt.keyStr);
    }
    else if (pkt.tcpHeader->th_flags & TH_RST){
      flowTable.erase(pkt.keyStr);      
    }
  }
  if ((curTs - lastLogTs) > LOGINTERVAL ){
    lastLogTs = curTs;
    cout << curTs << "," << flowTable.size() << "," << pktCt << "," << byteCt << endl;
  }
}