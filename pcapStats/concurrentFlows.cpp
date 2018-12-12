#include <unordered_map>
#include <vector>
#include "pcapProcessor.h"
using namespace std;
/**
 *
 * Minimal pcap processor.
 *
 */
uint64_t pktCt = 0;
uint64_t byteCt = 0;
std::unordered_map<std::string, uint64_t> flowTable;

#define LOGINTERVAL 1000000
uint64_t lastLogTs = 0;

#define TIMEOUT_CHECK_INTERVAL 100000 // check for timeouts every 100ms (100K us)
#define TIMEOUT_THRESH 5000000
uint64_t lastTimeoutTs = 0;
void scanTimeouts();

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
  pktCt++;
  byteCt+= pkt.payloadLen;
  if (pkt.isTcp){
    flowTable[pkt.keyStr] = curTs;
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
  // scan for timeouts.

  if ((curTs - lastLogTs) > LOGINTERVAL ){
    lastLogTs = curTs;
    cout << curTs << "," << flowTable.size() << "," << pktCt << "," << byteCt << endl;
  }
  if ((curTs - lastTimeoutTs) > TIMEOUT_CHECK_INTERVAL){
    lastTimeoutTs = curTs;
    scanTimeouts();
  }
}

void scanTimeouts() {
  std::vector<std::string> expired;
  for (auto &it : flowTable){
    if (curTs - it.second > TIMEOUT_THRESH){
      expired.push_back(it.first);
    }
  }
  for (auto &key : expired) {
      flowTable.erase(key);
  }
}