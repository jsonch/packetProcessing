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

// Parse the file.
int main(int argc, char *argv[]){
  if (argc != 2){
    cout << "incorrect number of arguments. Need 1. (filename)." << endl;
    exit(0);
  }
  char * inputFile = argv[1];

  cout << "ts(us), packets, bytes" << endl;
  parseFile(inputFile);
  cout << curTs << "," << pktCt << "," << byteCt << endl;
  return 0;
}

// Do custom analysis.
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  PacketMetadata pkt = getPktMetadata(userData, pkthdr, packet);
  pktCt++;
  byteCt+= pkt.payloadLen;
  if ((curTs - lastLogTs) > LOGINTERVAL ){
    lastLogTs = curTs;
    cout << curTs << "," << pktCt << "," << byteCt << endl;
  }
}