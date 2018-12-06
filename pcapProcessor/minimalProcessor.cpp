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
std::unordered_map<std::string, int> flowTable;

// Parse the file.
int main(int argc, char *argv[]){
  if (argc != 2){
    cout << "incorrect number of arguments. Need 1. (filename)." << endl;
    exit(0);
  }
  char * inputFile = argv[1];
  parseFile(inputFile);
  cout << "parsed " << pktCt << " packets" << endl;
  return 0;
}

// Do custom analysis.
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  PacketMetadata pkt = getPktMetadata(userData, pkthdr, packet);
  pktCt++;
  if (pktCt % 10000000 == 0){
    cout << "pktCt: " << pktCt << endl;
  }
}