#include <unordered_map>
#include <vector>
#include <algorithm>
#include "pcapProcessor.h"
using namespace std;
/**
 *
 * Parses the active flows during intervals.
 *
 */
// Local variables.
uint64_t pktCt = 0;
uint64_t byteCt = 0;

uint64_t curPktCt = 0;
unordered_map<std::string, int> flowIdTable;
unordered_map<std::string, int> packetCountTable;


uint64_t refreshIntervalStart = 0;
int refreshInterval;
int cacheHeight;
#define LOGINTERVAL 1000
uint64_t lastLogTs = 0;

// Parse the file.
int main(int argc, char *argv[]){
  if (argc != 4){
    cout << "incorrect number of arguments. Need 3. (pcap filename, cache height (# flow slots), cache refresh interval (us))." << endl;
    exit(0);
  }
  char * inputFile = argv[1];
  cacheHeight = atoi(argv[2]);
  refreshInterval = atoi(argv[3]);

  // cout << "ts(us)" << endl;
  parseFile(inputFile);
  // cout << curTs << "," << pktCt << "," << byteCt << endl;
  return 0;
}


bool sortinrev(const pair<int,std::string> &a,  
               const pair<int,std::string> &b) 
{ 
       return (a.first > b.first); 
} 
// Do custom analysis.
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  PacketMetadata pkt = getPktMetadata(userData, pkthdr, packet);

  // If start of a new interval:
  if ((curTs - refreshIntervalStart) >= refreshInterval) {
    // Sort the flows by packet ID.
    std::vector<std::pair<int, std::string>> tmp;
    for (auto kv : packetCountTable)
      tmp.emplace_back(std::pair<int, std::string>(kv.second, kv.first));
    sort(tmp.begin(), tmp.end(), sortinrev);

    // Print the top N flowsIDs (predeeded by the interval)
    int ct = 0;
    cout << refreshIntervalStart << ", ";
    for (auto vk : tmp){
      ct++;
      if (ct > cacheHeight)
        break;
      cout << flowIdTable[vk.second] << ", ";
    }
    cout << endl;
    // Print top N flows' weights. (preceeded by the number of packets)
    ct = 0;
    cout << curPktCt << ", ";
    for (auto vk : tmp){
      ct++;
      if (ct > cacheHeight)
        break;
      cout << vk.first << ", ";
    }
    cout << endl;
    // clear the packet count table.
    packetCountTable.clear();

    // update interval start.
    refreshIntervalStart = curTs;
    // reset current interval packet count.
    curPktCt = 0;
  }

  

  if (flowIdTable.find(pkt.keyStr) == packetCountTable.end())
    flowIdTable[pkt.keyStr] = flowIdTable.size();  

  if (packetCountTable.find(pkt.keyStr) != packetCountTable.end())
    packetCountTable[pkt.keyStr]++;
  else
    packetCountTable[pkt.keyStr] = 1;
  curPktCt++;


  // if ((curTs - lastLogTs) > LOGINTERVAL ){
  //   lastLogTs = curTs;
  //   cout << curTs << "," << pktCt << "," << byteCt << endl;
  // }
}