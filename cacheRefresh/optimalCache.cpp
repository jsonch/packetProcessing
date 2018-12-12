#include <unordered_map>
#include <vector>
#include <list>
#include <algorithm>
#include "pcapProcessor.h"
using namespace std;
/**
 *
 * Identify the best flows to cache for a given time window.
 *
 */
// Local variables.
uint64_t pktCt = 0;
uint64_t byteCt = 0;

unordered_map<std::string, int> flowIdTable;
unordered_map<std::string, int> packetCountTable;


list<struct PacketMetadata> pktBuffer;

int cacheHeight;
#define LOGINTERVAL 1000
uint64_t lastLogTs = 0;

// Parse the file.
int main(int argc, char *argv[]){
  if (argc != 3){
    cout << "incorrect number of arguments. Need 2. (pcap filename, cache height (# flow slots))." << endl;
    exit(0);
  }
  char * inputFile = argv[1];
  cacheHeight = atoi(argv[2]);

  // cout << "ts(us)" << endl;

  // cout << "interval start ts(us), # flows, # packets, # cache hits, cumulative hit ratio " << endl;
  parseFile(inputFile);
  // cout << curTs << "," << pktCt << "," << byteCt << endl;
  return 0;
}

#define BUFSIZE 100000


unordered_map<std::string, int> curCache;
unordered_map<std::string, int> lastCache;

bool sortinrev(const pair<int,std::string> &a,  
               const pair<int,std::string> &b) 
{ 
       return (a.first > b.first); 
} 

int getCache(){
  int changeCt = 0;
  // move current cache to last cache, rebuild current cache.
  lastCache.clear();
  for (auto kv : curCache){
    lastCache[kv.first] = kv.second;
  }
  curCache.clear();

  // // Fill the cache with the entries that you will need soon. 
  // for (auto pkt : pktBuffer){
  //   // if the flow is not in the cache, and there is room in the cache, add it.
  //   if (curCache.find(pkt.keyStr) == curCache.end()){
  //     if (curCache.size() < cacheHeight){
  //       curCache[pkt.keyStr]
  //     }
  //   }
  // }  

  std::vector<std::pair<int, std::string>> tmp;
  for (auto kv : packetCountTable)
   tmp.emplace_back(std::pair<int, std::string>(kv.second, kv.first));
  sort(tmp.begin(), tmp.end(), sortinrev);
  for (int i = 0; i < std::min(cacheHeight, static_cast<int>(tmp.size())); i++){
    curCache[tmp[i].second] = tmp[i].first;
    // Count number of changes.
    if (lastCache.find(tmp[i].second) == lastCache.end())
      changeCt++;
  }
  return changeCt;
}

// Do custom analysis.
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  PacketMetadata pkt = getPktMetadata(userData, pkthdr, packet);

  // put packet at back of buffer and update the table.
  pktBuffer.push_back(pkt);
  packetCountTable[pkt.keyStr]++;

  // if buffer has enough packets, process the first packet in the buffer.
  if (pktBuffer.size() == BUFSIZE){
    auto newPkt = pktBuffer.front();
    packetCountTable[newPkt.keyStr]--;    

    // Update cache.
    int changeCt = getCache();

    if (changeCt > 0)
      cout << curTs << ", " << changeCt << endl;


    pktBuffer.pop_front();



  }

  // // If start of a new interval:
  // if ((curTs - refreshIntervalStart) >= refreshInterval) {

  //   // refresh the last interval cache.
  //   lastIntervalCache.clear();
  //   for (auto kv : curIntervalCache){
  //     lastIntervalCache[kv.first] = kv.second;
  //   }

  //   // refresh the current interval cache.

  //   // calculate counts.
  //   totalCount = 0;
  //   for (auto kv : packetCountTable)
  //     totalCount += kv.second;
  //   hitCount = 0;
  //   for (auto kv : packetCountTable){
  //     // if flow is in the current interval cache, increment hit count.
  //     if (curIntervalCache.find(kv.first) != curIntervalCache.end()){
  //       hitCount += kv.second;
  //     }
  //   }

  //   cumulativeTotalCount += totalCount;
  //   cumulativeHitCount += hitCount;
  //   float cumulativeRatio = float(cumulativeHitCount) / float(cumulativeTotalCount);
  //   // Interval start, flow count, packet count, hit count
  //   cout << refreshIntervalStart << ", " << packetCountTable.size() << ", " << totalCount << ", " << hitCount << ", " << cumulativeRatio << endl;
  //   // refresh the complete packet arrival table.
  //   packetCountTable.clear();

  //   // update interval start.
  //   refreshIntervalStart = curTs;
  // }


  // if (packetCountTable.find(pkt.keyStr) != packetCountTable.end()){
  //   packetCountTable[pkt.keyStr]++;
  // } 
  // else {
  //   packetCountTable[pkt.keyStr] = 1;
  // }



  // if ((curTs - lastLogTs) > LOGINTERVAL ){
  //   lastLogTs = curTs;
  //   cout << curTs << "," << pktCt << "," << byteCt << endl;
  // }
}