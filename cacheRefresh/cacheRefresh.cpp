#include <unordered_map>
#include <vector>
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
uint64_t hitCount, totalCount;
uint64_t cumulativeHitCount, cumulativeTotalCount;

unordered_map<std::string, int> flowIdTable;

unordered_map<std::string, int> packetCountTable;

unordered_map<std::string, int> curIntervalCache;
unordered_map<std::string, int> lastIntervalCache;

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

  cout << "interval start ts(us), # flows, # packets, # cache hits, cumulative hit ratio " << endl;
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

  // at start of a time period, start a flow table to track packet counts.
  // at end of a time period, the table will have N flows. The top M are the ones to store in the cache. 
  // The cache represents an optimal cache built at the beginning of the interval.
  // The hit count is \sum{C_i , for i in M}.
  // The total count is  \sum{C_i, for i in N}

  // If start of a new interval:
  if ((curTs - refreshIntervalStart) >= refreshInterval) {

    // refresh the last interval cache.
    lastIntervalCache.clear();
    for (auto kv : curIntervalCache){
      lastIntervalCache[kv.first] = kv.second;
    }

    // refresh the current interval cache.
    curIntervalCache.clear();
    std::vector<std::pair<int, std::string>> tmp;
    for (auto kv : packetCountTable)
      tmp.emplace_back(std::pair<int, std::string>(kv.second, kv.first));
    sort(tmp.begin(), tmp.end(), sortinrev);
    for (int i = 0; i < std::min(cacheHeight, static_cast<int>(tmp.size())); i++)
      curIntervalCache[tmp[i].second] = tmp[i].first;

    // calculate counts.
    totalCount = 0;
    for (auto kv : packetCountTable)
      totalCount += kv.second;
    hitCount = 0;
    for (auto kv : packetCountTable){
      // if flow is in the current interval cache, increment hit count.
      if (curIntervalCache.find(kv.first) != curIntervalCache.end()){
        hitCount += kv.second;
      }
    }

    cumulativeTotalCount += totalCount;
    cumulativeHitCount += hitCount;
    float cumulativeRatio = float(cumulativeHitCount) / float(cumulativeTotalCount);
    // Interval start, flow count, packet count, hit count
    cout << refreshIntervalStart << ", " << packetCountTable.size() << ", " << totalCount << ", " << hitCount << ", " << cumulativeRatio << endl;
    // refresh the complete packet arrival table.
    packetCountTable.clear();

    // update interval start.
    refreshIntervalStart = curTs;
  }


  if (packetCountTable.find(pkt.keyStr) != packetCountTable.end()){
    packetCountTable[pkt.keyStr]++;
  } 
  else {
    packetCountTable[pkt.keyStr] = 1;
  }



  // if ((curTs - lastLogTs) > LOGINTERVAL ){
  //   lastLogTs = curTs;
  //   cout << curTs << "," << pktCt << "," << byteCt << endl;
  // }
}