#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <math.h>
#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <cstring>
#include <sstream> // for ostringstream
#include <vector>
#include <deque>
#include <unordered_map>
#include <list>
#include "MurmerHash3.h"
using namespace std;


// Simple packet processor that tracks per-flow packet counts.


// g++ packetProcessor.cpp -o packetProcessor -lpcap -std=c++11
// ./packetProcessor ~jsonch/datasets/caida2015/caida2015_02_dirA.pcap

#define TRACETYPE 0 // type of PCAP -- 0 = ethernet (i.e., nccdc), 1 = ip4v (i.e., caida)
#define KEYLEN 13 // Length of key used in any flow tables. 



// Simple struct for packet information. 
// Key is (srcip, dstip, srcport, destport, proto)
struct PacketMetadata{
  std::string keyStr;
  char key[KEYLEN];
  uint64_t ts;
  char * payload; 
  int payloadLen;
};

// The input PCAP.
char * inputFile;

// Some example stuff that we might want to track.
uint64_t pktCt, lastPktCt;
// An example flow table. 
std::unordered_map<std::string, int> flowTable;

// timestamp in the pcap.
uint64_t startTs, curTs; 

// The function that actually processes packets.
void packetHandler(PacketMetadata pkt);
// Some logging stuff.
void printStats();
void printHeader();

// The function that we pass to libpcap. Just wraps packetHandler.
void packetHandler_wrapper(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// extract the 4 tuple key from the packet header.
void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader);
// get current TS, in microseconds, as a uint64. 
uint64_t getMicrosecondTs(uint32_t seconds, uint32_t microSeconds);
// Simple hash function. 
unsigned simpleHash(unsigned int p, const char* s, int len, int maxHashVal);
// Memory dump.
void print_hex_memory(void *mem, int len);

// modify here. This sample function just keeps a global packet count, and a packet count for each flow. 
void packetHandler(PacketMetadata pkt){

  // Increment global counter.
  pktCt++;

  // If the packet's key is not in the flow table, print its key. 
  auto got = flowTable.find(pkt.keyStr);
  if (got == flowTable.end()){
    cout << "adding new flow to table. Key:" << endl;
    print_hex_memory(pkt.key, KEYLEN);
  }

  // Increment flow counter -- this auto inserts if the key is not there. 
  flowTable[pkt.keyStr] +=1;

  // Print stats every 1M packets (~1 second)
  uint64_t diff = pktCt - lastPktCt;
  if (diff > 1000000){
    lastPktCt = pktCt;
    printStats();
    print_hex_memory(pkt.key, KEYLEN);
  }

}

void printHeader(){
  cout << "ts(ms), packet Ct, flow Ct" << endl;
}

void printStats(){
  cout <<curTs/1000 << ", " << pktCt << ", " << flowTable.size() << endl;
  return;
}

int main(int argc, char *argv[]){
  if (argc != 2){
    cout << "incorrect number of arguments. Need 1. (filename)." << endl;
    exit(0);
  }
  inputFile = argv[1];
  cout << "reading from file: " << inputFile << endl;
  // intParam = atoi(argv[2]);

  // Process packets. 
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  // open capture file for offline processing
  descr = pcap_open_offline(inputFile, errbuf);
  printHeader();
  if (descr == NULL) {
      cerr << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }
  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler_wrapper, NULL) < 0) {
      cerr << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }
  cout << "FINAL STATS:" << endl;
  printStats();

  return 0;
}

void packetHandler_wrapper(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  const struct udphdr* udpHeader;

  // Set global timestamp relative to start of pcap. 
  if (startTs == 0) startTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
  curTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) - startTs;

  if (TRACETYPE == 0){
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    }
  }
  else if (TRACETYPE == 1) {
    ipHeader = (struct ip*)(packet);

  }

  // Move packet into metadata. 
  PacketMetadata pkt;
  if (ipHeader->ip_p == 6){
    tcpHeader = (tcphdr*)((u_char*)ipHeader + sizeof(*ipHeader));
    setKey(pkt.key, ipHeader, (udphdr*)tcpHeader);
    pkt.payload = (char *)tcpHeader + sizeof(*tcpHeader);
    pkt.payloadLen = (pkthdr -> len) - sizeof(*ipHeader) - sizeof(*tcpHeader);
  }

  else if (ipHeader->ip_p == 17){
    udpHeader = (udphdr*)((u_char*)ipHeader + sizeof(*ipHeader));
    setKey(pkt.key, ipHeader, (udphdr*)udpHeader);
    pkt.payload = (char *)udpHeader + sizeof(*udpHeader);
    pkt.payloadLen = (pkthdr -> len) - sizeof(*ipHeader) - sizeof(*udpHeader);
  }
  pkt.keyStr = std::string(pkt.key, KEYLEN);
  pkt.ts = curTs;

  // Call packet processing function. 
  packetHandler(pkt);

}

// Helpers.
// Get 64 bit timestamp.
uint64_t getMicrosecondTs(uint32_t seconds, uint32_t microSeconds){
  uint64_t ts = seconds * 1000000 + microSeconds;
  return ts;
}

void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  memcpy(&(keyBuf[0]), &ipHeader->ip_src, 4);
  memcpy(&(keyBuf[4]), &ipHeader->ip_dst, 4);
  memcpy(&(keyBuf[8]), &udpOrtcpHeader->source, 2);
  memcpy(&(keyBuf[10]), &udpOrtcpHeader->dest, 2);
  memcpy(&(keyBuf[12]), &ipHeader->ip_p, 1);
}
void print_hex_memory(void *mem, int len) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<len;i++) {
    printf("0x%02x ", p[i]);
    // if (i%16==0)
    //   printf("\n");
  }
  printf("\n");
}
