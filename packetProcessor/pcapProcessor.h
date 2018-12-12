#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <iostream>
#include <cstring>

/*===========================================
=            consts and structs.            =
===========================================*/

#define KEYLEN 13 // Length of key used in any flow tables. 
#define VLAN_HDRLEN 4
// Simple struct for packet information. 
// Key is (srcip, dstip, srcport, destport, proto)
struct PacketMetadata{
  std::string keyStr;
  char key[KEYLEN];
  uint64_t ts;
  char * payload; 
  const struct tcphdr* tcpHeader;
  uint16_t payloadLen;
  bool isEth;
  bool isIp;
  bool isTcp;
  bool isUdp;

};

int traceType = 0;
uint64_t startTs = 0;
uint64_t curTs = 0; 

/*=====  End of consts and structs.  ======*/

/*===========================================
=            Abstract Functions.            =
===========================================*/
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);



/*=====  End of Abstract Functions.  ======*/



/*=========================================
=            Concrete functions.          =
=========================================*/
int parseFile(char * inputFile);
PacketMetadata getPktMetadata(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader);
uint64_t getMicrosecondTs(uint32_t seconds, uint32_t microSeconds);
void print_hex_memory(void *mem, int len);

/**
 *
 * Start parsing the file.
 *
 */
int parseFile(char * inputFile) {
  // std::cout << "reading from file: " << inputFile << std::endl;

  // Process packets. 
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  // open capture file for offline processing
  descr = pcap_open_offline(inputFile, errbuf);

  traceType = pcap_datalink(descr); // 1 = ethernet, 12 = IP
  if (descr == NULL) {
      std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
      return 1;
  }
  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
      std::cerr << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }
  return 0;

}

/**
 *
 * Get packet metadata in a convenient format.
 *
 */
PacketMetadata getPktMetadata(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  // Parse packet metadata. 
  PacketMetadata pkt;
  pkt.isEth = false;
  pkt.isIp = false;
  pkt.isTcp = false;
  pkt.isUdp = false;


  const struct ether_header* ethernetHeader;
  uint16_t vlan_tci, vlan_etype;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;
  const struct udphdr* udpHeader;


  // Set global timestamp relative to start of pcap. 
  if (startTs == 0) startTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
  curTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) - startTs;
  pkt.ts = curTs;

  // parse headers.
  if (traceType == 1){
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
      pkt.isEth = true;
      pkt.isIp = true;
      ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    }
    else if (ntohs(ethernetHeader->ether_type) == 0x8100){
      // std::cout << "vlan packet" << std::endl;
      vlan_etype = ntohs((uint16_t) *(packet + sizeof(struct ether_header) + 2));
      if (vlan_etype == ETHERTYPE_IP) {
        pkt.isIp = true;
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header) + VLAN_HDRLEN);
      }
      else {
        return pkt;
      }
    }
    else {
      return pkt;
    }
  }
  else if (traceType == 12) {
    ipHeader = (struct ip*)(packet);
    pkt.isEth = true;
    pkt.isIp = true;
  }
  else {
    std::cout << "unknown trace type" << std::endl;
    exit(1);
  }
  if (!pkt.isIp){
    return pkt;
  }

  if (ipHeader->ip_p == 6){
    tcpHeader = (tcphdr*)((u_char*)ipHeader + sizeof(*ipHeader));
    setKey(pkt.key, ipHeader, (udphdr*)tcpHeader);
    pkt.payload = (char *)tcpHeader + sizeof(*tcpHeader);
    pkt.payloadLen = (pkthdr -> len) - sizeof(*ipHeader) - sizeof(*tcpHeader);

    pkt.tcpHeader = tcpHeader;
    pkt.isTcp = true;
  }

  else if (ipHeader->ip_p == 17){
    udpHeader = (udphdr*)((u_char*)ipHeader + sizeof(*ipHeader));
    setKey(pkt.key, ipHeader, (udphdr*)udpHeader);
    pkt.payload = (char *)udpHeader + sizeof(*udpHeader);
    pkt.payloadLen = (pkthdr -> len) - sizeof(*ipHeader) - sizeof(*udpHeader);
    pkt.isUdp = true;
  }
  pkt.keyStr = std::string(pkt.key, KEYLEN); // Waste.

  return pkt;
}


/**
 *
 * Get 64 bit microsecond timestamp.
 *
 */
uint64_t getMicrosecondTs(uint32_t seconds, uint32_t microSeconds){
  uint64_t seconds_64 = (uint64_t) seconds;
  uint64_t microSeconds_64 = (uint64_t) microSeconds;
  uint64_t ts = seconds_64 * 1000000 + microSeconds_64;
  return ts;
}

/**
 *
 * Fill IP 5-tuple key.
 *
 */
void setKey(char *keyBuf, const struct ip* ipHeader, const struct udphdr* udpOrtcpHeader){
  memcpy(&(keyBuf[0]), &ipHeader->ip_src, 4);
  memcpy(&(keyBuf[4]), &ipHeader->ip_dst, 4);
  memcpy(&(keyBuf[8]), &udpOrtcpHeader->source, 2);
  memcpy(&(keyBuf[10]), &udpOrtcpHeader->dest, 2);
  memcpy(&(keyBuf[12]), &ipHeader->ip_p, 1);
}

/**
 *
 * Print hex mem.
 *
 */
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

/*=====  End of Concrete functions.  ======*/
