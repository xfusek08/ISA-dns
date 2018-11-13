/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    pcapProcessor.cpp
 * \brief
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.1018
 */
/******************************************************************************/

#include <iostream>
#include <string>

#include <string.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

#include "utils.hpp"
#include "pcapProcessor.hpp"
#include "DNSStatistic.hpp"
#include "DNSResponse.hpp"

#define SIZE_ETHERNET (14)
#define DNS_PACKET_FILTER_EXP "(dst port 53) or (src port 53)"

using namespace std;
using namespace utils;

pcap_t *openPcapFile(const string& filename) {
  DWRITE("openPcapFile()");

  if (filename.empty()) {
    cerr << "Pcap file name is empty." << endl;
    return nullptr;
  }

  // try open the pcap file
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcapHandle = pcap_open_offline(filename.c_str(), errbuf);
  if (pcapHandle == nullptr) {
    cerr << "Pcap fail: \"" << errbuf << "\"" << endl;
    return nullptr;
  }

  return pcapHandle;
}

bool initDevice(const string& deviceName, bpf_u_int32 *net, bpf_u_int32 *mask) {
  if (!deviceName.empty()) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(deviceName.c_str(), net, mask, errbuf) == -1) {
      cerr << "Can't get netmask for device \"" << deviceName << "\"" << endl;
      cerr << "Error: " << errbuf << endl;
      return false;
    }
  }
  return true;
}

bool compileAndSetFilter(pcap_t *pcapHandle, bpf_u_int32 *net, const string& filterExpr) {
  struct bpf_program fp;
  if (pcap_compile(pcapHandle, &fp, filterExpr.c_str(), 0, *net) == -1) {
    cerr << "Couldn't parse filter \"" << filterExpr << "\": \"" << pcap_geterr(pcapHandle) << "\"" << endl;
    return false;
  }
  if (pcap_setfilter(pcapHandle, &fp) == -1) {
    cerr << "Error: pcap_setfilter() falied." << endl;
    return false;
  }
  return true;
}

unsigned int getTcpHeaderSize(struct tcphdr *my_tcp) {
  // header len is in 4 bits after source (2B), dest(2B), seq (4B) and akc (4B) -> (12B in total)
  unsigned char headerLen = ((unsigned char *)my_tcp)[12];
  // we want value in top 4 bits
  unsigned int res = headerLen >> 4;
  // value means number of 4B words in header in total
  res = res * 4;

  DPRINTF("Src port = %d, dst port = %d, header len: %02x %uB\n", ntohs(my_tcp->source), ntohs(my_tcp->dest), headerLen, res);

  // for (int i = 0; i < 16; ++i) {
  //   fprintf(stderr, "%02x ", ((unsigned char *)my_tcp)[i]);
  //   if ((i + 1) % 4 == 0)
  //     fprintf(stderr, "\n");
  // }
  // fprintf(stderr, "\n");
  return res;
}

/* returns true if in tcp header is specified PUSH flag */
bool isTcpMessageSegmented(struct tcphdr *my_tcp) {
  // 0x8 means PUHS mask 0000 1000
  return ((((unsigned char *)my_tcp)[12]) & 0x8) > 0;
}

void parseDnsData(const unsigned char *firstCharOfData, DNSResponse *respObj, std::shared_ptr<DNSStatistic> statObj) {
  if (respObj->parse(firstCharOfData)) {
    statObj->addAnswerRecords(respObj->answers);
    DWRITE("records parsed: " << respObj->answers.size());
  } else {
    DWRITE("corrupted -> dumped");
  }
}

bool processPcap(pcap_t *pcapHandle, const string& deviceName, const string& filterExpr, std::shared_ptr<DNSStatistic> statObj) {
  if (pcapHandle == nullptr || statObj == nullptr)
    return false;

  bpf_u_int32 mask = 0;
  bpf_u_int32 net = 0;
  if (!initDevice(deviceName, &net, &mask))
    return false;
  if (!compileAndSetFilter(pcapHandle, &net, filterExpr))
    return false;

  const u_char *packet;
  struct pcap_pkthdr actPcapPacketHeader;
  u_int size_ip;
  struct ip *my_ip;
  int n = 0;

  DNSResponse dnsResponse;
  while ((packet = pcap_next(pcapHandle, &actPcapPacketHeader)) != NULL) {
    DPRINTF("\nPacket no. %d:\n", ++n);

    // read the Ethernet header
    struct ether_header *eptr = (struct ether_header *)packet;
    switch (ntohs(eptr->ether_type))
    {                  // see /usr/include/net/ethernet.h for types
      case ETHERTYPE_IP: // IPv4 packet
        my_ip = (struct ip *)(packet + SIZE_ETHERNET); // skip Ethernet header
        size_ip = my_ip->ip_hl * 4;                    // length of IP header
        switch (my_ip->ip_p)
        {
          case 6: { // TCP protocol
            DPRINTF("protocol TCP (%d); ", my_ip->ip_p);
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + SIZE_ETHERNET + size_ip);
            unsigned int headerSize = getTcpHeaderSize(tcpHeader);
            // ignoring from statistics when tcp carries DNS payload in multiple segmets
            if (!isTcpMessageSegmented(tcpHeader)) {
              // dns message is after 2B specifiing length
              // it is posible that this packet is last segment of segmented - parsing will fail and data are ignored
              parseDnsData(
                (const unsigned char *)tcpHeader + headerSize + 2,
                &dnsResponse,
                statObj
              );
            } else {
              DWRITE("segmentated");
            }
          } break;
          case 17: { // UDP protocol
            DPRINTF("protocol UDP (%d); ", my_ip->ip_p);
            // struct udphdr *my_udp = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);
            // parse dns packet to response
            parseDnsData(
              packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr),
              &dnsResponse,
              statObj
            );
          } break;
          default:
            DPRINTF("protocol %d\n", my_ip->ip_p);
        }
        break;
      case ETHERTYPE_IPV6: // IPv6
        DPRINTF("Ethernet type is 0x%x, i.e., IPv6 packet\n", ntohs(eptr->ether_type));
        break;
      default:
        DPRINTF("Ethernet type 0x%x, not IPv4\n", ntohs(eptr->ether_type));
    }
  }

  return true;
}

bool processPcapFile(utils::ProgramOptions options, std::shared_ptr<DNSStatistic> statObj) {
  if (statObj == nullptr)
    return false;
  pcap_t *handle = openPcapFile(options.pcapFileName);
  bool success = processPcap(
    handle,                 // pcap handle
    "",                     // device name
    DNS_PACKET_FILTER_EXP,  // filter expresion
    statObj                 // statistic gaethering object
  );
  pcap_close(handle);
  return success;
}
