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
#include <unistd.h>

#include "utils.hpp"
#include "pcapProcessor.hpp"
#include "DNSStatistic.hpp"
#include "DNSResponse.hpp"

#define SIZE_ETHERNET (14)

using namespace std;
using namespace utils;

/**
 * hidden global variable for pcap handle to make sure that waiting for
 * next packet will be breakable form signal handler
 */
static pcap_t *glb_pcapHandle = nullptr;

/* signal handleing specifiing flag which is use to print out statistins */
static volatile sig_atomic_t glb_pcap_writeOutFlag = 0;
static volatile sig_atomic_t glb_pcap_sendToSyslogFlag = 0;

/* signal handleing specifiing flag which is use to print out statistins */
void pcap_writeoutSignal(int signum) {
  if (signum == SIGUSR1)
    glb_pcap_writeOutFlag = 1;
  else if (signum == SIGALRM)
    glb_pcap_sendToSyslogFlag = 1;
  else
    return;
  pcap_breakloop(glb_pcapHandle);
}

/**
 * @brief Function opens *.pcap file specified by given filename and returns initialized pcap_t handle.
 *
 * @param filename  Path to file to be open.
 * @return pcap_t*  Pcap handle initialized on offline file processing.
 *                  On error, message is written to stderr ont null is returned.
 */
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
    cerr << "Pcap offline failed: \"" << errbuf << "\"" << endl;
    return nullptr;
  }

  return pcapHandle;
}

/**
 * @brief Function opens live pcap on given interface device returns initialized pcap_t handle.
 *
 * @param interface name of interface device, can be ANY must not be emtpy
 * @return pcap_t*  Pcap handle initialized for live packet capturing.
 *                  On error, message is written to stderr ont null is returned.
 */
pcap_t *openLivePcap(const string& interface) {
  DWRITE("openPcapFile()");

  if (interface.empty()) {
    cerr << "Pcap file name is empty." << endl;
    return nullptr;
  } else if (interface == "any") {
    cerr << "Cannot use world \"any\" as an interface, feature is not supported." << endl;
    return nullptr;
  }

  // try open the pcap file
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcapHandle = pcap_open_live(
    interface.c_str(),  // device name
    1600,               // snapshot length
    1,                  // promiscuous mode
    1000,               // buffer timeout
    errbuf              // error buffer
  );
  if (pcapHandle == nullptr) {
    cerr << "Pcap open live failed: \"" << errbuf << "\"" << endl;
    return nullptr;
  }

  return pcapHandle;
}

/**
 * @brief Function initialize pcapHandle with device specified by deviceName and sets filter in filterExpr.
 * On error function writes error description on strerr and returns false.
 *
 * @param pcapHandle  handle to pcap structure. Must not be null.
 * @param deviceName  name of interface device. No device is used when this string is empty.
 * @param filterExpr  filter expression for pcap. No filter is used when this string is empty.
 * @return true       When everything went ok.
 * @return false      When error ocurred.
 */
bool initDeviceAndSetFilter(pcap_t *pcapHandle, const string& deviceName, const string& filterExpr) {
  if (pcapHandle == nullptr)
    return false;
  bpf_u_int32 mask = 0;
  bpf_u_int32 net = 0;
  struct bpf_program fp;

  if (!deviceName.empty()) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(deviceName.c_str(), &net, &mask, errbuf) == -1) {
      cerr << "Can't get netmask for device \"" << deviceName << "\"" << endl;
      cerr << "Error: " << errbuf << endl;
      return false;
    }
  }
  if (!filterExpr.empty()) {
    if (pcap_compile(pcapHandle, &fp, filterExpr.c_str(), 0, net) == -1) {
      cerr << "Couldn't parse filter \"" << filterExpr << "\": \"" << pcap_geterr(pcapHandle) << "\"" << endl;
      return false;
    }
    if (pcap_setfilter(pcapHandle, &fp) == -1) {
      cerr << "Error: pcap_setfilter() failed." << endl;
      return false;
    }
  }
  return true;
}

/**
 * @brief Supportive function gets information of number of bytes from tcp header.
 */
unsigned int getTcpHeaderSize(struct tcphdr *my_tcp) {
  // header len is in 4 bits after source (2B), dest(2B), seq (4B) and akc (4B) -> (12B in total)
  unsigned char headerLen = ((unsigned char *)my_tcp)[12];
  // we want value in top 4 bits
  unsigned int res = headerLen >> 4;
  // value means number of 4B words in header in total
  res = res * 4;

  DPRINTF("Src port = %d, dst port = %d, header len: %02x %uB\n", ntohs(my_tcp->source), ntohs(my_tcp->dest), headerLen, res);
  return res;
}

/**
 * @brief Supportive function returns true if in tcp header has specified PUSH flag.
 *
 * This code uses this function to determine if packet contains segmented
 * data (which we ignore) whole message is fit into one packet.
 */
bool isTcpMessageSegmented(struct tcphdr *my_tcp) {
  // 0x8 means PUSH mask 0000 1000
  return ((((unsigned char *)my_tcp)[12]) & 0x8) > 0;
}

/**
 * @brief Supportive function wraping parsing raw data from "firstCharOfData" by DNSResponse object
 * and filling result of this parsing into DNSStatistic object.
 */
void parseDnsData(const unsigned char *firstCharOfData, DNSResponse *respObj, std::shared_ptr<DNSStatistic> statObj) {
  if (respObj->parse(firstCharOfData)) {
    statObj->addAnswerRecords(respObj->answers);
    DWRITE("records parsed: " << respObj->answers.size());
  } else {
    DWRITE("corrupted -> dumped");
  }
}

/**
 * @brief Function decodes packet captured by pcap and if it is and dns response of right
 * type (see "Suported DNS Types" in DNSResponse.hpp) new record are added to the statistics object.
 *
 * @param packet  Pointer to first char of packet to be processed.
 * @param statObj Instance of DNSStatistics object to be filled with new data from actual packet
 */
void processOnePacket(const unsigned char *packet, std::shared_ptr<DNSStatistic> statObj) {
  struct ether_header *eptr = (struct ether_header *)packet;
  DNSResponse dnsResponse;

  switch (ntohs(eptr->ether_type)) {
    case ETHERTYPE_IP: { // IPv4
      struct ip *my_ip = (struct ip *)(packet + SIZE_ETHERNET); // skip Ethernet header
      u_int size_ip = my_ip->ip_hl * 4;                    // length of IP header
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
            DWRITE("segmented");
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
    } break;
    case ETHERTYPE_IPV6: // IPv6
      DPRINTF("Ethernet type is 0x%x, i.e., IPv6 packet\n", ntohs(eptr->ether_type));
      break;
    default:
      DPRINTF("Ethernet type 0x%x, not IPv4\n", ntohs(eptr->ether_type));
  }
}

/* Fill statistics with data from one pcap file (For more see pcapProcessor.hpp) */
bool processPcapFile(utils::ProgramOptions options, std::shared_ptr<DNSStatistic> statObj) {
  if (statObj == nullptr)
    return false;

  DWRITE("Processing file: " << options.pcapFileName);

  pcap_t *handle = openPcapFile(options.pcapFileName);
  if (handle == nullptr)
    return false;

  if (!initDeviceAndSetFilter(handle, "", DNS_PACKET_FILTER_EXP))
    return false;

  const u_char *packet;
  struct pcap_pkthdr actPcapPacketHeader;
  #ifdef DEBUG
  int n = 0;
  #endif
  while ((packet = pcap_next(handle, &actPcapPacketHeader)) != NULL) {
    DPRINTF("\nPacket no. %d:\n", ++n);
    processOnePacket(packet, statObj);
  }

  pcap_close(handle);
  return true;
}

/* Begins live packet capturing (For more see pcapProcessor.hpp) */
bool beginLiveDnsAnalysis(utils::ProgramOptions options, std::shared_ptr<DNSStatistic> statObj) {
  if (statObj == nullptr)
    return false;

  DWRITE("Start capturing on " << options.interface << ".");

  glb_pcapHandle = openLivePcap(options.interface);
  if (glb_pcapHandle == nullptr)
    return false;

  if (!initDeviceAndSetFilter(glb_pcapHandle, options.interface, DNS_PACKET_FILTER_EXP))
   return false;

  // set signal handler
  signal(SIGUSR1, pcap_writeoutSignal); // for writing on stdout
  signal(SIGALRM, pcap_writeoutSignal);  // for sending to syslog server

  const u_char *packet;
  struct pcap_pkthdr actPcapPacketHeader;

  #ifdef DEBUG
  int n = 0;
  #endif

  alarm(options.sendTimeIntervalSec);

  while (1) {
    while ((packet = pcap_next(glb_pcapHandle, &actPcapPacketHeader)) != NULL) {
      DPRINTF("\nPacket no. %d:\n", ++n);
      processOnePacket(packet, statObj);
    }

    if (glb_pcap_writeOutFlag == 1) {
      statObj->printStatistics();
      glb_pcap_writeOutFlag = 0;
    }

    if (glb_pcap_sendToSyslogFlag == 1) {
      statObj->sendToSyslog();
      alarm(options.sendTimeIntervalSec);
      glb_pcap_sendToSyslogFlag = 0;
    }
  }

  pcap_close(glb_pcapHandle);
  return true;
}
