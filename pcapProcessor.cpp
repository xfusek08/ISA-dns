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
  struct tcphdr *my_tcp;
  struct udphdr *my_udp;
  int n = 0;
  DNSResponse dnsResponse;
  while ((packet = pcap_next(pcapHandle, &actPcapPacketHeader)) != NULL) {
    DPRINTF("\nPacket no. %d:\n", ++n);
    // DPRINTF("\tLength %d, received at %s", actPcapPacketHeader.len, ctime((const time_t *)&actPcapPacketHeader.ts.tv_sec));

    // read the Ethernet header
    struct ether_header *eptr = (struct ether_header *)packet;
    // DPRINTF("\tSource MAC: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    // DPRINTF("\tDestination MAC: %s\n\t", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
    switch (ntohs(eptr->ether_type))
    {                  // see /usr/include/net/ethernet.h for types
      case ETHERTYPE_IP: // IPv4 packet
        DPRINTF("Ethernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));
        my_ip = (struct ip *)(packet + SIZE_ETHERNET); // skip Ethernet header
        size_ip = my_ip->ip_hl * 4;                    // length of IP header

        // DPRINTF("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n", ntohs(my_ip->ip_id), size_ip, my_ip->ip_v, ntohs(my_ip->ip_len), my_ip->ip_ttl);
        // DPRINTF("IP src = %s, ", inet_ntoa(my_ip->ip_src));
        // DPRINTF("IP dst = %s\n", inet_ntoa(my_ip->ip_dst));

        switch (my_ip->ip_p)
        {
          case 2: // IGMP protocol
            DPRINTF("protocol IGMP (%d); ", my_ip->ip_p);
            break;
          case 6: // TCP protocol
            DPRINTF("protocol TCP (%d); ", my_ip->ip_p);
            my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
            DPRINTF("Src port = %d, dst port = %d, seq = %u",ntohs(my_tcp->source), ntohs(my_tcp->dest), ntohl(my_tcp->seq));
            break;
          case 17: // UDP protocol
            DPRINTF("protocol UDP (%d); ", my_ip->ip_p);
            my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
            DPRINTF("Src port = %d, dst port = %d, length %d\n",ntohs(my_udp->source), ntohs(my_udp->dest), ntohs(my_udp->len));
            // parse dns packet to response
            if (dnsResponse.parse(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr))) {
              statObj->addAnswerRecords(dnsResponse.answers);
            }

            break;
          default:
            DPRINTF("protocol %d\n", my_ip->ip_p);
        }
        break;
      case ETHERTYPE_IPV6: // IPv6
        DPRINTF("Ethernet type is 0x%x, i.e., IPv6 packet\n", ntohs(eptr->ether_type));
        break;
      case ETHERTYPE_ARP: // ARP
        DPRINTF("Ethernet type is 0x%x, i.e., ARP packet\n", ntohs(eptr->ether_type));
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
