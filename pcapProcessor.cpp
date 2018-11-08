/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    pcapProcessor.cpp
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#include <iostream>
#include <string>

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

#define SIZE_ETHERNET (14)
#define DNS_PACKET_FILTER_EXP "port 53"

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

bool processPcap(pcap_t *pcapHandle, const string& deviceName, const string& filterExp) {
  DWRITE("processPcap()");

  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask = 0;
  bpf_u_int32 net = 0;
  struct bpf_program fp;

  if (!deviceName.empty()) {
    if (pcap_lookupnet(deviceName.c_str(), &net, &mask, errbuf) == -1) {
      cerr << "Can't get netmask for device \"" << deviceName << "\"" << endl;
      cerr << "Error: " << errbuf << endl;
      return false;
    }
  }

  if (pcap_compile(pcapHandle, &fp, filterExp.c_str(), 0, net) == -1) {
    cerr << "Couldn't parse filter \"" << filterExp << "\": \"" << pcap_geterr(pcapHandle) << "\"" << endl;
    return false;
  }

  if (pcap_setfilter(pcapHandle, &fp) == -1) {
    cerr << "Error: pcap_setfilter() falied." << endl;
    return false;
  }

  const u_char *packet;
  struct pcap_pkthdr actPcapPacketHeader;
  u_int size_ip;
  struct ip *my_ip;
  int n = 0;
  while ((packet = pcap_next(pcapHandle, &actPcapPacketHeader)) != NULL) {
    printf("Packet no. %d:\n", ++n);
    printf("\tLength %d, received at %s", actPcapPacketHeader.len, ctime((const time_t *)&actPcapPacketHeader.ts.tv_sec));

    // read the Ethernet header
    struct ether_header *eptr = (struct ether_header *)packet;
    printf("\tSource MAC: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    printf("\tDestination MAC: %s\n\t", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
    switch (ntohs(eptr->ether_type))
    {                  // see /usr/include/net/ethernet.h for types
      case ETHERTYPE_IP: // IPv4 packet
        printf("Ethernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));
        my_ip = (struct ip *)(packet + SIZE_ETHERNET); // skip Ethernet header
        size_ip = my_ip->ip_hl * 4;                    // length of IP header

        printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n", ntohs(my_ip->ip_id), size_ip, my_ip->ip_v, ntohs(my_ip->ip_len), my_ip->ip_ttl);
        printf("\tIP src = %s, ", inet_ntoa(my_ip->ip_src));
        printf("IP dst = %s\n\t", inet_ntoa(my_ip->ip_dst));

        switch (my_ip->ip_p)
        {
          case 2: // IGMP protocol
            printf("protocol IGMP (%d)\n", my_ip->ip_p);
            break;
          case 6: // TCP protocol
            printf("protocol TCP (%d)\n", my_ip->ip_p);
            break;
          case 17: // UDP protocol
            printf("protocol UDP (%d)\n", my_ip->ip_p);
            break;
          default:
            printf("protocol %d\n", my_ip->ip_p);
        }
        break;
      case ETHERTYPE_IPV6: // IPv6
        printf("Ethernet type is 0x%x, i.e., IPv6 packet\n", ntohs(eptr->ether_type));
        break;
      case ETHERTYPE_ARP: // ARP
        printf("Ethernet type is 0x%x, i.e., ARP packet\n", ntohs(eptr->ether_type));
        break;
      default:
        printf("Ethernet type 0x%x, not IPv4\n", ntohs(eptr->ether_type));
    }
  }

  return true;
}

bool processPcapFile(utils::ProgramOptions options) {
  DWRITE("processPcapFile()");
  pcap_t *handle = openPcapFile(options.pcapFileName);
  bool success = processPcap(handle, "", DNS_PACKET_FILTER_EXP);
  pcap_close(handle);
  return success;
}
