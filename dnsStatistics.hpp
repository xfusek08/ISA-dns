
/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    dnsStatistics.hpp
 * \brief
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.2018
 */
/******************************************************************************/

#pragma once

#include <string>
#include <map>
#include <vector>


enum dnsRecordType {
  A, AAAA, CNAME, MX, NS, SOA, TXT, SPF, DNSSEC
};

struct DNSStatRecord {
  std::string domainName;
  std::string ipAddress;
  dnsRecordType recType;
  unsigned int count;
};

class DNSStatistic {
public:
  DNSStatistic();
  ~DNSStatistic();
  void addRecord(DNSStatRecord);
  void addRecords(const std::vector<DNSStatRecord>&);
private:
  std::map<std::string, DNSStatRecord> _statistics;
};

std::vector<DNSStatRecord> resolveDnsResponsePacket(const unsigned char *);
