
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

#include "DNSResponse.hpp"

enum EStatDNSType {
  A, AAAA, CNAME, MX, NS, SOA, TXT, SPF
};

struct DNSStatRecord {
  SDNSAnswerRecord answerRec;
  unsigned int count;
};

class DNSStatistic {
public:
  DNSStatistic();
  ~DNSStatistic();
  void addAnswerRecord(const SDNSAnswerRecord&);
  void addAnswerRecords(const std::vector<SDNSAnswerRecord>&);
  std::vector<DNSStatRecord> getStatistics();
private:
  std::vector<DNSStatRecord> _statistics;
  std::string answerRecToString(const SDNSAnswerRecord&);
};
