
/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    DNSStatistics.hpp
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

struct SDnsStatRecord {
  SDnsAnswerRecord answerRec;
  unsigned int count;
};

class DNSStatistic {
public:
  DNSStatistic();
  ~DNSStatistic();
  void addAnswerRecord(const SDnsAnswerRecord&);
  void addAnswerRecords(const std::vector<SDnsAnswerRecord>&);
  std::vector<SDnsStatRecord> getStatistics();
  bool initializeSyslogServer(const std::string&);
  void sendToSyslog();
  void printStatistics();
private:
  bool _isSyslogInitialized;
  std::vector<SDnsStatRecord> _statistics;
  std::string answerRecToString(const SDnsAnswerRecord&);
};
