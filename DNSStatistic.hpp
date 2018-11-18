
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
  bool initSyslogServer(const std::string&);
  void deinitSyslogServer();
  void sendToSyslog();
  void printStatistics();
  std::string statToString(const SDnsStatRecord &);
private:
  bool _isSyslogInitialized;
  int _syslogSocket;
  std::string _localAddrString;
  std::vector<SDnsStatRecord> _statistics;
  std::string answerRecToString(const SDnsAnswerRecord&);
};
