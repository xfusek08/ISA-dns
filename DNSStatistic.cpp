/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    dnsStatistics.cpp
 * \brief
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.2018
 */
/******************************************************************************/

#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#include "utils.hpp"
#include "DNSStatistic.hpp"

using namespace std;

DNSStatistic::DNSStatistic() {}

DNSStatistic::~DNSStatistic() {}

void DNSStatistic::addAnswerRecord(const SDNSAnswerRecord& record) {
  bool isNew = true;
  for (unsigned int i = 0; i < _statistics.size(); ++i) {
    DNSStatRecord *actRec = &(_statistics[i]);
    if (actRec->answerRec.domainName     == record.domainName &&
        actRec->answerRec.translatedName == record.translatedName &&
        actRec->answerRec.typeString     == record.typeString) {
      actRec->count++;
      isNew = false;
      break;
    }
  }

  if (isNew)
    _statistics.push_back({ record, 1 });
}

void DNSStatistic::addAnswerRecords(const std::vector<SDNSAnswerRecord>& records) {
  for (auto &rec : records)
    addAnswerRecord(rec);
}

std::vector<DNSStatRecord> DNSStatistic::getStatistics() {
  return _statistics;
}
