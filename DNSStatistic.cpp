/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    DNSStatistics.cpp
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

DNSStatistic::DNSStatistic() {
  _isSyslogInitialized = false;
}

DNSStatistic::~DNSStatistic() {}

void DNSStatistic::addAnswerRecord(const SDnsAnswerRecord& record) {
  bool isNew = true;
  for (unsigned int i = 0; i < _statistics.size(); ++i) {
    SDnsStatRecord *actRec = &(_statistics[i]);
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

void DNSStatistic::addAnswerRecords(const std::vector<SDnsAnswerRecord>& records) {
  for (auto &rec : records)
    addAnswerRecord(rec);
}

bool DNSStatistic::initializeSyslogServer(const std::string&) { return true; }

void DNSStatistic::sendToSyslog() {
  DWRITE("send to syslog ... ");
}

void DNSStatistic::printStatistics() {
    DWRITE("printStatistics: " << _statistics.size());
    for (auto &rec : _statistics) {
    cout <<
      rec.answerRec.domainName      << " " <<
      rec.answerRec.typeString      << " " <<
      rec.answerRec.translatedName  << " " <<
      rec.count                     << endl;
  }
}
