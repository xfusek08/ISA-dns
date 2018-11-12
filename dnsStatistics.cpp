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
#include <map>
#include <vector>

#include "utils.hpp"
#include "dnsStatistics.hpp"
#include "DNSResponse.hpp"

std::vector<DNSStatRecord> resolveDnsResponsePacket(const unsigned char *firstCharOfPacketData) {
  DNSResponse answer;
  answer.parse(firstCharOfPacketData);
  return {};
}

DNSStatistic::DNSStatistic() {}

DNSStatistic::~DNSStatistic() {}

void DNSStatistic::addRecord(DNSStatRecord record) {
  (void) record;
}

void DNSStatistic::addRecords(const std::vector<DNSStatRecord> &records) {
  (void) records;
}