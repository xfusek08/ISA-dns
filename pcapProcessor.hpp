
/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    pcapProcessor.hpp
 * \brief
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.1018
 */
/******************************************************************************/

#pragma once

#include <memory>
#include <signal.h>

#include "utils.hpp"
#include "DNSStatistic.hpp"

/* Here is specified pcap filter which will be used in this module for capturing */
#define DNS_PACKET_FILTER_EXP "(dst port 53) or (src port 53)"

/**
 * @brief Fill statistics with data from one pcap file
 *
 * Function takes in program options, initialize pcap and proccess *.pcap
 * file packet by packet. Statistics of dns comunication are generated into
 * given DNSStatistic object. Whole file is proccesed in one run.
 * Function returns true when everything went ok, and false on error.
 *
 * @return true                           When statisitcs are succesfully generated
 * @return false                          when error occures.
 */
bool processPcapFile(utils::ProgramOptions, std::shared_ptr<DNSStatistic>);

/**
 * @brief Begins live packet capturing
 *
 * Function takes in program options, initialize pcap and begins monitoring
 * specified interface. Capturing dns packet and filling statistics.
 * Very x seconds specified in ProgramOptions::sendTimeIntervalSec function
 * will invoke sendToSyslog() method on statistics.
 */
bool beginLiveDnsAnalysis(utils::ProgramOptions, std::shared_ptr<DNSStatistic>);
