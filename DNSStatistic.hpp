
/******************************************************************************/
/**
 * @project ISA - Export DNS information with help of Syslog protocol
 * @file    DNSStatistics.hpp
 * @brief   Class and structures for DNS statistic gathering.
 * @author  Petr Fusek (xfusek08)
 * @date    19.11.2018
 */
/******************************************************************************/

#pragma once

#include <string>
#include <map>
#include <vector>

#include "DNSResponse.hpp"

/**
 * @brief One record of statistics. Holding information about concrete DNS ansver
 *        record from DNSResponse module and counter to store how many times this
 *        record was reserved.
 */
struct SDnsStatRecord {
  SDnsAnswerRecord answerRec;
  unsigned int count;
};

/**
 * @brief Class for gathering statistics about DNS traffics.
 *
 * Class uses records from DNSResponse module.
 * Also providing functionality for sending statistics in specific
 * format sto syslogserver.
 */
class DNSStatistic {
public:
  /** Constructor */
  DNSStatistic();

  /** Destructor */
  ~DNSStatistic();

  /**
   * @brief Adds given record to statistics.
   *
   * Creates new record in statistics or increment counter of existing statistic record.
   */
  void addAnswerRecord(const SDnsAnswerRecord&);

  /**
   * @brief Adds vector of SDnsAnswerRecords to statistics via addAnswerRecord method.
   */
  void addAnswerRecords(const std::vector<SDnsAnswerRecord>&);

  /**
   * @brief Function initialize connection to syslog server.
   *
   * Function tries to create connection to hostname specified in parameter.
   * Hostname should be in same format as node parameter of function getaddrinfo()
   * (see http://man7.org/linux/man-pages/man3/getaddrinfo.3.html).
   * If more addresses are resolved for one domain name connection is created for
   * the first succesful one.
   * @note calling this method is necessary before calling sendToSyslog method.
   * @return true   on success
   * @return false  on failure. Error and connection tires are written on stderr.
   */
  bool initSyslogServer(const std::string&);

  /**
   * @brief Disconnect from syslog server.
   *
   * Disconnect only if connection is initialized otherwise do nothing.
   */
  void deinitSyslogServer();

  /**
   * @brief Send all statistics to syslog server.
   *
   * Send actual statistics to syslog server in specific format.
   * Each statistic record is send as one datagram and certain amount of
   * failed sends are tolerated with warning written to stderr.
   * If more sends fails in one row error false is returned and error is
   * written out to etderr.
   *
   * @note Maximum number of failed sends in one row to raise error is
  *        specified by macro in *.cpp file and should be set to 5.
   * @note Server connetion has to be initialized therwise returns false and does nothing
   * @return true on success or semi-success of failing smaller number of sends.
   * @return false on failure, if more datagrams failed to send in one row
   *               or server connection weren't intialized.
   */
  bool sendToSyslog();

  /**
   * @brief Prints statistinc in specific format to stdout, each line for one statistic record.
   */
  void printStatistics();

  /**
   * @brief Takes record and get formated string representing one statistic record.
   *
   * @return std::string formated statistic record.
   */
  std::string statToString(const SDnsStatRecord &);
private:
  bool _isSyslogInitialized;
  int _syslogSocket;
  std::string _localAddrString;
  std::vector<SDnsStatRecord> _statistics;
};
