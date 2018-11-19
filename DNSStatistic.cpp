/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    DNSStatistics.cpp
 * \brief   (Class and structures for DNS statistic gathering.)
 *          Implementation of DNSStatistics.hpp.
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.2018
 */
/******************************************************************************/

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

#include "utils.hpp"
#include "DNSStatistic.hpp"

#define SYSLOG_PORT_NUMBER_TXT "514"  // port of syslog server
#define MAX_SEND_ERRORS_IN_ROW 5      // maximal number of errors that are allowed to occur while
                                      // sending list of statistics to syslog server.

using namespace std;

/** Constructor */
DNSStatistic::DNSStatistic() {
  _isSyslogInitialized = false;
  _syslogSocket = 0;
  _localAddrString = "";
}

/** Destructor */
DNSStatistic::~DNSStatistic() {
  deinitSyslogServer();
}

/**
 * @brief Adds given record to statistics.
 *
 * (See DNSStatistic.hpp for more info.)
 */
void DNSStatistic::addAnswerRecord(const SDnsAnswerRecord& record) {
  bool isNew = true;
  for (unsigned int i = 0; i < _statistics.size(); ++i) {
    SDnsStatRecord *actRec = &(_statistics[i]);
    if (actRec->answerRec.domainName     == record.domainName &&
        actRec->answerRec.answerData == record.answerData &&
        actRec->answerRec.typeString     == record.typeString) {
      actRec->count++;
      isNew = false;
      break;
    }
  }

  if (isNew)
    _statistics.push_back({ record, 1 });
}

/**
 * @brief Adds vector of SDnsAnswerRecords to statistics via addAnswerRecord method.
 *
 * (See DNSStatistic.hpp for more info.)
 */
void DNSStatistic::addAnswerRecords(const std::vector<SDnsAnswerRecord>& records) {
  for (auto &rec : records)
    addAnswerRecord(rec);
}

/**
 * @brief Function initialize connection to syslog server.
 *
 * Code ispired by example at http://man7.org/linux/man-pages/man3/getaddrinfo.3.html
 * (See DNSStatistic.hpp for more info.)
 */
bool DNSStatistic::initSyslogServer(const std::string& servername) {
  if (_isSyslogInitialized)
    deinitSyslogServer();

  struct addrinfo hints;
  struct addrinfo *resultAddrs, *actResultAddr;
  int errCode;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
  hints.ai_socktype = SOCK_DGRAM; // Datagram socket - we want use UDP to send data
  hints.ai_flags = 0;
  hints.ai_protocol = 0;          // Any protocol

  DWRITE("Connecting to syslog server: \"" << servername << "\"");

  // lets get available ip addresses for syslog server
  errCode = getaddrinfo(servername.c_str(), SYSLOG_PORT_NUMBER_TXT, &hints, &resultAddrs);
  if (errCode != 0) {
    fprintf(stderr,
      "cannot resolve addres for syslog server \"%s\"\n"
      "getaddrinfo error: %s\n",
      servername.c_str(),
      gai_strerror(errCode)
    );
    return false;
  }

  vector<string> addresses = {};
  // iterate throw returned Addresses for server name until we succesfully conect
  for (actResultAddr = resultAddrs; actResultAddr != nullptr; actResultAddr = actResultAddr->ai_next) {
    addresses.push_back(utils::addrinfo_getAddrString(actResultAddr->ai_addr));
    DPRINTF("\tTrying address: \"%s\" ... ", addresses.back().c_str());

    _syslogSocket = socket(
      actResultAddr->ai_family, actResultAddr->ai_socktype, actResultAddr->ai_protocol
    );

    if (_syslogSocket == -1) {
      DWRITE("socket fail");
      continue;
    }

    if (connect(_syslogSocket, actResultAddr->ai_addr, actResultAddr->ai_addrlen) != -1) {
      DWRITE("success");
      break;
    }

    DWRITE("connect fail");
    close(_syslogSocket);
  }

  if (actResultAddr == nullptr) {               /* No address succeeded */
    cerr << "Connection to syslog server \"" << servername << "\" failed.\n";
    cerr << "Tried addresses:\n";
    for (const auto& addrStr : addresses) {
      cerr << "\t" << addrStr << endl;
    }
    return false;
  }

  freeaddrinfo(resultAddrs); // free memory allocated in getaddrinfo()

  // connetion was successfull

  // get local address
  struct sockaddr_storage localAddr;
  memset(&localAddr, 0, sizeof(struct sockaddr_storage));
  unsigned int len = sizeof(struct sockaddr_storage);
  if (getsockname(_syslogSocket, (struct sockaddr *)(&localAddr), &len) != 0) {
    cerr << "Error: cannot resolve local IP address.\n";
    return false;
  }
  _localAddrString = utils::addrinfo_getAddrString((struct sockaddr *)&localAddr);
  DWRITE("Local IP address: " << _localAddrString);

  _isSyslogInitialized = true;
  return true;
}

/**
 * @brief Disconnect from syslog server.
 *
 * (See DNSStatistic.hpp for more info.)
 */
void DNSStatistic::deinitSyslogServer() {
  DWRITE("deinitSyslogServer()");
  if (_isSyslogInitialized) {
    close(_syslogSocket);
    _syslogSocket = 0;
    _isSyslogInitialized = false;
  }
}

/**
 * @brief Send all statistics to syslog server.
 *
 * (See DNSStatistic.hpp for more info.)
 */
bool DNSStatistic::sendToSyslog() {
  DWRITE("sendToSyslog ... (" << _isSyslogInitialized << ")");
  if (!_isSyslogInitialized)
    return false;

  string message;
  unsigned int errorCnt = 0;
  unsigned int sendCnt = 0;

  // for each string in statistic
  for (const auto &rec : _statistics) {
    // build message
    // <local0 = 16 + Informational = 6> version = 1
    //  (16)1000      (6)110 = 134
    message =
      "<134>1 " + utils::getActTimeStampString() + " " +
      _localAddrString + " " +
      "dns-export - - - " +
      statToString(rec);

    DWRITE("Sending statistic: " << message);

    // send ...
    if (write(_syslogSocket, message.c_str(), message.length()) != (int)message.length()) {
      cerr << "Sending statistic to syslog server failed or partial write." << endl;
      ++errorCnt;
    }
    else {
      errorCnt = 0;
      ++sendCnt;
    }

    if (errorCnt >= MAX_SEND_ERRORS_IN_ROW) {
      cerr << "Error: Too much unsuccessful send tries in the row when reporting statistics to syslog server:" << endl;
      cerr << "\t" <<  _statistics.size() - sendCnt << " out of " << _statistics.size() << " failed to send." << endl;
      return false;
    }
  }
  if (sendCnt != _statistics.size()) {
    cerr << "Warning: Errors ocurred while sending statistics to syslog server:\n";
    cerr << "\t" <<  _statistics.size() - sendCnt << " out of " << _statistics.size() << " failed to send." << endl;
  }
  return true;
}

/**
 * @brief Prints statistinc in specific format to stdout, each line for one statistic record.
 */
void DNSStatistic::printStatistics() {
    DWRITE("printStatistics: " << _statistics.size());
    for (const auto &rec : _statistics) {
      cout << statToString(rec) << endl;
  }
}

/**
 * @brief Takes record and get formated string representing one statistic record.
 */
string DNSStatistic::statToString(const SDnsStatRecord &rec) {
  stringstream resStream;
  resStream <<
    rec.answerRec.domainName      << " " <<
    rec.answerRec.typeString      << " " <<
    rec.answerRec.answerData  << " " <<
    rec.count;
  return resStream.str();
}
