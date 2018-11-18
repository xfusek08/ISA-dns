/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    pcapFileProcessor.hpp
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.1018
 */
/******************************************************************************/

#pragma once

#define STREAM_TO_STR(S)         static_cast<std::ostringstream&>(ostringstream() << S).str()
#define raiseErrorStream(S)      utils::raiseError(STREAM_TO_STR(S))
#define raiseErrorStreamHelp(S)  utils::raiseError(STREAM_TO_STR(S), true)

#ifdef DEBUG
#define DWRITE(T)             cerr << T << endl
#define DPRINTF(T, args ...)  fprintf(stderr, T, args)
#else
#define DWRITE(S)             do {} while(0)
#define DPRINTF(T, args ...)  do {} while(0)
#endif

#include <string>

namespace utils {
  struct ProgramOptions {
    bool isPcapFile;                    // flag if *.pcap file is specified
    bool isInterface;                   // flag if network interface device is specified
    bool isSyslogserveAddress;          // flag if syslog server address or name was specified
    std::string   pcapFileName;         // path to *.pcap file
    std::string   interface;            // name of network interface device
    std::string   syslogServerAddress;  // address or domain name of syslog server
    unsigned int sendTimeIntervalSec;   // interval in seconds in which statistics will be send to syslog server
  } ;

  /**
   * @brief Function offer an unified way to handle and exit program on errors
   */
  void raiseError(const std::string& message, const bool checkHelp = false);
  void raiseError(const char *message = nullptr, const bool checkHelp = false);

  /**
   * @brief Function is same as util_raiseError but message is called with perror function
   */
  void raisePerror(const std::string& message, const bool checkHelp = false);
  void raisePerror(const char *message = nullptr, const bool checkHelp = false);

  /**
   * @brief Function takes struct addrinfo and translates information about address int readable string
   * regaldless if its IPv4 or IPv6.
   *
   * @param addrinfo  pointer to struct addrinfo storing arddes to be translated
   * @return string   translated address string, empty string on error or if address does not exixts.
   */
  std::string addrinfo_getAddrString(const struct sockaddr *addrinfo);

  /**
   * @brief Get the Act Time Stamp String object
   *
   * @return retruns act time in string formatet for syslog in format
   * yyyy-MM-dd'T'HH:mm:ss.SSS'Z' by RFC3339
   */
  std::string getActTimeStampString();
}
