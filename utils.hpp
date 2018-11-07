/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    pcapFileProcessor.hpp
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#pragma once

#define STREAM_TO_STR(S)     static_cast<std::ostringstream&>(ostringstream() << S).str()
#define raiseErrorStream(S)  raiseError(STREAM_TO_STR(S))

#ifdef DEBUG
#define DWRITE(T)         cerr << T << endl
#else
#define DWRITE(S)         do {} while(0);
#endif

#include <string>

namespace utils {
  struct ProgramOptions {
    bool isPcapFile;
    bool isInterface;
    bool isSyslogserveAddress;
    std::string   pcapFileName;
    std::string   interface;
    std::string   syslogServerAddress;
    unsigned int sendTimeIntervalSec;
  } ;

  /**
   * \brief Function offer an unified way to handle and exit program on errors
   */
  void raiseError(const std::string& message);
  void raiseError(const char *message = nullptr);

  /**
   * \brief Function is same as util_raiseError but message is called with perror function
   */
  void raisePerror(const std::string& message);
  void raisePerror(const char *message = nullptr);
}
