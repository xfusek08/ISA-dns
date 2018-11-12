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
  void raiseError(const std::string& message, const bool checkHelp = false);
  void raiseError(const char *message = nullptr, const bool checkHelp = false);

  /**
   * \brief Function is same as util_raiseError but message is called with perror function
   */
  void raisePerror(const std::string& message, const bool checkHelp = false);
  void raisePerror(const char *message = nullptr, const bool checkHelp = false);
}
