/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    utils.cpp
 * \brief   Liblary providing supportive function for project
 *          implementation of utils.hpp
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.1018
 */
/******************************************************************************/

#include <iostream>
#include <string>
#include <arpa/inet.h>
#include <sys/time.h>
#include <math.h>

#include "utils.hpp"

using namespace std;

/* raiseError */
void utils::raiseError(const string& message, const bool checkHelp) {
  if (message.empty())
    utils::raiseError(nullptr, checkHelp);
  else
    utils::raiseError(message.c_str(), checkHelp);
}

/* raiseError - override */
void utils::raiseError(const char *message, const bool checkHelp) {
  if (message != nullptr)
    cerr << message << endl;
  if (checkHelp)
    cerr << "Use --help option to get help how to use this program." << endl;
  exit(EXIT_FAILURE);
}

/* raisePerror */
void utils::raisePerror(const string& message, const bool checkHelp) {
  if (message.empty())
    utils::raisePerror(nullptr, checkHelp);
  else
    utils::raisePerror(message.c_str(), checkHelp);
}

/* raisePerror - override*/
void utils::raisePerror(const char *message, const bool checkHelp) {
  if (message != nullptr)
    perror(message);
  else
    perror("");
  utils::raiseError(nullptr, checkHelp);
}

/**
 * @brief Translates sockaddr to readable string representation.
 *
 * Code ispired by code at: https://gist.github.com/jkomyno/45bee6e79451453c7bbdc22d033a282e
 * (see utils.hpp for more info.)
 */
string utils::addrinfo_getAddrString(const struct sockaddr *addrinfo) {
  string res = "";
  unsigned int maxLen = INET6_ADDRSTRLEN + 1;
  char buff[maxLen];
  switch(addrinfo->sa_family) {
   case AF_INET:
      inet_ntop(AF_INET,
        &(((struct sockaddr_in *)addrinfo)->sin_addr),
        buff, maxLen);
        res = string(buff);
      break;
    case AF_INET6:
      inet_ntop(AF_INET6,
        &(((struct sockaddr_in6 *)addrinfo)->sin6_addr),
        buff, maxLen);
        res = string(buff);
      break;
    default:
      break;
  }
  return res;
}

/**
 * @brief Get the Act Time Stamp String object
 *
 * Code ispired by example at https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811
 * (see utils.hpp for more info.)
 */
string utils::getActTimeStampString() {
  int millisec;
  struct tm* timeInfo;
  struct timeval tv;
  char buffer1 [50];
  char buffer2 [50];

  gettimeofday(&tv, NULL);

  millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec
  if (millisec>=1000) { // Allow for rounding up to nearest second
    millisec -=1000;
    tv.tv_sec++;
  }
  timeInfo = localtime(&tv.tv_sec);

  /* 2018-09-20T22:14:15.003Z */
  strftime(buffer1, 50, "%Y-%m-%dT%H:%M:%S", timeInfo);
  sprintf(buffer2, "%s.%03dZ", buffer1, millisec);

  return string(buffer2);
}
