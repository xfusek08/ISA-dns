/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    utils.cpp
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.1018
 */
/******************************************************************************/

#include <iostream>
#include <string>

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
    cerr << "Use --help option to display help text for using of this program." << endl;
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
