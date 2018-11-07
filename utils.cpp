/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    utils.cpp
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#include <iostream>
#include <string>

#include "utils.hpp"

using namespace std;

/* raiseError */
void utils::raiseError(const string& message) {
  if (message.empty())
    utils::raiseError();
  else
    utils::raiseError(message.c_str());
}

/* raiseError - override */
void utils::raiseError(const char *message) {
  if (message != nullptr)
    cerr << message << endl;
  cerr << "Use --help option to display help text for using of this program." << endl;
  exit(EXIT_FAILURE);
}

/* raisePerror */
void utils::raisePerror(const string& message) {
  if (message.empty())
    utils::raisePerror();
  else
    utils::raisePerror(message.c_str());
}

/* raisePerror - override*/
void utils::raisePerror(const char *message) {
  if (message != nullptr)
    perror(message);
  else
    perror("");
  utils::raiseError();
}
