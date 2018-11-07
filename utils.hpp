/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    utils.h
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#pragma once

#include <string>

namespace utils {
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
