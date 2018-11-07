/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    pcapFileProcessor.cpp
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#include <iostream>
#include <string>

#include "utils.hpp"
#include "pcapFileProcessor.hpp"

using namespace std;
using namespace utils;

int processPcapFile(ProgramOptions options) {
  DWRITE("processPcapFile()");
  if (options.pcapFileName.empty()) {
    return PCAPFILE_RESULT_FNOTFOUND;
  }
  return PCAPFILE_RESULT_OK;
}
