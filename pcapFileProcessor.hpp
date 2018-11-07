
/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    utils.hpp
 * \brief   Liblary providing supportive function for project
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#pragma once

#include "utils.hpp"

#define PCAPFILE_RESULT_OK        0
#define PCAPFILE_RESULT_FNOTFOUND 1
#define PCAPFILE_RESULT_FEMPTY    2

int processPcapFile(utils::ProgramOptions);
