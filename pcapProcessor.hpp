
/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    pcapProcessor.hpp
 * \brief
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.1018
 */
/******************************************************************************/

#pragma once

#include <memory>

#include "utils.hpp"
#include "DNSStatistic.hpp"

bool processPcapFile(utils::ProgramOptions, std::shared_ptr<DNSStatistic>);
