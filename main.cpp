/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    main.cpp
 * \brief   TODO:
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.1018
 */
/******************************************************************************/

#include <iostream>
#include <string>
#include <sstream>
#include <memory>

#include <unistd.h>

#include "utils.hpp"
#include "pcapProcessor.hpp"

using namespace std;
using namespace utils;

/* default time interval specified in task specification */
#define DEFAULT_STATISTIC_TIME  60

/* Display program help */
void printHelp()
{
  cout << "help" << endl;
}

ProgramOptions parseOptions(int argc, char * const argv[]) {
  if (argc < 2) {
    cerr << "Program expects parameters." << endl << endl;
    printHelp();
    raiseError();
  }

  // search argument for help option
  for (int i = 0; i < argc; ++i) {
    string actArgument(argv[i]);
    if (actArgument == "--help" || actArgument == "-h") {
      printHelp();
      raiseError();
    }
  }

  ProgramOptions resultOptions = {
    false, false, false,
    "", "", "", DEFAULT_STATISTIC_TIME
  };

  int opt = 0;
  while ((opt = getopt(argc, argv, "r:i:s:t:")) != -1) {
    switch (opt) {
      case 'r': resultOptions.isPcapFile = true;           resultOptions.pcapFileName        = optarg; break;
      case 'i': resultOptions.isInterface = true;          resultOptions.interface           = optarg; break;
      case 's': resultOptions.isSyslogserveAddress = true; resultOptions.syslogServerAddress = optarg; break;
      case 't': { // brackets because long value after case label
        long value = strtol(optarg, nullptr, 10);
        if (value <= 0)
          raiseErrorStreamHelp("For paramter -t \"" << optarg << "\" is not a valid whole positive number\n");
        resultOptions.sendTimeIntervalSec = value;
      } break;
      default:
        raiseError(nullptr, true);
    }
  }

  return resultOptions;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char * const argv[]) {
  ProgramOptions progOptions = parseOptions(argc, argv);
  DWRITE(endl <<
    "Option values:" << endl <<
    "  Pcap file:             " << progOptions.pcapFileName        << endl <<
    "  Interface:             " << progOptions.interface           << endl <<
    "  Syslog server address: " << progOptions.syslogServerAddress << endl <<
    "  Send interval seconds: " << progOptions.sendTimeIntervalSec << endl
  );

  // file and interface are mutual exclusive
  if (progOptions.isPcapFile && progOptions.isInterface)
    raiseError("Parameters -r and -i are mutual exclusive.", true);

  shared_ptr<DNSStatistic> statistic = make_shared<DNSStatistic>();

  if (progOptions.isSyslogserveAddress) {
    if (!statistic->initializeSyslogServer(progOptions.syslogServerAddress))
      raiseError();
  }

  if (progOptions.isPcapFile) {
    if (!processPcapFile(progOptions, statistic))
      raiseError();

    if (progOptions.isSyslogserveAddress)
      statistic->sendToSyslog();
    else
      statistic->printStatistics();
  }
  else if (progOptions.isInterface) {
    // set signal handler on golbal flag from pcapProcessor module.
    signal(SIGUSR1, pcap_writeoutSignal);

    // start capturing
    if (!beginLiveDnsAnalysis(progOptions, statistic))
      raiseError();
  }
  return 0;
}
