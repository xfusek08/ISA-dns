/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    main.cpp
 * \brief   TODO:
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#define DEFAULT_STATISTIC_TIME  60

#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>

#include "utils.hpp"
#include "pcapFileProcessor.hpp"

using namespace std;
using namespace utils;

/* Display program help */
void printHelp()
{
  cout <<
    "help\n"
    // "\nProgram \"ipk-mtrip\" - Bandwidth Measurement.\n"
    // "Mesure Bandwidth between two points in internet.\n"
    // "It can be run in two modes \"REFLECTOR\" and \"METER\".\n"
    // "\n"
    // "REFLECTOR:\n"
    // "\tipk-mtrip reflect -p port \n"
    // "\n"
    // "\t\tport\t- Port number on which reflector will listen.\n"
    // "\n"
    // "METER:\n"
    // "\tipk-mtrip meter -h far_host -p far_port - s probe_size -t mesure_time\n"
    // "\n"
    // "\t\tfar_host\t- Domain name or ip address of reflector.\n"
    // "\t\tfar_port\t- Port on which reflector is running.\n"
    // "\t\tprobe_size\t- Size of one probe packet in bytes. (0 < tprobe_size < 60000)\n"
    // "\t\tmesure_time\t- Time of measurement in seconds. (tmesure_time > 0)\n"
  ;
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
          raiseErrorStream("For paramter -t \"" << optarg << "\" is not a valid whole positive number\n");
        resultOptions.sendTimeIntervalSec = value;
      } break;
      default:
        raiseError();
    }
  }

  return resultOptions;
}

int main(int argc, char * const argv[]) {
  ProgramOptions progOptions = parseOptions(argc, argv);
  DWRITE(endl <<
    "Option values:" << endl <<
    "  Pcap file:             " << progOptions.pcapFileName        << endl <<
    "  Interface:             " << progOptions.interface           << endl <<
    "  Syslog server address: " << progOptions.syslogServerAddress << endl <<
    "  Send interval seconds: " << progOptions.sendTimeIntervalSec << endl
  );

  if (progOptions.isPcapFile) {
    switch (processPcapFile(progOptions)) {
      case PCAPFILE_RESULT_FEMPTY:          raiseError("Pcap file name is empty.");                                        break;
      case PCAPFILE_RESULT_FNOTFOUND: raiseErrorStream("Pcap file \"" << progOptions.pcapFileName << "\" was not found."); break;
      case PCAPFILE_RESULT_OK:                  DWRITE("Pcap file was successfully processed");                            break;
    }
  }

  return 0;
}
