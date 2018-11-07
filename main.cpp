/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    main.cpp
 * \brief   TODO:
 * \author  Petr Fusek (xfusek08)
 * \date    09.11.2018
 */
/******************************************************************************/

#include <iostream>
#include "utils.hpp"

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

void parseOptions(int argc, char * const argv[]) {
  if (argc < 2) {
    cerr << "Program expects parameters.\n";
    printHelp();
    raiseError();
  }
  (void)argc;
  (void)argv;
  //   // process loop from getopt manual page
  // int opt = 0;
  // while ((opt = getopt(argc - 1, &(argv[1]), "h:p:s:t:")) != -1)
  // {
  //   switch (opt)
  //   {
  //     case 'h':
  //       glbop_hostAddrStr = optarg;
  //       break;
  //     case 'p':
  //       if (!util_strToPort(optarg, &glbop_portNum, true))
  //         util_raiseError(NULL);
  //       break;
  //     case 's':
  //       if (!util_strToULong(optarg, &glbop_probeSize))
  //         util_raiseError("Not valid probe size value");
  //       break;
  //     case 't':
  //       if (!util_strToULong(optarg, &glbop_uMeasureTime))
  //         util_raiseError("Not valid measurement time value");
  //       break;
  //     default: // error mesages of unknown options handles getopt function
  //       exit(EXIT_FAILURE);
  //   }
  // }
  // if (glbop_portNum == 0)
  //   util_raiseError("Unspecified port.");
  // if (glbop_probeSize == 0)
  //   util_raiseError("Unspecified probe size.");
  // if (glbop_uMeasureTime == 0)
  //   util_raiseError("Unspecified measurement time.");
}

int main(int argc, char * const argv[]) {
  parseOptions(argc, argv);
  return 0;
}
