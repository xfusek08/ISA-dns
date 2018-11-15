/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    DNSResponse.hpp
 * \brief
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.2018
 */
/******************************************************************************/

#pragma once

#include <string>
#include <vector>
#include <linux/types.h>

struct SDnsHeader {
  __u16 transactionID;
  __u16 flags;
  __u16 questions;
  __u16 ansversRRs;
  __u16 authorityRRs;
  __u16 additionalRRs;
};

struct SDNSAnswerHeader {
  __u16 domainNameOffset;
  __u16 type;
  __u16 recClass;
  __u32 timeToLive;
  __u16 dataLen;
};

struct SDNSAnswerRecord {
  SDNSAnswerHeader header;
  std::string domainName;
  std::string translatedName;
  std::string typeString;
};

class DNSResponse {
public:
  std::vector<SDNSAnswerRecord> answers;

  bool parse(const unsigned char *);

private:
  unsigned char *_beginOfPacket;

  bool resolveAnswes(unsigned short count);
  SDnsHeader parseDnsHeader(const unsigned char *firstCharOfHeader);
  SDNSAnswerHeader parseDNSAnswerHeader(const unsigned char *firstCharOfHeader);
  std::string readDomainName(const unsigned short offsetOfName, unsigned int *lenght = nullptr);
  SDNSAnswerRecord createAnswerRecord(SDNSAnswerHeader answerHeader, const unsigned char *actPointerToAnswer);
  std::string getRsicPayload(const unsigned char *firstCharOfData);
  std::string getSoaPayload(const unsigned char *firstCharOfData);
  std::string getDnskeyOrDSPayload(const unsigned char *firstCharOfData, unsigned short len);
  std::string readTextData(const unsigned char *firstCharOfData, unsigned short len);
};
