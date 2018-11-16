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

// Suported DNS Types
#define DNS_RECTYPE_A                1 // a host address
#define DNS_RECTYPE_NS               2 // an authoritative name server
#define DNS_RECTYPE_AAAA            28 // IPv6 result
#define DNS_RECTYPE_CNAME            5 // the canonical name for an alias
#define DNS_RECTYPE_MX              15 // mail exchange
#define DNS_RECTYPE_SOA              6 // marks the start of a zone of authority
#define DNS_RECTYPE_TXT             16 // text strings
#define DNS_RECTYPE_SPF             99 // Sender Policy Framework
#define DNS_RECTYPE_RSIG            46 // resig
#define DNS_RECTYPE_DNSKEY          48 // dnskey
#define DNS_RECTYPE_DS              43 // DS
#define DNS_RECTYPE_NSEC            47 // Next Secure record

struct SDnsHeader {
  __u16 transactionID;
  __u16 flags;
  __u16 questions;
  __u16 ansversRRs;
  __u16 authorityRRs;
  __u16 additionalRRs;
};

struct SDnsAnswerHeader {
  __u16 domainNameOffset;
  __u16 type;
  __u16 recClass;
  __u32 timeToLive;
  __u16 dataLen;
};

struct SDnsAnswerRecord {
  SDnsAnswerHeader header;
  std::string domainName;
  std::string translatedName;
  std::string typeString;
};

class DNSResponse {
public:
  std::vector<SDnsAnswerRecord> answers;

  bool parse(const unsigned char *);

private:
  unsigned char *_beginOfPacket;

  bool resolveAnswes(unsigned short count);
  SDnsHeader parseDnsHeader(const unsigned char *firstCharOfHeader);
  SDnsAnswerHeader parseDNSAnswerHeader(const unsigned char *firstCharOfHeader);
  std::string readDomainName(const unsigned short offsetOfName, unsigned int *lenght = nullptr);
  SDnsAnswerRecord createAnswerRecord(SDnsAnswerHeader answerHeader, const unsigned char *actPointerToAnswer);
  std::string getRsicPayload(const unsigned char *firstCharOfData);
  std::string getSoaPayload(const unsigned char *firstCharOfData);
  std::string getDnskeyOrDSPayload(const unsigned char *firstCharOfData, unsigned short len);
  std::string readTextData(const unsigned char *firstCharOfData, unsigned short len);
};
