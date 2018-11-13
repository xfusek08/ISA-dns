/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    DNSResponse.cpp
 * \brief
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.2018
 */
/******************************************************************************/

#include <iostream>
#include <string>
#include <sstream>
#include <map>
#include <string.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "DNSResponse.hpp"
#include "utils.hpp"

using namespace std;

#define SIZE_OF_QUESTION_FOOTER (4)
#define DNS_HEADER_SIZE (12)
#define DNS_ASWER_HEADER_SIZE (12)

// DNS Types
#define DNS_RECTYPE_A                1  // a host address
#define DNS_RECTYPE_NS               2 // an authoritative name server
#define DNS_RECTYPE_AAAA            28 // an authoritative name server
#define DNS_RECTYPE_CNAME            5 // the canonical name for an alias
#define DNS_RECTYPE_MX              15 // mail exchange
#define DNS_RECTYPE_SOA              6 // marks the start of a zone of authority
#define DNS_RECTYPE_TXT             16 // text strings
#define DNS_RECTYPE_SPF             99 // Sender Policy Framework


bool DNSResponse::parse(const unsigned char *packet) {

  answers.clear();

  if (packet == nullptr)
    return false;

  _beginOfPacket = (unsigned char *)packet;

  SDnsHeader mainHeader = parseDnsHeader(_beginOfPacket);
  if (mainHeader.ansversRRs < 1) // nothing to do if there arent any ansvers
    return true;

  if (!resolveAnswes(mainHeader.ansversRRs))
    return false; // error

  return true;
}

bool DNSResponse::resolveAnswes(unsigned short count) {
  unsigned char *actPointerToPacket = _beginOfPacket;

  // rewind ower question and resolve ansver
  actPointerToPacket += DNS_HEADER_SIZE; // jump to question
  while (*actPointerToPacket != 0) {
    ++actPointerToPacket;
  }
  actPointerToPacket += SIZE_OF_QUESTION_FOOTER + 1;

  for (int i = 0; i < count; ++i) {
    SDNSAnswerHeader ansHeader = parseDNSAnswerHeader(actPointerToPacket);
    SDNSAnswerRecord answerRec = createAnswerRecord(ansHeader, actPointerToPacket);

    answers.push_back(answerRec);
    actPointerToPacket += ansHeader.dataLen + DNS_ASWER_HEADER_SIZE;
  }
  return true;
}

SDnsHeader DNSResponse::parseDnsHeader(const unsigned char *firstCharOfHeader) {
  SDnsHeader *header = (SDnsHeader *)firstCharOfHeader;
  SDnsHeader res = {
    ntohs(header->transactionID),
    header->flags,
    ntohs(header->questions),
    ntohs(header->ansversRRs),
    ntohs(header->authorityRRs),
    ntohs(header->additionalRRs)
  };

  // debug header printout
  #ifdef DEBUG
    #ifdef HEADERS
      DWRITE("parseDnsHeader");
      for (unsigned int i = 0; i < DNS_HEADER_SIZE; ++i) {
      fprintf(stderr, "%02x ", firstCharOfHeader[i]);
      if ((i % 16) == 0 && i != 0)
        fprintf(stderr, "\n");
      }
      DPRINTF("\n"
        "transactionID: 0x%02x  \n"
        "flags:         0x%02x  \n"
        "questions:     %u    \t0x%04x\n"
        "ansversRRs:    %u    \t0x%04x\n"
        "authorityRRs:  %u    \t0x%04x\n"
        "additionalRRs: %u    \t0x%04x\n",
        res.transactionID,
        res.flags,
        res.questions, res.questions,
        res.ansversRRs, res.ansversRRs,
        res.authorityRRs, res.authorityRRs,
        res.additionalRRs, res.additionalRRs
      );
    #endif // HEADERS
  #endif // DEBUG
  return res;
}

SDNSAnswerHeader DNSResponse::parseDNSAnswerHeader(const unsigned char *firstCharOfHeader) {
  SDNSAnswerHeader *header = (SDNSAnswerHeader *)firstCharOfHeader;
  __u16 *datalen = (__u16 *)(firstCharOfHeader + 10); // in struct data are padded after __u32
  SDNSAnswerHeader res = {
    ntohs(header->domainNameOffset),
    ntohs(header->type),
    ntohs(header->recClass),
    ntohs(header->timeToLive),
    ntohs(*datalen)
  };

  res.domainNameOffset = res.domainNameOffset & 0x3fff;

  // debug answer header printout
  #ifdef DEBUG
    #ifdef HEADERS
      DWRITE("parseDNSAnswerHeader");
      for (unsigned int i = 0; i < DNS_ASWER_HEADER_SIZE; ++i) {
      fprintf(stderr, "%02x ", firstCharOfHeader[i]);
      if ((i % 16) == 0 && i != 0)
        fprintf(stderr, "\n");
      }
      DPRINTF("\n"
        "domainNameOffset:  %04u\t\t0x%04x\n"
        "type:              %04u\t\t0x%04x\n"
        "recClass:          %04u\t\t0x%04x\n"
        "timeToLive:        %04u\t\t0x%08x\n"
        "dataLen:           %04u\t\t0x%04x\n",
        res.domainNameOffset, res.domainNameOffset,
        res.type, res.type,
        res.recClass, res.recClass,
        res.timeToLive, res.timeToLive,
        res.dataLen, res.dataLen
      );
    #endif // HEADERS
  #endif // DEBUG
  return res;
}

string DNSResponse::readDomainName(const unsigned short offsetOfName) {
  unsigned short actOffset = offsetOfName;
  unsigned char actChar = 0;
  string result = "";
  DPRINTF("readDomainName on offset: %d | ", (int)offsetOfName);
  while ((actChar = _beginOfPacket[actOffset]) != 0) {
    DPRINTF("%02x ", actChar);
    // if act char has pointer prefix
    if ((actChar & 0xc0) == 0xc0) {  // mask out everything except first 11 bits as ptr prefix and if it is prt then get value
      // get whole 16b word begining with 11... and read value then mask out prefix
      __u16 namePtr = htons(*((__u16 *)(&(_beginOfPacket[actOffset])))) & 0x3fff;
      DPRINTF("[%02x] ", (int)namePtr);
      actOffset = namePtr;
    }
    // char signalizing number of octets
    else if (actChar < 64) {
      char label[64];
      ++actOffset;
      // read corresponding number of octets
      memcpy(label, _beginOfPacket + actOffset, actChar);
      actOffset += actChar;
      label[actChar] = 0;
      if (!result.empty())
        result += ".";
      result += string(label);
    }
    // we shouldn't get anything but ptr or number of next label octets
    else {
      return "error";
    }
  }
  DWRITE(""); // \n
  return result;
}

SDNSAnswerRecord DNSResponse::createAnswerRecord(SDNSAnswerHeader answerHeader, const unsigned char *actPointerToAnswer) {
  SDNSAnswerRecord resultRecord;
  resultRecord.header = answerHeader;
  resultRecord.domainName = readDomainName(answerHeader.domainNameOffset);
  resultRecord.translatedName = "???";

  switch (answerHeader.type) {
    case DNS_RECTYPE_A: {
      resultRecord.typeString = "A";
      struct in_addr *address = (struct in_addr *)(actPointerToAnswer + DNS_ASWER_HEADER_SIZE);
      resultRecord.translatedName = string(inet_ntoa(*address));
    } break;
    case DNS_RECTYPE_NS:
      resultRecord.typeString = "NS";
      break;
    case DNS_RECTYPE_AAAA:
      resultRecord.typeString = "AAAA";
      break;
    case DNS_RECTYPE_CNAME:
      resultRecord.typeString = "CNAME";
      // to next function we need to calculate offset of data from the begining of the packet
      resultRecord.translatedName  = readDomainName(actPointerToAnswer - _beginOfPacket + DNS_ASWER_HEADER_SIZE);
      break;
    case DNS_RECTYPE_MX:
      resultRecord.typeString = "MX";
      break;
    case DNS_RECTYPE_SOA:
      resultRecord.typeString = "SOA";
      break;
    case DNS_RECTYPE_TXT:
      resultRecord.typeString = "TXT";
      break;
    case DNS_RECTYPE_SPF:
      resultRecord.typeString = "SPF";
      break;
    default:
      resultRecord.typeString = STREAM_TO_STR("unknown(" << (int)answerHeader.type << ")");
  }

  return resultRecord;
}
