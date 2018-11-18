/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    DNSResponse.cpp
 * \brief   Module providing structure and class for parsing dns headers and answers.
 *          Implementation of DNSResponse.hpp.
 * \author  Petr Fusek (xfusek08)
 * \date    19.11.2018
 */
/******************************************************************************/

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
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

/**
 * @brief Proceeds raw data of packet payload into DNS response.
 *
 * (See DNSResponse.hpp for more info.)
 */
bool DNSResponse::parse(const unsigned char *packet) {

  answers.clear();

  if (packet == nullptr)
    return false;

  _beginOfPacket = (unsigned char *)packet;

  SDnsHeader mainHeader = parseDnsHeader(_beginOfPacket);
  // check if header is reasonable
  if ((mainHeader.flags & 0x7f) != 0) // check of reserved zeros and zero error codes
    return false;
  if ((mainHeader.flags & 0x8000) == 0) // we care only about responses
    return false;
  // rough data check: we proceeds if amount of data is reasonable and fits to 1500
  if (mainHeader.questions > 100 ||
      mainHeader.ansversRRs > 100 ||
      mainHeader.authorityRRs > 100 ||
      mainHeader.additionalRRs > 100 )
    return false;
  if (mainHeader.ansversRRs < 1) // nothing to do if there aren't any ansvers
    return false;
  if (!resolveAnswers(mainHeader.ansversRRs))
    return false; // error

  return true;
}

/**
 * @brief Parsing raw data to SDnsHeader structure
 *
 * (See DNSResponse.hpp for more info.)
 */
SDnsHeader DNSResponse::parseDnsHeader(const unsigned char *firstCharOfHeader) const {
  SDnsHeader *header = (SDnsHeader *)firstCharOfHeader;
  SDnsHeader res = {
    ntohs(header->transactionID),
    ntohs(header->flags),
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

/**
 * @brief Parsing raw data to SDnsAnswerHeader structure
 *
 * (See DNSResponse.hpp for more info.)
 */
SDnsAnswerHeader DNSResponse::parseDNSAnswerHeader(const unsigned char *firstCharOfHeader)  const {
  SDnsAnswerHeader *header = (SDnsAnswerHeader *)firstCharOfHeader;
  __u16 *datalen = (__u16 *)(firstCharOfHeader + 10); // in struct data are padded after __u32
  SDnsAnswerHeader res = {
    ntohs(header->domainNameOffset),
    ntohs(header->type),
    ntohs(header->recClass),
    ntohl(*(__u32 *)(firstCharOfHeader + 6)),
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

/**
 * @brief Resolves answer section in DNS response.
 *
 * (See DNSResponse.hpp for more info.)
 */
bool DNSResponse::resolveAnswers(unsigned short count) {
  unsigned char *actPointerToPacket = _beginOfPacket;

  // rewind throw question and resolve ansver
  actPointerToPacket += DNS_HEADER_SIZE; // jump to question
  while (*actPointerToPacket != 0) {
    ++actPointerToPacket;
  }
  actPointerToPacket += SIZE_OF_QUESTION_FOOTER + 1;

  for (int i = 0; i < count; ++i) {
    SDnsAnswerHeader ansHeader = parseDNSAnswerHeader(actPointerToPacket);
    // check if header is reasonable
    if (ansHeader.recClass != 1 || ansHeader.dataLen > 1400)
      return false;

    SDnsAnswerRecord answerRec = createAnswerRecord(ansHeader, actPointerToPacket);

    #ifndef INCLUDE_UNKNOWN
    if (answerRec.answerData != "???")
    #endif
    answers.push_back(answerRec);
    actPointerToPacket += ansHeader.dataLen + DNS_ASWER_HEADER_SIZE;
  }
  return true;
}

/**
 * @brief Resolve domain name coded inside of DNS response
 *
 * (See DNSResponse.hpp for more info.)
 */
string DNSResponse::readDomainName(const unsigned short offsetOfName, unsigned int *length) {
  unsigned short actOffset = offsetOfName;
  unsigned char actChar = 0;
  bool wasJump = false;
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
      wasJump = true;
      if (length != nullptr) {
        *length += 2;
      }
    }
    // char signalizing number of octets
    else if (actChar < 64) {
      char label[64];
      ++actOffset;
      // read corresponding number of octets
      memcpy(label, _beginOfPacket + actOffset, actChar);
      actOffset += actChar;
      if (length != nullptr && !wasJump) {
        *length += actChar + 1;
      }
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
  // we reached zero character
  if (length != nullptr && !wasJump)
    *length +=  1;
  DWRITE(""); // \n
  return result;
}

/**
 * @brief Resolves DNS answer data to DNS answer record.
 *
 * (See DNSResponse.hpp for more info.)
 */
SDnsAnswerRecord DNSResponse::createAnswerRecord(SDnsAnswerHeader answerHeader, const unsigned char *actPointerToAnswer) {
  SDnsAnswerRecord resultRecord;
  resultRecord.header = answerHeader;
  resultRecord.domainName = readDomainName(answerHeader.domainNameOffset);
  resultRecord.answerData = "???";

  unsigned short offsetToData = actPointerToAnswer - _beginOfPacket + DNS_ASWER_HEADER_SIZE;

  switch (answerHeader.type) {
    case DNS_RECTYPE_A: {
      resultRecord.typeString = "A";
      struct in_addr *address = (struct in_addr *)(actPointerToAnswer + DNS_ASWER_HEADER_SIZE);
      resultRecord.answerData = string(inet_ntoa(*address));
    } break;
    case DNS_RECTYPE_NS:
      resultRecord.typeString = "NS";
      // to next function we need to calculate offset of data from the begining of the packet
      resultRecord.answerData  = readDomainName(offsetToData);
      break;
    case DNS_RECTYPE_AAAA: {
      resultRecord.typeString = "AAAA";
      struct in6_addr *address = (struct in6_addr *)(actPointerToAnswer + DNS_ASWER_HEADER_SIZE);
      char buff[INET6_ADDRSTRLEN];
      resultRecord.answerData = string(inet_ntop(AF_INET6, address, buff, INET6_ADDRSTRLEN));
    } break;
    case DNS_RECTYPE_CNAME:
      resultRecord.typeString = "CNAME";
      resultRecord.answerData  = readDomainName(offsetToData);
      break;
    case DNS_RECTYPE_MX:
      resultRecord.typeString = "MX";
      // same as in CNAME + 2 bytes of preference
      resultRecord.answerData  = readDomainName(offsetToData + 2);
      break;
    case DNS_RECTYPE_SOA:
      resultRecord.typeString = "SOA";
      resultRecord.answerData = getSoaPayload(_beginOfPacket + offsetToData);
      break;
    case DNS_RECTYPE_TXT:
      resultRecord.typeString = "TXT";
      resultRecord.answerData = readTextData(_beginOfPacket + offsetToData, answerHeader.dataLen);
      break;
    case DNS_RECTYPE_SPF:
      resultRecord.typeString = "SPF";
      resultRecord.answerData = readTextData(_beginOfPacket + offsetToData, answerHeader.dataLen);
      break;
    case DNS_RECTYPE_RSIG:
      resultRecord.typeString = "RSIG";
      resultRecord.answerData = getRsicPayload(_beginOfPacket + offsetToData);
      break;
    case DNS_RECTYPE_DNSKEY:
      resultRecord.typeString = "DNSKEY";
      resultRecord.answerData = getDnskeyOrDSPayload(_beginOfPacket + offsetToData, answerHeader.dataLen);
      break;
    case DNS_RECTYPE_DS:
      resultRecord.typeString = "DS";
      resultRecord.answerData = getDnskeyOrDSPayload(_beginOfPacket + offsetToData, answerHeader.dataLen);
      break;
    case DNS_RECTYPE_NSEC:
      resultRecord.typeString = "NSEC";
      resultRecord.answerData  = readDomainName(offsetToData);
      break;
    default:
      resultRecord.typeString = STREAM_TO_STR("unknown(" << (int)answerHeader.type << ")");
  }

  return resultRecord;
}


/**
 * @brief Private method to parse data of DNSKEY or DS answer
 *
 * DNSKEY or DS have same structure in principle only with different naming.
 *
 * @param firstCharOfData pointer to the first char of data in answer
 * @param len             expected length of data to correctly resolve Public Key or Digest
 * @return string         data summarize as string in quotes
 */
string DNSResponse::getDnskeyOrDSPayload(const unsigned char *firstCharOfData, unsigned short len) {
  unsigned char *actDataChar = (unsigned char *)firstCharOfData;
  stringstream resStream;
  resStream << "\"";

  // DNSKEY/DS

  // flags/Key Tag   2B
  resStream << "0x" << setfill('0') << setw(4) << hex << ntohs(*((unsigned short *)(actDataChar))) << " ";
  actDataChar += sizeof(__u16);

  // protocol/Algorithm  1B
  resStream << (int)(*((char *)(actDataChar))) << " ";
  actDataChar += sizeof(char);

  // algorithm/Digest Type 1B
  resStream << (int)(*((char *)(actDataChar))) << " ";
  actDataChar += sizeof(char);

  // Public Key/Digest
  for (int i = 0; i < actDataChar - firstCharOfData + len; ++i) {
    resStream << hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(actDataChar[i]);
  }

  resStream << "\"";
  return resStream.str();
}

/**
 * @brief Private method to parse data of TXT answer
 *
 * Is used also with SPF aswers.
 *
 * @param firstCharOfData pointer to the first char of data in answer
 * @param len             expected length of data to correctly load text
 * @return string         data summarize as string in quotes
 */
string DNSResponse::readTextData(const unsigned char *firstCharOfData, unsigned short len) {
  stringstream resStream;
  resStream << "\"";
  for (unsigned short i = 0; i < len; ++i)
    resStream << firstCharOfData[i];
  resStream << "\"";
  return resStream.str();
}

/**
 * @brief Private method to parse data of SOA answer
 *
 * @param firstCharOfData pointer to the first char of data in answer
 * @return string         data summarize as string in quotes
 */
string DNSResponse::getSoaPayload(const unsigned char *firstCharOfData) {
  unsigned char *actDataChar = (unsigned char *)firstCharOfData;
  unsigned int length = 0;
  stringstream resStream;
  resStream << "\"";

  // domain of primary name server
  resStream << readDomainName(actDataChar - _beginOfPacket, &length) << " ";
  actDataChar += length;

  // domain of responsible authority mail box
  resStream << readDomainName(actDataChar - _beginOfPacket, &length) << " ";
  actDataChar += length;

  // serial number 4B
  resStream << ntohs(*((__u32 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u32);

  // REFRESH 4B
  resStream << ntohs(*((__u32 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u32);

  // RETRY 4B
  resStream << ntohs(*((__u32 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u32);

  // EXPIRE 4B
  resStream << ntohs(*((__u32 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u32);

  // MINIMUM 4B
  resStream << ntohs(*((__u32 *)(actDataChar)));
  actDataChar += sizeof(__u32);

  resStream << "\"";
  return resStream.str();
}

/**
 * @brief Private method to parse data of RSIG answer
 *
 * @param firstCharOfData pointer to the first char of data in answer
 * @return string         data summarize as string in quotes
 */
string DNSResponse::getRsicPayload(const unsigned char *firstCharOfData) {
  unsigned char *actDataChar = (unsigned char *)firstCharOfData;
  stringstream resStream;
  resStream << "\"";

  // type covered 2B
  resStream << ntohs(*((__u16 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u16);

  // alghorithm 1B
  resStream << (int)(*((char *)(actDataChar))) << " ";
  actDataChar += sizeof(char);

  // labels 1B
  resStream << (int)(*((char *)(actDataChar))) << " ";
  actDataChar += sizeof(char);

  // orig TTL 4B
  resStream << ntohs(*((__u32 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u32);

  // Signature Expiration 4B
  resStream << ntohs(*((__u32 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u32);

  // Signature Inception 4B
  resStream << ntohs(*((__u32 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u32);

  // keytag 2B
  resStream << ntohs(*((__u16 *)(actDataChar))) << " ";
  actDataChar += sizeof(__u16);

  // Signer's Name domain ...
  resStream << readDomainName(actDataChar - _beginOfPacket);

  resStream << "\"";
  return resStream.str();
}
