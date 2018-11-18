/******************************************************************************/
/**
 * \project ISA - Export DNS information with help of Syslog protocol
 * \file    DNSResponse.hpp
 * \brief   Module providing structure and class for parsing dns headers and answers.
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
#define DNS_RECTYPE_RSIG            46 // RSIG    - Signature for a DNSSEC-secured record set.
#define DNS_RECTYPE_DNSKEY          48 // DNSKEY  - The key record used in DNSSEC.
#define DNS_RECTYPE_DS              43 // DS      - The record used to identify the DNSSEC signing key of a delegated zone.
#define DNS_RECTYPE_NSEC            47 // NSEC    - Part of DNSSEC—used to prove a name does not exist.

/**
 * @brief Structure for parsing DNS header
 */
struct SDnsHeader {
  __u16 transactionID;
  __u16 flags;
  __u16 questions;
  __u16 ansversRRs;
  __u16 authorityRRs;
  __u16 additionalRRs;
};

/**
 * @brief Structure for parsing DNS answer header
 *
 * @note Direct cast to raw data is not safe due to data
 *       padding, actual size in memory is 16 B instead of 12B.
 *       Use parseDNSAnswerHeader method from DNSResponse class
 *       to proper parsing.
 */
struct SDnsAnswerHeader {
  __u16 domainNameOffset;
  __u16 type;
  __u16 recClass;
  __u32 timeToLive;
  __u16 dataLen;
};

/**
 * @brief Record holding proccessed information about individual DNS answers.
 */
struct SDnsAnswerRecord {
  SDnsAnswerHeader header;  /*!< Whole parsed header of this answer. */
  std::string domainName;   /*!< string holding resolved domain name. */
  std::string answerData;   /*!< string holding data derived from answer data payload */
  std::string typeString;   /*!< string holding type of answer. */
};

/**
 * @brief Class for parsing raw DNS answer data.
 */
class DNSResponse {
public:
  /**
   * @brief Vector of answers parsed from one DNS response packet.
   */
  std::vector<SDnsAnswerRecord> answers;

  /**
   * @brief Proceeds raw data of packet payload into DNS response.
   *
   * Fills answers vector with fully resolved SDnsAnswerRecords from this
   * particular dns data. Procedure checks validity of data taken from char pointer
   * on any inconsistency immediately returns false.
   *
   * @param packet  pointer to fist char of dns packet
   * @return true   on successfull parse of all answers in DNS response packet
   * @return false  on any discovered data corruption or inconsistency
   *                or packet is not DNS response
   *                or response does not carry any answers.
   */
  bool parse(const unsigned char *packet);

  /**
   * @brief Parsing raw data to SDnsHeader structure
   *
   * @note Function does not checks if data are valid or not.
   * @param firstCharOfHeader pointer to first char of data.
   * @return SDnsHeader parsed header
   */
  SDnsHeader parseDnsHeader(const unsigned char *firstCharOfHeader) const;

  /**
   * @brief Parsing raw data to SDnsAnswerHeader structure
   *
   * @note Function does not checks if data are valid or not.
   * @param firstCharOfHeader pointer to first char of data.
   * @return SDnsAnswerHeader parsed header
   */
  SDnsAnswerHeader parseDNSAnswerHeader(const unsigned char *firstCharOfHeader) const;

  /**
   * @brief Resolves answer section in DNS response.
   *
   * Each resolved answer is added to ansvers vector.
   * Using private field to get packet data.
   *
   * @param count   expected numebr of answers
   * @return true   on success
   * @return false  on failure
  */
  bool resolveAnswers(unsigned short count);

  /**
   * @brief Resolves domain name coded inside of DNS response
   *
   * It counts with pointers and as result is returned complete
   * string of gained domain name.
   *
   * @param offsetOfName  offset from beginign og the response data
   * @param length        pointer to unsigned integer which will be filled with
   *                      actual length of data after offsetOfName including width
   *                      of pointer but not counting data resolved behind pointer.
   * @return string       Composed string of full resolved domain name.
   */
  std::string readDomainName(const unsigned short offsetOfName, unsigned int *lenght = nullptr);

  /**
   * @brief Resolves DNS answer data to DNS answer record.
   *
   * Takes in resolved answer header and based on answer DNS record type.
   * Resolves data to which asked domain translates to.
   * Also get string representation of DNS record type.
   *
   * @param answerHeader        resolved dns ansver header structure
   * @param actPointerToAnswer  pointer to beginign af actual answer
   * @return SDnsAnswerRecord   fully resolved answer record
   * If type is unknown or fails to be resolved, it will translated to unknown(<number of unknown type>)
   * If data fails to be resolved "???" string is filled.
   */
  SDnsAnswerRecord createAnswerRecord(SDnsAnswerHeader answerHeader, const unsigned char *actPointerToAnswer);

private: /* private implementation is documented in *.cpp file */
  unsigned char *_beginOfPacket;
  std::string getDnskeyOrDSPayload(const unsigned char *firstCharOfData, unsigned short len);
  std::string readTextData(const unsigned char *firstCharOfData, unsigned short len);
  std::string getSoaPayload(const unsigned char *firstCharOfData);
  std::string getRsicPayload(const unsigned char *firstCharOfData);
};
