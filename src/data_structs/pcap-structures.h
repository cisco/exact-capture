/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     10 July 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  A local declaration of the the PCAP file format headers, to avoid pulling in
 *  all of libpcap
 */


#ifndef SRC_DATA_STRUCTS_PCAP_STRUCTURES_H_
#define SRC_DATA_STRUCTS_PCAP_STRUCTURES_H_

#include <stdint.h>
#include <sys/time.h>
#include "../data_structs/timespecps.h"

#define TCPDUMP_MAGIC      0xa1b2c3d4
#define NSEC_TCPDUMP_MAGIC 0xa1b23c4d
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define DLT_EN10MB         1

typedef struct __attribute__ ((packed)) pcap_file_header {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        uint32_t thiszone;   /* gmt to local correction */
        uint32_t sigfigs;    /* accuracy of timestamps */
        uint32_t snaplen;    /* max length saved portion of each pkt */
        uint32_t linktype;   /* data link type (LINKTYPE_*) */
} __attribute__ ((packed)) pcap_file_header_t;

typedef struct __attribute__ ((packed)) pcap_pkthdr {
        union {
            struct{
                uint32_t ts_sec;     /* time stamp */
                uint32_t ts_usec;
            } us;
            struct{
                uint32_t ts_sec;     /* time stamp */
                uint32_t ts_nsec;
            } ns;
            int64_t raw;
        } ts;

        uint32_t caplen;     /* length of portion present */
        uint32_t len;        /* length this packet (off wire) */
} __attribute__ ((packed)) pcap_pkthdr_t;

#endif /* SRC_DATA_STRUCTS_PCAP_STRUCTURES_H_ */
