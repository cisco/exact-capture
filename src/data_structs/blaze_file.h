/*
 * Copyright (c) 2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     9 January 2019
 *  Author:      Matthew P. Grosvenor
 * See LICENSE.txt for full details.
 *
 *  Created:     9 January 2019
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of the "blaze" file format for writing packets out of Exact-
 *  Capture. Blaze format borrows loosely some concepts from pcap and ERF,
 *  but is optimized around high resolution timestamping.
 */


#ifndef SRC_DATA_STRUCTS_BLAZE_FILE_H_
#define SRC_DATA_STRUCTS_BLAZE_FILE_H_

#include <stdint.h>
#include <sys/time.h>
#include "../data_structs/timespecps.h"

#define BLAZE_FILE_MAGIC         0xB1A2EF11E00FFFFFULL
#define BLAZE_FILE_VERSION_MAJOR 1
#define BLAZE_FILE_VERSION_MINOR 0

typedef struct __attribute__ ((packed)) blaze_file_hdr {
        uint64_t magic;
        uint64_t version_major :16;
        uint64_t version_minor :16;
        uint64_t linktype      :32; //see http://www.tcpdump.org/linktypes.html
} __attribute__ ((packed)) blaze_file_hdr_t;

typedef enum blaze_flags{
    BLAZE_FLAG_NONE    = 0x00, //No flags

    BLAZE_FLAG_IGNR    = 0x01, //This is a padding packet, ignore it

    BLAZE_FLAG_ABRT    = 0x02, //Frame aborted (on the wire)
    BLAZE_FLAG_CRPT    = 0x04, //Frame corrupt (CRC is wrong)
    BLAZE_FLAG_TRNC    = 0x08, //Frame truncated
    BLAZE_FLAG_SWOVFL  = 0x10, //A software overflow happened
    BLAZE_FLAG_HWOVFL  = 0x20, //A hardware overflow happened

} blaze_flags_t;


typedef struct  blaze_rec_t  {
    uint64_t caplen  :32; //Bytes of this packet captured
    uint64_t wirelen :32; //Length of packet on the wire

    //This forms a single uniq seq for every packet
    uint64_t dev     : 8; //Source device ID
    uint64_t port    : 8; //Source port ID
    uint64_t seq     : 48; //Up to ~100 days of capture at 400G....

    uint64_t flags   : 16; //See balze_flags_t
    uint64_t dropped : 48; //Dropped packets between last and this packet

    uint64_t ts; //Time since UNIX epoch (UTC) in units of "cycles" @ hz
    uint64_t _  : 16; //Reserved, could be used for higher resolution cycles values;
    uint64_t hz : 48; //Cycle speed in HZ. Speeds up to 281 THz supported.

} __attribute__((packed)) blaze_hdr_t;



#endif /* SRC_DATA_STRUCTS_BLAZE_FILE_H_ */
