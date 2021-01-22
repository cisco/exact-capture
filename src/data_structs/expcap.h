/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     5 Mar 2018
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Declaration of a the expcap footer structure. This structure
 *  makes it possible to include picosecond timestamps (for high resolution
 *  capture), port and device IDs (for traceability) and dropped counters and
 *  flags (for debugging). It is appended to each packet.
 */


#ifndef SRC_DATA_STRUCTS_EXPCAP_H_
#define SRC_DATA_STRUCTS_EXPCAP_H_

#include <stdint.h>

enum {
    EXPCAP_FLAG_NONE    = 0x00, //No flags
    EXPCAP_FLAG_HASCRC  = 0x01, //New CRC included
    EXPCAP_FLAG_ABRT    = 0x02, //Frame aborted
    EXPCAP_FLAG_CRPT    = 0x04, //Frame corrupt
    EXPCAP_FLAG_TRNC    = 0x08, //Frame truncated
    EXPCAP_FLAG_SWOVFL  = 0x10, //A software overflow happened
    EXPCAP_FLAG_HWOVFL  = 0x20, //A hardware overflow happened
};


typedef struct expcap_pktftr  {
    uint64_t ts_secs : 32; /* 32bit seconds = max 136 years */
    uint64_t ts_psecs :40; /* 40bit picos   = max 1.09 seconds */
    uint8_t flags;
    uint8_t dev_id;
    uint8_t port_id;
    union {
        struct{
            uint16_t dropped;
            uint16_t _reserved;
        } extra;
        uint32_t new_fcs;
    } foot;
} __attribute__((packed)) expcap_pktftr_t;


#endif /* SRC_DATA_STRUCTS_EXPCAP_H_ */
