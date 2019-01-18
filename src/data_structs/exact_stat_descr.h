/*
 * Copyright (c) 2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     17 January 2019
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of the exact capture statistics descriptors
 */

#ifndef SRC_DATA_STRUCTS_EXACT_STAT_DESCR_H_
#define SRC_DATA_STRUCTS_EXACT_STAT_DESCR_H_

#include <stdint.h>


typedef enum {
    EXACT_STAT_TYPE_NONE = 0,
    EXACT_STAT_TYPE_INT64,
    EXACT_STAT_TYPE_DOUBLE,
    EXACT_STAT_TYPE_STR,
} exact_stats_types_t;

typedef enum {
    EXACT_STAT_UNIT_NONE = 0,
    EXACT_STAT_UNIT_BYTES,
    EXACT_STAT_UNIT_SECONDS,
    EXACT_STAT_UNIT_DEGREES_C,
    EXACT_STAT_UNIT_PACKETS,
    EXACT_STAT_UNIT_ID,
    EXACT_STAT_UNIT_NAME,
    EXACT_STAT_UNIT_TICKS,
    EXACT_STAT_UNIT_COUNT,
} exact_stats_units_t;

typedef struct
{
    exact_stats_types_t type;
    char vname[256]; //variable name
    char hname[256]; //Human readable name
    exact_stats_units_t unit;
    int64_t radix;
} exac_stats_descr_t;


#endif /* SRC_DATA_STRUCTS_EXACT_STAT_DESCR_H_ */
