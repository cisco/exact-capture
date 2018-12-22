/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     13 July 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  A local definition of a timespec like structure for containing picosecond
 *  values
 */

#ifndef SRC_DATA_STRUCTS_TIMESPECPS_H_
#define SRC_DATA_STRUCTS_TIMESPECPS_H_

#include <stdint.h>

typedef struct timespecps {
    int64_t tv_sec;
    int64_t tv_psec;
} __attribute__((packed)) timespecps_t;


#endif /* SRC_DATA_STRUCTS_TIMESPECPS_H_ */
