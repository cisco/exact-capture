/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     17 Jul 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of utilities for operating with time (quickly)
 */

#ifndef SRC_EXACTIO_EXACTIO_TIMING_H_OLD_
#define SRC_EXACTIO_EXACTIO_TIMING_H_

#include "../data_structs/timespecps.h"


//Some handy time related utils
//Get the current time in timespecps format
void eio_nowns(int64_t* ts);

//Convert a timespec ps to int64 nanoseconds
//int64_t eio_tspstonsll(timespecps_t* ts);

//Convert a timespec ps to double double
//double eio_tspstonsf(timespecps_t* ts);

#endif /* SRC_EXACTIO_EXACTIO_TIMING_H_OLD_ */
