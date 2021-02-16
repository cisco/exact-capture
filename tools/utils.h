/*
 * Copyright (c) 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     6 Apr. 2018
 *  Author:      Matthew P. Grosvenor
 *  Description: Application wide useful utility functions and macros
 */


#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include <stdint.h>
#include <chaste/utils/util.h>
#include "data_structs/timespecps.h"

int64_t time_now_ns();

#define NS_IN_SECS (1000LL*1000*1000)
#define PS_IN_SECS (1000LL*1000*1000*1000)
timespecps_t sub_tsps_tsps(const timespecps_t* lhs, const timespecps_t* rhs);
timespecps_t add_tsps_tsps(const timespecps_t* lhs, const timespecps_t* rhs);
timespecps_t sub_tsps_ps(const timespecps_t* lhs, const int64_t ps);
timespecps_t add_tsps_ps(const timespecps_t* lhs, const int64_t ps);
double tsps_to_double_ns(const timespecps_t* lhs);

#endif /* SRC_UTILS_H_ */
