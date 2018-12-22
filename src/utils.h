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

#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htonll(x) __bswap_64(x)
#  define ntohll(x) __bswap_64(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#  define htonll(x) (x)
#  define ntohll(x) (x)
#else
#  error Unknown byte order
#endif


#define PKT(hdr) ((char*)(hdr+1))
#define PKT_OFF(hdr, off) (PKT(hdr) + off)

int64_t time_now_ns();

void init_dummy_data(char* dummy_data, int len);

void print_flags(uint8_t flags);

int parse_device (const char* interface,
                  char device[16], int* dev_number, int *port_number);


int max_digitsf (double a, double b, double c, double d, double e, double f,
                 double g, double h,  double i, double j);
int max_digitsll (int64_t a, int64_t b, int64_t c, int64_t d, int64_t e,
                  int64_t f, int64_t g, int64_t h, int64_t i, int64_t j);



#define PS_IN_SECS (1000LL*1000*1000*1000)
timespecps_t sub_tsps_tsps(timespecps_t* lhs, timespecps_t* rhs);
timespecps_t add_tsps_tsps(timespecps_t* lhs, timespecps_t* rhs);
timespecps_t sub_tsps_ps(timespecps_t* lhs, int64_t ps);
timespecps_t add_tsps_ps(timespecps_t* lhs, int64_t ps);
double tsps_to_double_ns(timespecps_t* lhs);

#endif /* SRC_UTILS_H_ */
