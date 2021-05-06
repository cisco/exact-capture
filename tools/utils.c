/*
 * Copyright (c) 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     6 Apr. 2018
 *  Author:      Matthew P. Grosvenor
 *  Description: Application wide useful utility functions
 */



#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "utils.h"

int64_t time_now_ns()
{
    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec * 1000ULL * 1000 * 1000 + now.tv_nsec;
}

timespecps_t sub_tsps_tsps(const timespecps_t* lhs, const timespecps_t* rhs)
{
    timespecps_t result = {0};
    result.tv_psec = lhs->tv_psec - rhs->tv_psec;
    result.tv_sec  = lhs->tv_sec  - rhs->tv_sec;

    if(result.tv_psec < 0){
        result.tv_psec = PS_IN_SECS + result.tv_psec;
        result.tv_sec -= 1;
    }

    return result;
}

timespecps_t add_tsps_tsps(const timespecps_t* lhs, const timespecps_t* rhs)
{
    timespecps_t result = {0};
    int64_t carry_secs  = 0;
    result.tv_psec = lhs->tv_psec + rhs->tv_psec;

    if(result.tv_psec > PS_IN_SECS){
        carry_secs++;
        result.tv_psec -= PS_IN_SECS;
    }

    result.tv_sec  = lhs->tv_sec  + rhs->tv_sec  + carry_secs;

    return result;
}

timespecps_t sub_tsps_ps(const timespecps_t* lhs, const int64_t ps)
{
    timespecps_t rhs = {.tv_sec = 0, .tv_psec = ps};
    return sub_tsps_tsps(lhs, &rhs);
}


timespecps_t add_tsps_ps(const timespecps_t* lhs, const int64_t ps)
{
    timespecps_t rhs = {.tv_sec = 0, .tv_psec = ps};
    return add_tsps_tsps(lhs, &rhs);
}


double tsps_to_double_ns(const timespecps_t* lhs)
{ 
    return (double)(lhs->tv_psec/1000.0) + (double)lhs->tv_sec*PS_IN_SECS/1000.0;
}
