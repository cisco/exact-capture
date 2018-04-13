/*
 * Copyright (c) 2017, 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     17 Jul 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Implementation of utilities for operating with time (quickly)
 */




#include <time.h>
#include <math.h>

#include "exactio_timing.h"
#include "exactio.h"


//static inline uint64_t rdtscp( uint32_t *aux )
//{
//    uint64_t rax,rdx;
//    __asm__ __volatile__( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
//    return (rdx << 32) + rax;
//}

void eio_nowns(int64_t* ts)
{


    iflikely(!ts){
        return;
    }

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now );
    *ts =  now.tv_sec * 1000 * 1000 * 1000 + now.tv_nsec;

//    uint32_t aux;
//    ts->tv_sec = 0;
//    ts->tv_psec = rdtscp(&aux); // * 1000 / 3.5;
}


double eio_tspstonsf(timespecps_t* ts)
{
    if(!ts){
        return NAN;
    }


    const double secs = ts->tv_sec;
    const double psec = ts->tv_psec;

    return secs * 1000.0 * 1000.0 * 1000.0 + psec / 1000.0;
}

int64_t eio_tspstonsll(timespecps_t* ts)
{

    if(!ts){
        return ~0;
    }

    const int64_t secs = ts->tv_sec;
    const int64_t psec = ts->tv_psec;
    //return (double)psec/3.5;

    return secs * 1000 * 1000 * 1000 + psec / 1000;
}

