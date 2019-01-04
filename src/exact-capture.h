/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     4 Aug 2017
 *  Author:      Matthew P. Grosvenor
 *  Description: Useful global definitions for the application, especially stats
 */


#ifndef SRC_EXACT_CAPTURE_H_
#define SRC_EXACT_CAPTURE_H_

#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <signal.h>
#include <exanic/exanic.h>


#define MIN_ETH_PKT (64)

/*
 * High efficiency disk writing uses O_DIRECT, but writing must be aligned and
 * sized as a multiple of the disk block size
 */
#define DISK_BLOCK (4096)

/*
 * BRINGs are used join listener and writer threads to each other. They are
 * named shared memory rings that reside in /dev/shm.
 */
#define BRING_NAME_LEN (512)
/*Must be a multiple of disk block size. 512 * 4096 = 2MB */
#define BRING_SLOT_SIZE (512 * DISK_BLOCK)
#define BRING_SLOT_COUNT (128)

/*Maximum number of input and output threads/cores*/
#define MAX_WTHREADS   (64)
#define MAX_LTHREADS   (16)
#define MAX_LWCONNS (MAX_LTHREADS * MAX_WTHREADS)

typedef struct
{
    int64_t swofl;
    int64_t hwofl;
    int64_t dropped;
    int64_t errors;
    int64_t spins1_rx;
    int64_t spinsP_rx;
    int64_t bytes_rx;
    int64_t packets_rx;

} lstats_t  __attribute__( ( aligned ( 8 ) ) );



typedef struct
{
    int64_t pcbytes; /* capture packet bytes */
    int64_t plbytes; /* wire length packet bytes */
    int64_t dbytes;  /* to disk bytes */
    int64_t packets;
    int64_t spins;

} wstats_t  __attribute__( ( aligned ( 8 ) ) );



#endif /* SRC_EXACT_CAPTURE_H_ */
