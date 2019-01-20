/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
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
#define BRING_SLOT_COUNT (256)

/*Maximum number of input and output threads/cores*/
#define MAX_WTHREADS   (64)
#define MAX_LTHREADS   (16)
#define MAX_LWCONNS (MAX_LTHREADS * MAX_WTHREADS)




#endif /* SRC_EXACT_CAPTURE_H_ */
