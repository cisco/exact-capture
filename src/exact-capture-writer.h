/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     4 Aug 2017
 *  Author:      Matthew P. Grosvenor
 *  Description: Definition of writer threads
 */


#ifndef SRC_EXACT_CAPTURE_WRITER_C_
#define SRC_EXACT_CAPTURE_WRITER_C_

#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <sys/mman.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/timing/timestamp.h>

#include "data_structs/pthread_vec.h"
#include "data_structs/eiostream_vec.h"
#include "data_structs/pcap-structures.h"

#include "exactio/exactio.h"
#include "exactio/exactio_exanic.h"
#include "exact-capture.h"
#include "exactio/exactio_timing.h"
#include "utils.h"


/*
 * Wrap up istreams for the writer thread. The writer cares which listener NIC
 * packets came from so that it can do timestamp conversion
 */
typedef struct
{
    eio_stream_t* ring_istream;
    eio_stream_t* nic_istream;
} ring_istream_t;





typedef struct
{
    int64_t wtid; /* Writer thread id */
    eio_stream_t* disk_ostream;
    ring_istream_t* rings;
    int64_t rings_count;
    volatile bool* stop;
} writer_params_t;



void* writer_thread (void* params);


#endif /* SRC_EXACT_CAPTURE_WRITER_C_ */
