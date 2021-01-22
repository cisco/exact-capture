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
#include "exactio/exactio_timing.h"

#include "exact-capture.h"
#include "utils.h"

typedef struct
{
    char* destination;
    CH_VECTOR(cstr)* interfaces;
    int* exanic_port_id;
    int* exanic_dev_id;
    volatile bool* stop;
    bool dummy_istream;
    bool dummy_ostream;
    int64_t wtid; /* Writer thread id */
} writer_params_t;

typedef struct
{
    eio_stream_t* istream;
    eio_stream_t* exa_istream;
    ch_word dev_id;
    ch_word port_num;
} istream_state_t;

void* writer_thread (void* params);


#endif /* SRC_EXACT_CAPTURE_WRITER_C_ */
