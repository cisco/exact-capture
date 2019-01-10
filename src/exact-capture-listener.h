/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     4 Aug 2017
 *  Author:      Matthew P. Grosvenor
 *  Description: Definition of listener threads
 */


#ifndef SRC_EXACT_CAPTURE_LISTENER_C_
#define SRC_EXACT_CAPTURE_LISTENER_C_

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



#include "exactio/exactio.h"
#include "exactio/exactio_exanic.h"
#include "exact-capture.h"
#include "exactio/exactio_timing.h"

typedef struct
{
    int64_t ltid; /* Listener thread id */
    volatile bool* stop;

    eio_stream_t* nic_istream;

    eio_stream_t** rings;
    int64_t rings_count;
    int64_t snaplen;
    listen_stats_t stats;

} lparams_t;


void* listener_thread (void* params);

#endif /* SRC_EXACT_CAPTURE_LISTENER_C_ */
