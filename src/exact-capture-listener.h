/*
 * Copyright (c) 2017,2018 All rights reserved.
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

#include "data_structs/pthread_vec.h"
#include "data_structs/eiostream_vec.h"
#include "data_structs/pcap-structures.h"

#include "exactio/exactio.h"
#include "exactio/exactio_exanic.h"
#include "exactio/exactio_timing.h"

#include "exact-capture.h"

typedef struct
{
    char* interface;
    CH_VECTOR(cstr)* dests;
    volatile bool* stop;
    bool dummy_istream;
    bool dummy_ostream;
    int64_t ltid; /* Listener thread id */

    exanic_t* nic;
    int exanic_port;
    int exanic_dev_num;
    char exanic_dev[16];

    bool kernel_bypass;
    bool promisc;
    bool clear_buff;

} listener_params_t;

void* listener_thread (void* params);

#endif /* SRC_EXACT_CAPTURE_LISTENER_C_ */
