/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of a memory mapped "blocking ring" or circular queue to join
 *  listener and writer threads using the exactio abstract IO interface.
 */

#ifndef EXACTIO_BRING_H_
#define EXACTIO_BRING_H_

#include "exactio_stream.h"

typedef struct  {
    uint64_t slot_size;
    uint64_t slot_count;
    uint64_t dontexpand;
    char* name;
    int64_t id_major;
    int64_t id_minor;
    bool use_huge_pages;
    bool use_memory_locking;
} bring_args_t;




NEW_IOSTREAM_DECLARE(bring,bring_args_t);

#endif /* EXACTIO_BRING_H_ */
