/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of an ExaNIC reader/writer stream using the exactio abstract
 *  I/O interface. Some of the speed critical function a pulled into the header
 *  file to (hopefully) aid compilation optimizations.
 */


#ifndef EXACTIO_EXA_H_
#define EXACTIO_EXA_H_

#include "exactio_stream.h"


typedef struct  {
    const char* interface_rx;
    const char* interface_tx;
    bool promisc;
    bool kernel_bypass;
    bool clear_buff;
    int64_t rx_pkt_buf; //For internal buffering. 0 = no internal buffer
} exa_args_t;

NEW_IOSTREAM_DECLARE(exa,exa_args_t);


#endif /* EXACTIO_EXA_H_ */
