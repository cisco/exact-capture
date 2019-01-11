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

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/port.h>
#include <exanic/config.h>
#include <chaste/log/log.h>

#include "exactio_timing.h"


typedef struct  {
    const char* interface_rx;
    const char* interface_tx;
    bool promisc;
    bool kernel_bypass;
    bool clear_buff;
    int64_t snaplen; //This is not supported but should be in the future
} exa_args_t;

NEW_IOSTREAM_DECLARE(exa,exa_args_t);

/******************************************************************************/
/* Bring the below code up in to the header to make it easier for the compiler
 * to inline the functions properly.
 */


typedef struct exa_priv {
    int rx_port;
    int rx_dev_id;
    int tx_port;
    int tx_dev_id;
    char rx_dev[16];
    char tx_dev[16];

    exanic_t* tx_nic;
    exanic_t* rx_nic;
    exanic_tx_t *tx;
    exanic_rx_t *rx;

    char* rx_buffer;
    int64_t rx_len;
    uint32_t chunk_id;
    int more_rx_chunks;

    size_t max_tx_mtu;
    char* tx_buffer;
    int64_t tx_buffer_len;

    bool closed;

    uint32_t tick_hz;

    int64_t id_major;
    int64_t id_minor;

} exa_priv_t;


typedef struct nic_stats_hw
{
    uint32_t tx_count;
    uint32_t rx_count;
    uint32_t rx_ignored_count;
    uint32_t rx_error_count;
    uint32_t rx_dropped_count;
    char* name;
} nic_stats_hw_t;

#endif /* EXACTIO_EXA_H_ */
