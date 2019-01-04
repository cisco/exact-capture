/*
 * Copyright (c) 2017, 2018 All rights reserved.
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
} exa_priv_t;


//eio_error_t exa_read_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts );
//eio_error_t exa_read_release(eio_stream_t* this, int64_t* ts);

//Read operations
static inline eio_error_t exa_read_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts )
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(priv->closed){
        return EIO_ECLOSED;
    }

    ifassert((ssize_t)priv->rx_buffer){
        return EIO_ERELEASE;
    }

    struct rx_chunk_info info = {.frame_status =0};
    priv->rx_len = exanic_receive_chunk_inplace_ex(
            priv->rx,&priv->rx_buffer,&priv->chunk_id,&priv->more_rx_chunks,
            &info);

    ssize_t frame_error = -(info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);
    ifunlikely(priv->rx_len < 0){
        frame_error = -EXANIC_RX_FRAME_SWOVFL;
    }

    ifunlikely(frame_error){
        switch(frame_error){
            //These are unrecoverable errors, so exit now.
            //Translate between ExaNIC error codes and EIO codes
            case -EXANIC_RX_FRAME_SWOVFL:  return EIO_ESWOVFL;
            case -EXANIC_RX_FRAME_HWOVFL:  return EIO_EHWOVFL;
        }
    }

    //This is a very likely path, but we want to optimise the data path
    ifunlikely(priv->rx_len == 0){
        return EIO_ETRYAGAIN;
    }

    //The user doesn't want this chunk, and therefore the whole frame, skip it
    ifunlikely(buffer == NULL || len == NULL){
        iflikely(priv->more_rx_chunks){
            int err = exanic_receive_abort(priv->rx);
            ifunlikely( err == -EXANIC_RX_FRAME_SWOVFL){
                return EIO_ESWOVFL;
            }
        }
        return EIO_ENONE;
    }


    iflikely((ssize_t)ts){
        const exanic_cycles32_t ts32 = exanic_receive_chunk_timestamp(priv->rx, priv->chunk_id);
        const exanic_cycles_t ts64 = exanic_expand_timestamp(priv->rx_nic,ts32);
//        struct exanic_timespecps tsps;
//        exanic_cycles_to_timespecps(priv->rx_nic, ts64, &tsps);
        //These two timespecps structures look the same but come from different
        //names-spaces. Making the copy explicit here just to be safe
        //ts->tv_sec  = tsps.tv_sec;
        *ts = ts64; //tsps.tv_psec;
    }

    //All good! Successful "read"!
    *buffer = priv->rx_buffer;
    *len    = priv->rx_len;

    switch(frame_error){
        case -EXANIC_RX_FRAME_CORRUPT: return EIO_EFRAG_CPT;
        case -EXANIC_RX_FRAME_ABORTED: return EIO_EFRAG_ABT;
        default:
            iflikely(priv->more_rx_chunks) return EIO_EFRAG_MOR;
           return EIO_ENONE;
    }
}

//Convert an exanic timestamp into cycles
static inline eio_error_t exa_rxcycles_to_timespec(eio_stream_t* this, exanic_cycles_t cycles, struct timespec* ts )
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    iflikely(ts){
        exanic_cycles_to_timespec(priv->rx_nic, cycles, ts);
    }

    return EIO_ENONE;
}

static inline eio_error_t exa_rxcycles_to_timespecps(eio_stream_t* this, exanic_cycles_t cycles, struct exanic_timespecps* ts )
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    iflikely(ts){
        exanic_cycles_to_timespecps(priv->rx_nic, cycles, ts);
    }

    return EIO_ENONE;
}




static inline eio_error_t exa_read_release(eio_stream_t* this, int64_t* ts)
{
    eio_error_t result = EIO_ENONE;
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);


    ifassert(!priv->rx_buffer){
        return EIO_ERELEASE;
    }

    ifunlikely(exanic_receive_chunk_recheck(priv->rx, priv->chunk_id) == 0){
        result = EIO_ESWOVFL;
    }

    priv->rx_buffer = NULL;
    (void)ts;
    //eio_nowns(ts);

    //Nothing to do here;
    return result;
}

static inline eio_error_t exa_read_sw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;
	return EIO_ENOTIMPL;
}

static inline eio_error_t exa_read_hw_stats(eio_stream_t* this, void* stats)
{
	exanic_port_stats_t* port_stats = (exanic_port_stats_t*)stats;
	exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

	ch_log_debug1("Getting port stats on nic %s port %i\n", this->name, priv->rx_port);
	int err = exanic_get_port_stats(priv->rx_nic,
			priv->rx_port,
			port_stats);

	return err;
}


#endif /* EXACTIO_EXA_H_ */
