/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Implementation of an ExaNIC reader/writer stream using the exactio abstract
 *  I/O interface.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>
#include <chaste/log/log.h>
#include <immintrin.h>
#include <emmintrin.h>


#include <linux/ethtool.h>
#ifndef ETHTOOL_GET_TS_INFO
#include "ethtool_ts_info.h"
#endif

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/port.h>
#include <exanic/config.h>
#include <chaste/log/log.h>

#include "exactio_timing.h"
#include <data_structs/exact_stat_hdr.h>


#include "exactio_exanic.h"

#include "../utils.h"


typedef struct nic_stats_hw
{
    char* device;
    int64_t tx_count;
    int64_t rx_count;
    int64_t rx_ignored_count;
    int64_t rx_error_count;
    int64_t rx_dropped_count;
} __attribute__((packed)) __attribute__((aligned(8))) nic_stats_hw_t;

static exact_stats_hdr_t exanic_stats_hw_hdr[7] =
{
    {EXACT_STAT_TYPE_STR,   "exanic_hw_device",            "ExaNIC HW device",           EXACT_STAT_UNIT_NAME,    0},
    {EXACT_STAT_TYPE_INT64, "exanic_hw_tx_count",          "ExaNIC HW tx count",         EXACT_STAT_UNIT_PACKETS, 1},
    {EXACT_STAT_TYPE_INT64, "exanic_hw_rx_count",          "ExaNIC HW rx count",         EXACT_STAT_UNIT_PACKETS, 1},
    {EXACT_STAT_TYPE_INT64, "exanic_hw_rx_ignored_count",  "ExaNIC HW rx ignored count", EXACT_STAT_UNIT_PACKETS, 1},
    {EXACT_STAT_TYPE_INT64, "exanic_hw_rx_error_count",    "ExaNIC HW rx error count",   EXACT_STAT_UNIT_PACKETS, 1},
    {EXACT_STAT_TYPE_INT64, "exanic_hw_rx_dropped_count",  "ExaNIC HW rx dropped count", EXACT_STAT_UNIT_PACKETS, 1},
    {0,0,0,0},
};

typedef struct nic_stats_sw_rx
{
    int64_t spins_first;
    int64_t spins_more;
    int64_t packets_rx;
    int64_t bytes_rx;
    int64_t dropped;
    int64_t aborted;
    int64_t corrupted;
    int64_t truncated;
    int64_t swofl;
    int64_t hwofl;
} __attribute__((packed)) __attribute__((aligned(8))) nic_stats_sw_rx_t;

static exact_stats_hdr_t exanic_stats_sw_rx_hdr[11] =
{
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_spins_first",  "ExaNIC SW first chunk spin count",       EXACT_STAT_UNIT_COUNT,    1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_spins_more",   "ExaNIC SW remaining chunks spin count",  EXACT_STAT_UNIT_COUNT,    1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_packets_rx",   "EXANIC SW rx frames",                    EXACT_STAT_UNIT_PACKETS,  1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_bytes_rx",     "EXANIC SW rx bytes",                     EXACT_STAT_UNIT_BYTES,    1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_dropped",      "EXANIC SW rx dropped frames ",           EXACT_STAT_UNIT_PACKETS,  1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_aborted",      "EXANIC SW rx aborted frames ",           EXACT_STAT_UNIT_PACKETS,  1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_corrupted",    "EXANIC SW rx corrupted frames",          EXACT_STAT_UNIT_PACKETS,  1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_truncated",    "EXANIC SW rx truncated frames",          EXACT_STAT_UNIT_PACKETS,  1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_swofl",        "EXANIC SW rx software overflows",        EXACT_STAT_UNIT_COUNT,    1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_hwofl",        "EXANIC SW rx hardware overflows",        EXACT_STAT_UNIT_COUNT,    1},
    {0,0,0,0},
};


typedef struct nic_stats_sw_tx
{
    int64_t packets_tx;
    int64_t bytes_tx;
} __attribute__((packed)) __attribute__((aligned(8))) nic_stats_sw_tx_t;

static exact_stats_hdr_t exanic_stats_sw_tx_hdr[3] =
{
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_packets_rt",   "EXANIC SW tx frames", EXACT_STAT_UNIT_PACKETS, 1},
    {EXACT_STAT_TYPE_INT64, "exanic_sw_rx_bytes_tx",     "EXANIC SW tx bytes",  EXACT_STAT_UNIT_BYTES,   1},
    {0,0,0,0},
};


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

    bool rx_in_progress;
    char* rx_chunk_ptr;
    int64_t rx_chunk_len;
    uint32_t rx_chunk_id;
    int more_rx_chunks;

    char* rx_pkt_buf;
    int64_t rx_pkt_buf_len;

    size_t max_tx_mtu;
    char* tx_buffer;
    int64_t tx_buffer_len;

    bool closed;

    uint32_t tick_hz;

    int64_t id_major;
    int64_t id_minor;

    nic_stats_hw_t stats_hw;
    nic_stats_sw_rx_t stats_sw_rx;
    nic_stats_sw_rx_t stats_sw_tx;

    //volatile bool* stop; //Tell spinning to stop

} exa_priv_t;

static void exa_destroy(eio_stream_t* this)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return;
    }

    if(priv->rx){
        exanic_release_rx_buffer(priv->rx);
    }

    if(priv->tx){
        exanic_release_tx_buffer(priv->tx);
    }

    if(priv->rx_nic){
        exanic_release_handle(priv->rx_nic);
    }

    if(priv->tx_nic){
        exanic_release_handle(priv->tx_nic);
    }

    if(this->name)
    {
        free(this->name);
        this->name = NULL;
    }

    priv->closed = true;

}




///* Copy a packet fragment from ibuff to obuff. Return the number of bytes copied*/
//static inline int64_t cpy_frag(blaze_hdr_t* hdr, char* const obuff,
//                               char* ibuff, int64_t ibuff_len, int64_t snaplen)
//{
//    int64_t added = 0;
//    /* Only copy as much as the caplen */
//    iflikely(hdr->wirelen < snaplen)
//    {
//        /*
//         * Get the data out of the fragment, but don't copy more
//         * than max_caplen
//         */
//        const int64_t copy_bytes = MIN(snaplen - hdr->wirelen, ibuff_len);
//        memcpy (obuff, ibuff, copy_bytes);
//
//        /* Do accounting and stats */
//        hdr->caplen += copy_bytes;
//        added = copy_bytes;
//    }
//
//    hdr->wirelen     += ibuff_len;
//    stats->bytes_rx += ibuff_len;
//
//    return added;
//}
//
//
///* This func tries to rx one packet and returns the number of bytes RX'd.
// * The return may be zero if no packet was RX'd, or if there was an error */
//static inline int64_t rx_packet ( eio_stream_t* istream,  char* const obuff,
//        char* obuff_end, int64_t* dropped, int64_t* packet_seq,
//        volatile bool* stop, int64_t snaplen )
//{
//#ifndef NOIFASSERT
//    i64 rx_frags = 0;
//#endif
//
//    /* Set up a new pcap header */
//    int64_t rx_b = 0;
//
//    blaze_hdr_t* hdr = (blaze_hdr_t*) (obuff);
//    rx_b += sizeof(blaze_file_hdr_t);
//    ifassert(obuff + rx_b >= obuff_end)
//        ch_log_fatal("Obuff %p + %li = %p will exceeded max %p\n", obuff, rx_b,
//                     obuff + rx_b, obuff_end);
//
//    /* Reset just the things that need to be incremented in the header */
//    hdr->caplen  = 0;
//    hdr->wirelen = 0;
//
//    /* Try to RX the first fragment */
//    eio_error_t err = EIO_ENONE;
//    char* ibuff;
//    int64_t ibuff_len;
//    int64_t rx_time = 0;
//    int64_t rx_time_hz = 0;
//    for (int64_t tryagains = 0; ; priv->statspins1_rx++, tryagains++)
//    {
//        err = eio_rd_acq (istream, &ibuff, &ibuff_len, &rx_time, &rx_time_hz);
//
//        iflikely(err != EIO_ETRYAGAIN)
//        {
//            hdr->ts = rx_time;
//            hdr->hz = rx_time_hz;
//            break;
//        }
//
//        /* Make sure we don't wait forever */
//        ifunlikely(*stop || tryagains >= (1024 * 1024))
//        {
//            return 0;
//        }
//
//    }
//
//    /* Note, no use of lstop: don't stop in the middle of RX'ing a packet */
//    for (;; err = eio_rd_acq (istream, &ibuff, &ibuff_len, NULL, NULL),
//            stats->spinsP_rx++)
//    {
//#ifndef NOIFASSERT
//        rx_frags++;
//#endif
//        switch(err)
//        {
//            case EIO_ETRYAGAIN:
//                /* Most of the time will be spent here (hopefully..) */
//                continue;
//
//            /* Got a fragment. There are some more fragments to come */
//            case EIO_EFRAG_MOR:
//                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
//                break;
//
//            /* Got a complete frame. There are no more fragments */
//            case EIO_ENONE:
//                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
//                complete_packet(hdr, BLAZE_FLAG_NONE, dropped, dev_id, port_id,
//                                *packet_seq);
//                break;
//
//            /* Got a corrupt (CRC) frame. There are no more fragments */
//            case EIO_EFRAG_CPT:
//                stats->errors++;
//                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
//                complete_packet(hdr, BLAZE_FLAG_CRPT,dropped, dev_id, port_id,
//                                *packet_seq);
//                break;
//
//            /* Got an aborted frame. There are no more fragments */
//            case EIO_EFRAG_ABT:
//                stats->errors++;
//                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
//                complete_packet(hdr, BLAZE_FLAG_ABRT,dropped, dev_id,  port_id,
//                                *packet_seq);
//                break;
//
//            /* **** UNRECOVERABLE ERRORS BELOW THIS LINE **** */
//            /* Software overflow happened, we're dead. Exit the function */
//            case EIO_ESWOVFL:
//                stats->swofl++;
//                /* Forget what we were doing, just exit */
//                eio_rd_rel(istream);
//
//                /*Skip to a good place in the receive buffer*/
//                err = eio_rd_acq(istream, NULL, NULL, NULL, NULL);
//                eio_rd_rel(istream);
//                return 0;
//
//            /* Hardware overflow happened, we're dead. Exit the function */
//            case EIO_EHWOVFL:
//                stats->hwofl++;
//                /* Forget what we were doing, just exit */
//                eio_rd_rel(istream);
//
//                /*Skip to a good place in the receive buffer*/
//                err = eio_rd_acq(istream, NULL, NULL, NULL, NULL);
//                eio_rd_rel(istream);
//                return 0;
//
//            default:
//                ch_log_fatal("Unexpected error code %i\n", err);
//        }
//
//        /* When we get here, we have fragment(s), so we need to release the read
//         * pointer, but this may fail. In which case we drop everything */
//        if(eio_rd_rel(istream)){
//            return 0;
//        }
//
//#ifndef NOIFASSERT
//        ifassert(obuff + rx_b >= obuff_end)
//            ch_log_fatal("Obuff %p + %li = %p exceeds max %p\n",
//                     obuff, rx_b, obuff + rx_b, obuff_end);
//#endif
//
//
//        /* If there are no more frags to come, then we're done! */
//        if(err != EIO_EFRAG_MOR){
//            stats->packets_rx++;
//            (*packet_seq) += 1;
//            return rx_b;
//        }
//
//        /* There are more frags, go again!*/
//    }
//
//    /* Unreachable */
//    ch_log_fatal("Error: Reached unreachable code!\n");
//    return -1;
//}

/**
 * Fast memory copy for 120B fragments. Unroll the loop into:
 * - 3x 32B (AVX256) operations,
 * - 2x 16B (MME)    operations,
 * - 1x 8B operation.
 * Assumes that the src is aliged to a 32B boundary (which it will be)
 */
//static inline void memcpy120(void *dst, const void *src) {
//    const __m256i* src0q = ((const __m256i*)src)   + 0;
//    const __m256i* src1q = ((const __m256i*)src)   + 1;
//    const __m256i* src2q = ((const __m256i*)src)   + 2;
//    const __m256i* src3q = ((const __m256i*)src)   + 3;
//    const __m128i* src0d = ((const __m128i*)src3q) + 0;
//    const __m128i* src1d = ((const __m128i*)src3q) + 1;
//    const int64_t* src0s = ((const int64_t*)src1d) + 0;
//
//    __m256i* const dst0q = (( __m256i*)dst)   + 0;
//    __m256i* const dst1q = (( __m256i*)dst)   + 1;
//    __m256i* const dst2q = (( __m256i*)dst)   + 2;
//    __m256i* const dst3q = (( __m256i*)dst)   + 3;
//    __m128i* const dst0d = (( __m128i*)dst3q) + 0;
//    __m128i* const dst1d = (( __m128i*)dst3q) + 1;
//    int64_t* const dst0s = (( int64_t*)dst1d) + 0;
//
//    __m256i m0 = _mm256_load_si256(src0q);
//    __m256i m1 = _mm256_load_si256(src1q);
//    __m256i m2 = _mm256_load_si256(src2q);
//
//    __m128i m3 = _mm_load_si128(src0d);
//    __m128i m4 = _mm_load_si128(src1d);
//
//    _mm256_storeu_si256(dst0q, m0);
//    _mm256_storeu_si256(dst1q, m1);
//    _mm256_storeu_si256(dst2q, m2);
//
//    _mm_storeu_si128(dst0d, m3);
//    _mm_storeu_si128(dst1d, m4);
//
//    *dst0s = *src0s;
//}


static inline int get_next_chunk(exa_priv_t* priv, int64_t* ts,
                                            int64_t* ts_hz)
{
    struct rx_chunk_info info = {.frame_status = 0};
    priv->rx_chunk_len = exanic_receive_chunk_inplace_ex(
                priv->rx,&priv->rx_chunk_ptr,&priv->rx_chunk_id,
                &priv->more_rx_chunks, &info);

    iflikely(priv->rx_chunk_len == 0){
        //This is a bit naughty, but EIO_ERRORS are positive and EXANIC errors
        //are negative, so it should be ok.
        return EIO_ETRYAGAIN;
    }

    ifunlikely(priv->rx_chunk_len < 0){
        return -EXANIC_RX_FRAME_SWOVFL;
    }

    const ssize_t frame_error = -(info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);
    ifunlikely(frame_error == -EXANIC_RX_FRAME_SWOVFL){
        return frame_error;
    }

    ifunlikely((ssize_t)ts){
        const exanic_cycles32_t ts32 = exanic_receive_chunk_timestamp(priv->rx, priv->rx_chunk_id);
        const exanic_cycles_t ts64 = exanic_expand_timestamp(priv->rx_nic,ts32);
        *ts = ts64;
        *ts_hz = priv->tick_hz;
    }

    return frame_error;
}


//Read operations
static inline eio_error_t exa_read_acquire(eio_stream_t* this, char** buffer,
                                           int64_t* len, int64_t* ts,
                                           int64_t* ts_hz )
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(priv->closed){
        return EIO_ECLOSED;
    }

    ifassert((ssize_t)priv->rx_in_progress){
        return EIO_ERELEASE;
    }
    priv->rx_in_progress = true;
    priv->stats_sw_rx.spins_first++;

    int error = get_next_chunk(priv, ts, ts_hz);
    switch(error){
    //There's nothing we can do to recover from these errors
        case EIO_ETRYAGAIN:           return EIO_ETRYAGAIN;
        case -EXANIC_RX_FRAME_SWOVFL:
            priv->stats_sw_rx.swofl++;
            return EIO_ESWOVFL;
    }

    //We've now got the first packet chunk...
    //Figure out if we want to keep it?
    void* dst_buf = NULL;
    int64_t dst_buf_len = 0;
    ifunlikely(buffer == NULL || len == NULL){
        //The user doesn't want this chunk, and therefore the whole frame
        priv->stats_sw_rx.dropped++;
        iflikely(priv->more_rx_chunks){
            int err = exanic_receive_abort(priv->rx);
            ifunlikely( err == -EXANIC_RX_FRAME_SWOVFL){
                priv->stats_sw_rx.swofl++;
                return EIO_EFRAME_DRP;
            }
        }
        return EIO_EFRAME_DRP;
    }

    //We want to keep this packet, so figure out where to put it
    priv->stats_sw_rx.packets_rx++;

    iflikely(*buffer && *len > 0 ){
        //User has supplied a buffer, copy to it
        dst_buf     = *buffer;
        dst_buf_len = *len;
    }
    else ifunlikely(priv->rx_pkt_buf_len){
        //We are copying to a local buffer and then returning it
        dst_buf     = priv->rx_pkt_buf;
        dst_buf_len = priv->rx_pkt_buf_len;
    }
    else{
        //No buffer from the user, and no buffer internally!
        ch_log_fatal("Cannot copy packet, no buffer supplied\n");
        return EIO_ENOMEM;
    }

    //We're going to return a packet one way or another...
    //but be careful not to copy too much...
    const int64_t to_copy = MIN(dst_buf_len,priv->rx_chunk_len);
    memcpy(dst_buf,  priv->rx_chunk_ptr,  to_copy);
    int64_t frame_len = priv->rx_chunk_len;

    //If there are more chunks in this packet, then we need those too
    for(;priv->more_rx_chunks;priv->stats_sw_rx.spins_more++){

        //See if there's some more chunks
        error = get_next_chunk(priv, NULL, NULL);
        switch(error){
            case EIO_ETRYAGAIN: continue;
            //There's nothing we can do to recover from this error
            case -EXANIC_RX_FRAME_SWOVFL:
                priv->stats_sw_rx.swofl++;
                return EIO_ESWOVFL;
        }

// Fast copy for 120B frames
//      ifunlikely(priv->rx_chunk_len == 120 && dst_buf_len - frame_len >= 120 ){
//          memcpy120(dst_buf,  priv->rx_chunk_ptr);
//       }else
         iflikely(frame_len < dst_buf_len ){
            const int64_t to_copy = MIN(dst_buf_len - frame_len,priv->rx_chunk_len);
            memcpy(dst_buf,  priv->rx_chunk_ptr,  to_copy);
        }
        frame_len += priv->rx_chunk_len;
    }

    //At this point the value of "error" is from the last chunk that we rx'd

    *buffer = dst_buf;
    *len    = frame_len;
    //Only count the number of bytes we actually received
    priv->stats_sw_rx.bytes_rx += MIN(dst_buf_len, frame_len);

    if(frame_len >= dst_buf_len){
        priv->stats_sw_rx.truncated++;
        switch(error){
            case -EXANIC_RX_FRAME_SWOVFL:
                priv->stats_sw_rx.swofl++;
                return EIO_ESWOVFL;
            case -EXANIC_RX_FRAME_HWOVFL:
                priv->stats_sw_rx.hwofl++;
                return EIO_EFRAME_TRC_HWO;
            case -EXANIC_RX_FRAME_ABORTED:
                priv->stats_sw_rx.aborted++;
                return EIO_EFRAME_TRC_ABT;
            case -EXANIC_RX_FRAME_CORRUPT:
                priv->stats_sw_rx.corrupted++;
                return EIO_EFRAME_TRC_CPT;
            default:
                return EIO_EFRAME_TRC;
        }
    }

    switch(error){
        case -EXANIC_RX_FRAME_SWOVFL:
            priv->stats_sw_rx.swofl++;
            return EIO_ESWOVFL;
        case -EXANIC_RX_FRAME_HWOVFL:
            priv->stats_sw_rx.hwofl++;
            return EIO_EFRAME_HWO;
        case -EXANIC_RX_FRAME_ABORTED:
            priv->stats_sw_rx.aborted++;
            return EIO_EFRAME_ABT;
        case -EXANIC_RX_FRAME_CORRUPT:
            priv->stats_sw_rx.corrupted++;
            return EIO_EFRAME_CPT;
    }

    return EIO_ENONE;
}


static inline eio_error_t exa_read_release(eio_stream_t* this)
{
    eio_error_t result = EIO_ENONE;
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);


    ifassert(!priv->rx_in_progress){
        return EIO_ERELEASE;
    }

    ifunlikely(exanic_receive_chunk_recheck(priv->rx, priv->rx_chunk_id) == 0){
        priv->stats_sw_rx.swofl++;
        result = EIO_ESWOVFL;
    }

    priv->rx_in_progress = false;

    //Nothing to do here;
    return result;
}


static inline eio_error_t exa_read_sw_stats(eio_stream_t* this,void** stats,
                                            exact_stats_hdr_t** stats_hdr)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return EIO_ECLOSED;
    }

    *stats       = &priv->stats_sw_rx;
    *stats_hdr = exanic_stats_sw_rx_hdr;

    return EIO_ENONE;
}



static inline eio_error_t exa_read_hw_stats(eio_stream_t* this,
                                            void** stats,
                                            exact_stats_hdr_t** stats_hdr)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return EIO_ECLOSED;
    }

    nic_stats_hw_t* nic_hw_stats = &priv->stats_hw;

    ch_log_debug1("Getting port stats on nic %s port %i\n", this->name, priv->rx_port);
    exanic_port_stats_t port_stats = {0};
    int err = exanic_get_port_stats(priv->rx_nic,
            priv->rx_port,
            &port_stats);

    nic_hw_stats->tx_count         = port_stats.tx_count;
    nic_hw_stats->rx_count         = port_stats.rx_count;
    nic_hw_stats->rx_dropped_count = port_stats.rx_dropped_count;
    nic_hw_stats->rx_error_count   = port_stats.rx_error_count;
    nic_hw_stats->rx_ignored_count = port_stats.rx_ignored_count;
    nic_hw_stats->device = this->name;

    *stats       = nic_hw_stats;
    *stats_hdr = exanic_stats_hw_hdr;
    return err;
}


//Write operations
static eio_error_t exa_write_acquire(eio_stream_t* this, char** buffer, int64_t* len)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    ifassert(priv->tx_buffer){
        return EIO_ERELEASE;
    }

    ifassert(*len > (int64_t)priv->max_tx_mtu){
        return EIO_ETOOBIG;
    }

    iflikely(*len == 0){
        *len = priv->max_tx_mtu;
    }

    priv->tx_buffer_len = *len;
    priv->tx_buffer = exanic_begin_transmit_frame(priv->tx,(size_t)*len);

    *buffer = priv->tx_buffer;

    return EIO_ENONE;
}

static eio_error_t exa_write_release(eio_stream_t* this, int64_t len)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(!priv->tx_buffer){
        return EIO_EACQUIRE;
    }

    ifassert(len > priv->tx_buffer_len){
        fprintf(stderr,"Error: length supplied is larger than length of buffer. Corruption likely. Aborting\n");
        exit(-1);
    }

//    exanic_cycles32_t old_start = 0;
//    exanic_cycles32_t start     = 0;
//    ifunlikely(ts){
//        old_start = exanic_get_tx_timestamp(priv->tx);
//    }

    ifunlikely(len == 0){
        exanic_abort_transmit_frame(priv->tx);
        return EIO_ENONE;
    }

    ifunlikely(exanic_end_transmit_frame(priv->tx,len)){
        return EIO_EUNSPEC;
    }

    priv->stats_sw_tx.packets_rx++;
    priv->stats_sw_tx.bytes_rx += len;

//    ifunlikely(ts){
//        do{
//            /* Wait for TX frame to leave the NIC */
//        }
//        while (old_start == start);
//
//        //This is nasty because the last packet sent timestamp will not always
//        //be timestamp of the packet sent
//        *ts = exanic_expand_timestamp(priv->tx_nic, start);
//    }

    priv->tx_buffer     = NULL;
    priv->tx_buffer_len = 0;
    return EIO_ENONE;
}


static inline eio_error_t exa_write_sw_stats(eio_stream_t* this,void** stats,
                                             exact_stats_hdr_t** stats_hdr)
{

    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return EIO_ECLOSED;
    }

    *stats       = &priv->stats_sw_tx;
    *stats_hdr = exanic_stats_sw_tx_hdr;

    return EIO_ENONE;
}


static inline eio_error_t exa_write_hw_stats(eio_stream_t* this, void** stats,
        exact_stats_hdr_t** stats_hdr)

{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return EIO_ECLOSED;
    }

    nic_stats_hw_t* nic_hw_stats = &priv->stats_hw;

    ch_log_debug1("Getting port stats on nic %s port %i\n", this->name, priv->rx_port);
    exanic_port_stats_t port_stats = {0};
    int err = exanic_get_port_stats(priv->tx_nic,
            priv->tx_port,
            &port_stats);

    nic_hw_stats->tx_count         = port_stats.tx_count;
    nic_hw_stats->rx_count         = port_stats.rx_count;
    nic_hw_stats->rx_dropped_count = port_stats.rx_dropped_count;
    nic_hw_stats->rx_error_count   = port_stats.rx_error_count;
    nic_hw_stats->rx_ignored_count = port_stats.rx_ignored_count;
    nic_hw_stats->device = this->name;

    *stats       = nic_hw_stats;
    *stats_hdr = exanic_stats_hw_hdr;
    return err;
}


static eio_error_t exa_get_id(eio_stream_t* this, int64_t* id_major, int64_t* id_minor)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    ifassert(!id_major || !id_minor){
        return EIO_EINVALID;
    }

    *id_major = priv->id_major;
    *id_minor = priv->id_minor;

    return EIO_ENONE;
}



int ethtool_ioctl(int fd, char *ifname, void *data)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_data = data;

    return ioctl(fd, SIOCETHTOOL, &ifr);
}

static int ethtool_get_priv_flags(int fd, char *ifname, uint32_t *flags)
{
    struct ethtool_value val;
    int ret;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_GPFLAGS;
    ret = ethtool_ioctl(fd, ifname, &val);
    if (ret == 0)
        *flags = val.data;

    return ret;
}


static int ethtool_get_flag_names(int fd, char *ifname,
                                  char flag_names[32][ETH_GSTRING_LEN])
{
    struct ethtool_drvinfo drvinfo;
    struct ethtool_gstrings *strings;
    unsigned len;

    /* Get number of flags from driver info */
    memset(&drvinfo, 0, sizeof(drvinfo));
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    if (ethtool_ioctl(fd, ifname, &drvinfo) == -1)
        return -1;

    len = drvinfo.n_priv_flags;
    if (len > 32)
        len = 32;

    /* Get flag names */
    strings = calloc(1, sizeof(struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_PRIV_FLAGS;
    strings->len = len;
    if (ethtool_ioctl(fd, ifname, strings) == -1)
    {
        free(strings);
        return -1;
    }

    memset(flag_names, 0, 32 * ETH_GSTRING_LEN);
    memcpy(flag_names, strings->data, len * ETH_GSTRING_LEN);

    return 0;
}


static int ethtool_set_priv_flags(int fd, char *ifname, uint32_t flags)
{
    struct ethtool_value val;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_SPFLAGS;
    val.data = flags;

    return ethtool_ioctl(fd, ifname, &val);
}

static int set_exanic_params(exanic_t *exanic, char* device, int port_number,
                             bool promisc, bool kernel_bypass)
{
    struct ifreq ifr;
    int fd;

    if (exanic_get_interface_name(exanic, port_number, ifr.ifr_name, IFNAMSIZ) != 0)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                exanic_get_last_error());
        exit(1);
    }


    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
            ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    if(promisc)
        ifr.ifr_flags |= IFF_PROMISC;

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }


    if(!kernel_bypass)
        return 0;


    /* Get flag names and current setting */
    char flag_names[32][ETH_GSTRING_LEN];
    uint32_t flags = 0;
    if (ethtool_get_flag_names(fd, ifr.ifr_name, flag_names) == -1 ||
        ethtool_get_priv_flags(fd, ifr.ifr_name, &flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    /* Look for flag name */
    int i = 0;
    for (i = 0; i < 32; i++)
        if (strcmp("bypass_only", flag_names[i]) == 0)
            break;
    if (i == 32)
    {
        fprintf(stderr, "%s:%d: could not find bypass-only flag \n",
                device, port_number);
        exit(1);
    }

    flags |= (1 << i);

    /* Set flags */
    if (ethtool_set_priv_flags(fd, ifr.ifr_name, flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                (errno == EINVAL) ? "Feature not supported on this port"
                                  : strerror(errno));
        exit(1);
    }

    return 0;
}


/*
 * Arguments
 * [0] filename
 * [1] read buffer size
 * [2] write buffer size
 * [3] reset on modify
 */
static eio_error_t exa_construct(eio_stream_t* this, exa_args_t* args)
{
    const char* interface_rx = args->interface_rx;
    const char* interface_tx = args->interface_tx;
    const bool promisc       = args->promisc;
    const bool kernel_bypass = args->kernel_bypass;
    const bool clear_buff    = args->clear_buff;
    const int64_t rx_pkt_buf = args->rx_pkt_buf;

    ch_log_info("Constructing exanic %s\n", args->interface_rx);
    /*TODO for the moment just use the RX interface name. Should think of
     * something smarter to do here? Maybe "rx:tx"?
     */
    const char* name = args->interface_rx;
    const int64_t name_len = strnlen(name, 1024);
    this->name = calloc(name_len + 1, 1);
    memcpy(this->name, name, name_len);

    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    if(interface_rx){
        if(parse_device(interface_rx, priv->rx_dev, &priv->rx_dev_id, &priv->rx_port))
        {
            fprintf (stderr, "%s: no such interface or not an ExaNIC\n",
                     interface_rx);
            return 1;
        }

        priv->id_major = priv->rx_dev_id;
        priv->id_minor = priv->rx_port;

        priv->rx_nic = exanic_acquire_handle(priv->rx_dev);
        if (!priv->rx_nic){
            fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
            return 1;
        }
        priv->tick_hz  = priv->rx_nic->tick_hz;

        priv->rx = exanic_acquire_rx_buffer(priv->rx_nic, priv->rx_port, 0);
        if (!priv->rx){
            fprintf(stderr, "exanic_acquire_rx_buffer: %s\n", exanic_get_last_error());
            return 1;
        }

        if(clear_buff){
            ch_log_warn("Warning: clearing rx buffer on %s\n", interface_rx);
            const size_t rx_buff_sz = 64 * 1024;
            char rx_buff[rx_buff_sz];
            int64_t clear_cnt = -1;
            for(ssize_t err = -1; err != 0; clear_cnt++){
                 err =exanic_receive_frame(priv->rx, rx_buff, rx_buff_sz, NULL);
                 if(err < 0){
                     ch_log_warn("Warning: rx error %li on %s\n", err, interface_rx);
                 }
            }
            if(clear_cnt > 0){
                ch_log_warn("Cleared stale frames from rx buffer on %s\n",
                            interface_rx);
            }
            ch_log_info("Done clearing rx buffer on %s\n", interface_rx);
        }

        if(set_exanic_params(priv->rx_nic, priv->rx_dev, priv->rx_port,
                             promisc,kernel_bypass)){
            return 1;
        }

        if(rx_pkt_buf){
            priv->rx_pkt_buf = calloc(rx_pkt_buf, 1);
            if(!priv->rx_pkt_buf){
                return EIO_ENOMEM;
            }
            priv->rx_pkt_buf_len = rx_pkt_buf;
        }

    }

    if(interface_tx){
        if(parse_device(interface_tx, priv->tx_dev, &priv->tx_dev_id, &priv->tx_port))
        {
            fprintf (stderr, "%s: no such interface or not an ExaNIC\n",
                     interface_tx);
            return 1;
        }


        priv->tx_nic = exanic_acquire_handle(priv->tx_dev);
        if (!priv->tx_nic){
            fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
            return 1;
        }

        priv->max_tx_mtu = exanic_get_tx_mtu(priv->tx);

        priv->tx = exanic_acquire_tx_buffer(priv->tx_nic, priv->tx_port, 0);
        if (!priv->tx){
            fprintf(stderr, "exanic_acquire_tx_buffer: %s\n", exanic_get_last_error());
            return 1;
        }
    }


    //priv->eof    = 0;
    priv->closed = false;

    return 0;

}

NEW_IOSTREAM_DEFINE(exa,exa_args_t, exa_priv_t)

