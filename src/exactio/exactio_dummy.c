/*
 * Copyright (c) 2017, 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Implementation of dummy stream that simply returns a static memory region
 *  rather than performing I/O operations.
 */


#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>

#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <chaste/chaste.h>

#include "exactio_dummy.h"
#include "../data_structs/expcap.h"
#include "../data_structs/pcap-structures.h"
#include "exactio_timing.h"

#define getpagesize() sysconf(_SC_PAGESIZE)
#define HEADER_SIZE getpagesize()

typedef enum {
    EXACTIO_FILE_MOD_IGNORE = 0,
    EXACTIO_FILE_MOD_RESET  = 1,
    EXACTIO_FILE_MOD_TAIL   = 2,
} exactio_dummy_mod_t;

typedef struct exactio_dummy_priv_s {
    int fd;
    char* filename;
    bool eof;
    bool closed;

    char* read_buff;
    int64_t read_buff_size;
    bool reading;


    char* write_buff;
    int64_t write_buff_size;
    char* usr_write_buff;
    int64_t usr_write_buff_size;
    bool writing;

    int64_t segs;

    int64_t exanic_pkt_size;
    int64_t exanic_bytes_read;

    int64_t rd_mode;



} dummy_priv_t;


static void dummy_destroy(eio_stream_t* this)
{
    dummy_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return;
    }


    if(priv->write_buff){
        munlock(priv->write_buff, priv->write_buff_size);
        free(priv->read_buff);
    }


    if(priv->read_buff){
        munlock(priv->read_buff, priv->read_buff_size);
        free(priv->read_buff);
    }

    if(priv->write_buff){
        munlock(priv->write_buff, priv->write_buff_size);
        free(priv->read_buff);
    }

    if(priv->filename){
        free(priv->filename);
    }

    if(priv->fd){
        close(priv->fd);
    }

    if(this->name)
    {
        free(this->name);
        this->name = NULL;
    }

    priv->closed = true;

}


//Read operations
#define EXANIC_DATA_CHUNK_SIZE 120 /* This is unlikely to ever change. Ever. */
static eio_error_t dummy_read_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts )
{
    dummy_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(priv->closed){
        return EIO_ECLOSED;
    }

    ifassert(priv->reading){
        ch_log_fatal("Call read release before calling read acquire\n");
        return EIO_ERELEASE;
    }

    int result = EIO_ENONE;

    if(buffer == NULL || len == NULL){
        priv->reading = true;
        return EIO_ENONE;
    }


    if(priv->rd_mode == DUMMY_MODE_EXANIC){
        const int64_t remain = priv->exanic_pkt_size - priv->exanic_bytes_read;
//        ch_log_info("remain=%li, pkt_size=%li, bytes_read=%li\n",
//                    remain,
//                    priv->exanic_pkt_size,
//                    priv->exanic_bytes_read);
        if(remain > EXANIC_DATA_CHUNK_SIZE ){
           priv->exanic_bytes_read += EXANIC_DATA_CHUNK_SIZE;
           *len = EXANIC_DATA_CHUNK_SIZE;
           result = EIO_EFRAG_MOR;
        }
        else{
           priv->exanic_bytes_read = 0;
           *len = remain;
       }
    }
    else{
        *len    = priv->read_buff_size;
    }

    //All good! Successful "read"!
    *buffer = priv->read_buff;

    priv->reading = true;

    (void)ts;
    //eio_nowns(ts);
    //ch_log_info("Returning buffer of size=%li at %p\n", *len, *buffer);
    return result;
}

static eio_error_t dummy_read_release(eio_stream_t* this, int64_t* ts)
{
    dummy_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    ifassert(!priv->reading){
        ch_log_fatal("Error: Call acquire before calling release\n");
        return EIO_EACQUIRE;
    }

    priv->reading = false;
    eio_nowns(ts);
    //Nothing to do here;
    return EIO_ENONE;
}

static inline eio_error_t dummy_read_sw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}

static inline eio_error_t dummy_read_hw_stats(eio_stream_t* this, void* stats)
{

    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}



//Write operations
static eio_error_t dummy_write_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts)
{
    dummy_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ch_log_debug3("Calling dummy write acquire\n");

    ifassert(priv->writing){
        ch_log_fatal("Error: Call release before calling acquire\n");
        return EIO_ERELEASE;
    }

    ifassert(*len > priv->write_buff_size){
        ch_log_fatal("Error: Requested write size too big\n");
        return EIO_ETOOBIG;
    }

    iflikely(*buffer && *len){
         //User has supplied a buffer and a length, so just give it back to them
         priv->usr_write_buff = *buffer;
         priv->usr_write_buff_size = *len;

     }
     else{
         *len = priv->write_buff_size;
         *buffer = priv->write_buff;
     }

     priv->writing = true;
     eio_nowns(ts);

    return EIO_ENONE;
}

static eio_error_t dummy_write_release(eio_stream_t* this, int64_t len, int64_t* ts)
{
    dummy_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ch_log_debug3("Calling dummy write release\n");


    ifassert(!priv->writing){
        ch_log_error("Error: Call acquire before calling release\n");
        return EIO_EACQUIRE;
    }

    ifassert(len > priv->write_buff_size){
        ch_log_error("Error: Too much data written, corruption likely\n");
        return EIO_ETOOBIG;
    }


    //If the user has supplied their own buffer, use it
    //const char* buff = priv->usr_write_buff ? priv->usr_write_buff : priv->write_buff;
    //priv->usr_write_buff = NULL;

    priv->writing = false;

    eio_nowns(ts);
    return EIO_ENONE;
}

static inline eio_error_t dummy_write_sw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}

static inline eio_error_t dummy_write_hw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

    return EIO_ENOTIMPL;
}


static eio_error_t dummy_time_to_tsps(eio_stream_t* this, void* time, timespecps_t* tsps)
{
    (void)this;
    (void)time;
    (void)tsps;

    return EIO_ENOTIMPL;
}



/*
 * Arguments
 * [0] filename
 * [1] read buffer size
 * [2] write buffer size
 * [3] reset on modify
 */
static eio_error_t dummy_construct(eio_stream_t* this, dummy_args_t* dummy_args)
{

    const uint64_t read_buff_size   = dummy_args->read_buff_size;
    const uint64_t write_buff_size  = dummy_args->write_buff_size;
    const dummy_read_mode rd_mode   = dummy_args->rd_mode;

    const char* name                = dummy_args->name;
    const int64_t name_len = strnlen(name, 1024);
    this->name = calloc(name_len + 1, 1);
    memcpy(this->name, name, name_len);




    dummy_priv_t* priv = IOSTREAM_GET_PRIVATE(this);


    priv->read_buff_size  = round_up(read_buff_size,getpagesize()); //Round up to nearest page size
    priv->write_buff_size = round_up(write_buff_size,getpagesize()); //Round up to nearest page size


    priv->read_buff = aligned_alloc(getpagesize(), priv->read_buff_size);
    if(!priv->read_buff){
        ch_log_error("Error: could allocate read buffer body null stream. Error=%s\n", strerror(errno));
        dummy_destroy(this);
        return -3;
    }


    if(mlock(priv->read_buff, priv->read_buff_size)){
        ch_log_error("Error: could not lock read buffer for body header null stream. Error=%s\n", strerror(errno));
        //dummy_destroy(this);
        //return -4;
    }

    priv->rd_mode = rd_mode;
    if(rd_mode == DUMMY_MODE_EXPCAP){

        const int64_t pkt_size = MIN(64, dummy_args->expcap_bytes);

        const int64_t record_size = sizeof(pcap_pkthdr_t) + pkt_size
                + sizeof(expcap_pktftr_t);

        /*
         * Figure out how many expcap packets we can fit, the last packet will
         * mop up any left of bytes to make it all fit
         */
        const int64_t num_packets = (priv->read_buff_size - record_size) / record_size;
        const int64_t total_bytes = num_packets * record_size;
        const int64_t last_record =  priv->read_buff_size - total_bytes;
        ch_log_info("Null stream is in EXPCAP mode, read buffer size = %liB\n %li packets of size %liB ea will be written into %liB records\n the last record is %liB, total packets bytes=%liB\n",
                    priv->read_buff_size, num_packets + 1, pkt_size, record_size, last_record,
                    num_packets * record_size + last_record);

        for(int i = 0; i < num_packets; i++){
            pcap_pkthdr_t* pkt_hdr = (pcap_pkthdr_t*)(priv->read_buff + i * record_size );
            pkt_hdr->caplen = pkt_size + sizeof(expcap_pktftr_t);
            pkt_hdr->len = pkt_size;
            pkt_hdr->ts.raw = ~0;
        }

        pcap_pkthdr_t* pkt_hdr = (pcap_pkthdr_t*)(priv->read_buff + num_packets * record_size );
        //Use the last ts value so the writer thread doesn't break
        pkt_hdr->ts.raw = ~0;
        pkt_hdr->caplen = last_record - sizeof(pkt_hdr);
        pkt_hdr->len = 0; /*This is an invalid packet, 0 wire length */

    }
    else if(rd_mode == DUMMY_MODE_EXANIC){
        priv->exanic_pkt_size = dummy_args->exanic_pkt_bytes;
    }



    priv->write_buff = aligned_alloc(getpagesize(), priv->write_buff_size);
    if(!priv->write_buff){
        ch_log_error("Error: could allocate write buffer for null stream. Error=%s\n", strerror(errno));
        dummy_destroy(this);
        return -5;
    }

    if(mlock(priv->write_buff, priv->write_buff_size)){
        ch_log_error("Error: could not lock write buffer for null stream. Error=%s\n", strerror(errno));
        dummy_destroy(this);
        return -6;
    }

    priv->eof    = 0;
    priv->closed = false;


    ch_log_info("Created file reader/write with buffer size rd=%li, wr=%li\n", priv->read_buff_size, priv->write_buff_size);
    return 0;

}


NEW_IOSTREAM_DEFINE(dummy, dummy_args_t, dummy_priv_t)
