/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     4 Aug 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  This is the main listener thread. Its job is to read a single ExaNIC buffer
 *  (2MB) and copy fragments of packets in 120B chunks into a slot in a larger
 *  circular queue. The larger queue is the connection to a writer thread that
 *  syncs data to disk. The listener thread formats data int "blaze" file format
 *  directly in the buffer. It only has about 60ns to handle each fragment and
 *  maintain line rate for minimum sized packets. The writer requires that all
 *  data is 4K aligned. To solve this the listener inserts "dummy" packets to
 *  pad out to 4K whenever it syncs to
 *  the writer.
 */
#include <errno.h>

#include "exact-capture-listener.h"

#include "data_structs/blaze_file.h"
#include "utils.h"


static __thread int64_t dev_id;
static __thread int64_t port_id;
static __thread listen_stats_t* stats;

static inline void add_dummy_packet(char* obuff, int64_t dummy_rec_len)
{


    const int64_t dummy_payload_len = dummy_rec_len - sizeof(blaze_hdr_t);

    ch_log_debug1("Adding dummy of blaze record of len=%li (payload=%li) to %p\n",
                  dummy_rec_len, dummy_payload_len, obuff);

    blaze_hdr_t* dummy_hdr = (blaze_hdr_t*) (obuff);
    obuff += sizeof(blaze_hdr_t);

    //Use the last ts value so the writer thread doesn't break
    dummy_hdr->flags = BLAZE_FLAG_IGNR;
    dummy_hdr->caplen  = dummy_rec_len - sizeof(blaze_hdr_t);
    dummy_hdr->wirelen = 0; /*This is an invalid dummy packet, 0 wire length */

    obuff += dummy_payload_len;

}


static inline void flush_buffer(eio_stream_t* ostream, int64_t bytes_added,
                  int64_t obuff_len, char* obuff)
{

    //Nothing to do if nothing was added
    if(bytes_added == 0)
    {
        return;
    }

    ch_log_debug1("Flushing at offset %li, buffer_start=%p, buffer_fin=%p\n",
                  bytes_added,
                  obuff,
                  obuff+obuff_len-1);

    /* What is the minimum sized record that we can squeeze in?
     * Just a blaze header and no content */
    const int64_t min_rec = sizeof(blaze_hdr_t);


    /* Find the next disk block boundary with space for adding a minimum packet*/
    const int64_t block_bytes = round_up(bytes_added + min_rec, DISK_BLOCK);

    ch_log_debug1("Block bytes=%li\n", block_bytes);
    ifassert(block_bytes > obuff_len)
    {
        ch_log_fatal("Assumption violated %li > %li\n", block_bytes, obuff_len);
    }

    /* How many bytes do we need to write? */
    int64_t remain = block_bytes - bytes_added;

    ch_log_debug1("Remain bytes=%li\n", remain);

    add_dummy_packet(obuff + bytes_added, remain);
    bytes_added += remain;
    ch_log_debug1("Added dummy of size %li\n", remain);

    /* At this point, we've padded up to the disk block boundary.
     * Flush out to disk thread writer*/
    eio_wr_rel(ostream, bytes_added);

    ch_log_debug1("Done flushing at %li bytes added\n", bytes_added);
}

/* Finish off a packet by populating remaining fields in the header*/
static inline void complete_packet(blaze_hdr_t* hdr, uint8_t flags,
        int64_t* dropped, int dev_id, int port_id,  int64_t packet_seq)
{
    hdr->flags   = flags;
    hdr->dropped = *dropped;
    hdr->dev     = dev_id;
    hdr->port    = port_id;
    hdr->seq     = packet_seq;
    *dropped     = 0;
}



/*
 * Look for a new output stream and output the buffer from that stream
 */
static inline int get_ring(int64_t curr_ring, int64_t ring_count,
                            eio_stream_t** rings, char** ring_buff,
                            int64_t* obuff_len )
{
    ch_log_debug2("Looking for new ring..\n");
    /* Look at each ostream just once */
    for (int i = 0; i < ring_count; i++, curr_ring++)
    {
        curr_ring = curr_ring >= ring_count ? 0 : curr_ring;
        eio_stream_t* ring = rings[curr_ring];
        eio_error_t err = eio_wr_acq (ring, ring_buff, obuff_len);
        iflikely(err == EIO_ENONE)
        {
            ch_log_debug1("Got ring at index %li..\n", curr_ring);
            return curr_ring;
        }
        iflikely(err == EIO_ETRYAGAIN)
        {
            continue; //Look at the next ring
        }

        ch_log_error("Could not get bring with unexpected error %i\n", err);
        return -1;
    }

    ch_log_debug2("Could not find an ostream!\n");
    return curr_ring;

}


/*
 * This is the main listener thread. Its job is to read a single ExaNIC buffer
 * (2MB) and copy fragments of packets in 120B chunks into a slot in a larger
 * circular queue. The larger queue is the connection to a writer thread that
 * syncs data to disk. The listener thread puts templates for PCAP headers
 * into the ring and minimal info into these headers. Final preparation of the
 * headers is left to the writer thread. This thread has very tight timing
 * requirements. It only has about 60ns to handle each fragment and maintain
 * line rate. The writer requires that all data is 4K aligned. To solve this the
 * listener inserts "dummy" packets to pad out to 4K whenever it syncs to the
 * writer.
 */

void* listener_thread (void* params)
{
    lparams_t* lparams = params;
    ch_log_debug1("Creating exanic listener thread id=%li on interface=%s\n",
                    lparams->ltid, lparams->nic_istream->name);

    //Raise this thread prioirty
    if(nice(-20) == -1)
    {
        ch_log_warn("Failed to change thread priority."
                       "Performance my be affected! (%s)\n", strerror(errno));
    }
    /*
     * Set up a dummy packet to pad out extra space when needed
     * dummy packet areas are per thread to avoid falsely sharing memory
     */
    char dummy_data[DISK_BLOCK * 2];
    init_dummy_data(dummy_data, DISK_BLOCK *2);

    const int64_t ltid = lparams->ltid; /* Listener thread id */

    /* Thread local storage parameters */
    eio_get_id(lparams->nic_istream, &dev_id, &port_id);
    stats  = &lparams->stats;

    eio_stream_t** rings = lparams->rings;
    int64_t rings_count = lparams->rings_count;
    eio_stream_t* nic = lparams->nic_istream;


    //**************************************************************************
    //Listener - Real work begins here!
    //**************************************************************************
    char* obuff = NULL;
    int64_t obuff_len = 0;

    /* May want to change this depending on scheduling goals */
    int64_t curr_ring = ltid;
    int64_t bytes_added = 0;


    int64_t now;
    const int64_t maxwaitns = 1000 * 1000 * 100;
    eio_nowns (&now);
    int64_t timeout = now + maxwaitns; //100ms timeout

    int64_t packet_seq = 0;
    int64_t dropped    = 0;

    const int64_t blaze_hdr_size = (int64_t)sizeof(blaze_hdr_t);
    const int64_t max_blaze_rec = lparams->snaplen + blaze_hdr_size;
    const int64_t min_blaze_rec = blaze_hdr_size;

    int64_t tryagain_counter = 0;

    while (!*lparams->stop){
        /*
         * The following code will flush the output buffer and send it across to
         * the writer thread and then obtain a new output buffer. It does so in
         * one of 2 circumstances:
         *
         * 1) There is less than 1 full packet plus a blaze_pkt_hdr_t left worth
         * of space in the output buffer. The blaze_pkthdr_t is required to ensure
         * there is enough space for a dummy packet to pad out the rest of this
         * buffer to be block aligned size for high speed writes to disk.
         *
         * 2) There has been a timeout and there are packets waiting (not just a
         * pre-prepared pcap header. We do this so that packets don't wait too
         * long before timestamp conversions and things happen.
         */

        const bool buff_full = obuff_len - bytes_added <  max_blaze_rec * 2;
        const bool timed_out = now >= timeout && bytes_added > blaze_hdr_size;
        ifunlikely( obuff && (buff_full || timed_out)){
            ch_log_debug1( "Buffer flush: buff_full=%i, timed_out =%i, obuff_len (%li) - bytes_added (%li) = %li < full_packet_size x 2 (%li) = (%li)\n",
                    buff_full, timed_out, obuff_len, bytes_added, obuff_len - bytes_added, max_blaze_rec * 2);

            flush_buffer(rings[curr_ring], bytes_added, obuff_len, obuff);

            /* Reset the timer and the buffer */
            eio_nowns(&now);
            timeout = now + maxwaitns;
            obuff = NULL;
            obuff_len = 0;
            bytes_added = 0;
        }

        while(!obuff && !*lparams->stop){
            /* We don't have an output buffer to work with, so try to grab one*/
            curr_ring = get_ring(curr_ring,rings_count,rings, &obuff,&obuff_len);

            if(curr_ring < 0){
                goto finished;
            }

            /*
             * We looked at all the ostreams, there was nowhere to put a frame.
             * If there is a new frame, then skip it, otherwise try again to
             * find a place to put it. We don't want this to happen, but we do
             * want it to be fast when it does hence "likely".
             */
            iflikely(!obuff){
                ch_log_debug2("No buffer, dropping packet..\n");
                eio_error_t err = EIO_ENONE;
                err = eio_rd_acq(nic, NULL, NULL, NULL, NULL);
                iflikely(err == EIO_EFRAME_DRP){
                    packet_seq++;
                    dropped++;

                }
                err = eio_rd_rel(nic);
            }
        }

        if(*lparams->stop){
            goto finished;
        }


        /* Try to RX one packet. Deal with any errors */

        blaze_hdr_t* hdr = (blaze_hdr_t*) (obuff);
        bytes_added += sizeof(blaze_hdr_t);
        const int64_t obuff_remain = obuff_len - bytes_added - min_blaze_rec;
        const int64_t max_rx_bytes = MIN(lparams->snaplen, obuff_remain);

        int64_t rx_bytes   = max_rx_bytes;
        char* buffer       = obuff + bytes_added;
        int64_t rx_time    = 0;
        int64_t rx_time_hz = 0;
        eio_error_t err_aq = eio_rd_acq(nic, &buffer, &rx_bytes, &rx_time, &rx_time_hz);

        //Since we are supplying the buffer to rd_acq(), we can "release" it
        //immediately
        eio_error_t err_rl = eio_rd_rel(nic);
        if(err_rl == EIO_ESWOVFL || err_aq == EIO_ESWOVFL){
            //Unwind the header;
            bytes_added -= sizeof(blaze_hdr_t);
            continue;
        }

        switch(err_aq){
            case EIO_ETRYAGAIN:{
                //Unwind the header;
                bytes_added -= sizeof(blaze_hdr_t);
                tryagain_counter++;
                ifunlikely(tryagain_counter > 1000){
                    /* Do this here so we don't do it too often. Only when we're
                     * waiting around with nothing to do (eg 1000 try again's in
                     * a row)*/
                    eio_nowns(&now);
                    tryagain_counter = 0;
                }
                continue;
            }

            //At this point, we know we got a frame, we're just not sure how good it is...
            case EIO_ENONE:      hdr->flags = BLAZE_FLAG_NONE;   break;
            case EIO_EFRAME_ABT: hdr->flags = BLAZE_FLAG_ABRT;   break;
            case EIO_EFRAME_CPT: hdr->flags = BLAZE_FLAG_CRPT;   break;
            case EIO_EFRAME_HWO: hdr->flags = BLAZE_FLAG_HWOVFL; break;
            case EIO_EFRAME_TRC: hdr->flags = BLAZE_FLAG_TRNC;   break;
            case EIO_EFRAME_TRC_ABT: hdr->flags = BLAZE_FLAG_TRNC | BLAZE_FLAG_ABRT ; break;
            case EIO_EFRAME_TRC_CPT: hdr->flags = BLAZE_FLAG_TRNC | BLAZE_FLAG_ABRT ; break;
            case EIO_EFRAME_TRC_HWO: hdr->flags = BLAZE_FLAG_TRNC | BLAZE_FLAG_ABRT ; break;

            default:
                ch_log_fatal("Unexpected error type %i\n", err_aq);
        }

        switch(err_aq){
            //Fully received frames
            case EIO_ENONE:
            case EIO_EFRAME_ABT:
            case EIO_EFRAME_CPT:
            case EIO_EFRAME_HWO:
                hdr->caplen  = rx_bytes;
                hdr->wirelen = rx_bytes;
                break;

            //Truncated frames
            case EIO_EFRAME_TRC:
            case EIO_EFRAME_TRC_ABT:
            case EIO_EFRAME_TRC_CPT:
            case EIO_EFRAME_TRC_HWO:
                hdr->caplen  = max_rx_bytes;
                hdr->wirelen = rx_bytes;
                break;
            default:
                ch_log_fatal("Unexpected error type %i\n", err_aq);
        }

        //The rest of the header details
        hdr->ts      = rx_time;
        hdr->hz      = rx_time_hz;
        hdr->dev     = dev_id;
        hdr->port    = port_id;
        hdr->seq     = packet_seq;
        hdr->dropped = dropped;

        //Clean up the accounting
        dropped = 0;
        bytes_added += rx_bytes;

        ifassert(bytes_added > obuff_len){
            ch_log_fatal("Wrote beyond end of buffer %li > %li\n", rx_bytes, obuff_len);
        }

    }

finished:
    ch_log_debug1("Listener thread %i for %s exiting\n", lparams->ltid,
                lparams->nic_istream->name);


    //Remove any last headers that are waiting
    if(bytes_added == sizeof(blaze_hdr_t))
    {
        bytes_added = 0;
    }

    if(obuff){
        flush_buffer(rings[curr_ring], bytes_added, obuff_len, obuff);
    }

    ch_log_debug1("Listener thread %i for %s done.\n", lparams->ltid,
                lparams->nic_istream->name);

    //free(params); ??
    return NULL;
}
