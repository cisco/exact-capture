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


/* Copy a packet fragment from ibuff to obuff. Return the number of bytes copied*/
static inline int64_t cpy_frag(blaze_hdr_t* hdr, char* const obuff,
                               char* ibuff, int64_t ibuff_len, int64_t snaplen)
{
    int64_t added = 0;
    /* Only copy as much as the caplen */
    iflikely(hdr->wirelen < snaplen)
    {
        /*
         * Get the data out of the fragment, but don't copy more
         * than max_caplen
         */
        const int64_t copy_bytes = MIN(snaplen - hdr->wirelen, ibuff_len);
        memcpy (obuff, ibuff, copy_bytes);

        /* Do accounting and stats */
        hdr->caplen += copy_bytes;
        added = copy_bytes;
    }

    hdr->wirelen     += ibuff_len;
    stats->bytes_rx += ibuff_len;

    return added;
}


/* This func tries to rx one packet and returns the number of bytes RX'd.
 * The return may be zero if no packet was RX'd, or if there was an error */
static inline int64_t rx_packet ( eio_stream_t* istream,  char* const obuff,
        char* obuff_end, int64_t* dropped, int64_t* packet_seq,
        volatile bool* stop, int64_t snaplen )
{
#ifndef NOIFASSERT
    i64 rx_frags = 0;
#endif

    /* Set up a new pcap header */
    int64_t rx_b = 0;

    blaze_hdr_t* hdr = (blaze_hdr_t*) (obuff);
    rx_b += sizeof(blaze_file_hdr_t);
    ifassert(obuff + rx_b >= obuff_end)
        ch_log_fatal("Obuff %p + %li = %p will exceeded max %p\n", obuff, rx_b,
                     obuff + rx_b, obuff_end);

    /* Reset just the things that need to be incremented in the header */
    hdr->caplen  = 0;
    hdr->wirelen = 0;

    /* Try to RX the first fragment */
    eio_error_t err = EIO_ENONE;
    char* ibuff;
    int64_t ibuff_len;
    int64_t rx_time = 0;
    int64_t rx_time_hz = 0;
    for (int64_t tryagains = 0; ; stats->spins1_rx++, tryagains++)
    {
        err = eio_rd_acq (istream, &ibuff, &ibuff_len, &rx_time, &rx_time_hz);

        iflikely(err != EIO_ETRYAGAIN)
        {
            hdr->ts = rx_time;
            hdr->hz = rx_time_hz;
            break;
        }

        /* Make sure we don't wait forever */
        ifunlikely(*stop || tryagains >= (1024 * 1024))
        {
            return 0;
        }

    }

    /* Note, no use of lstop: don't stop in the middle of RX'ing a packet */
    for (;; err = eio_rd_acq (istream, &ibuff, &ibuff_len, NULL, NULL),
            stats->spinsP_rx++)
    {
#ifndef NOIFASSERT
        rx_frags++;
#endif
        switch(err)
        {
            case EIO_ETRYAGAIN:
                /* Most of the time will be spent here (hopefully..) */
                continue;

            /* Got a fragment. There are some more fragments to come */
            case EIO_EFRAG_MOR:
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
                break;

            /* Got a complete frame. There are no more fragments */
            case EIO_ENONE:
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
                complete_packet(hdr, BLAZE_FLAG_NONE, dropped, dev_id, port_id,
                                *packet_seq);
                break;

            /* Got a corrupt (CRC) frame. There are no more fragments */
            case EIO_EFRAG_CPT:
                stats->errors++;
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
                complete_packet(hdr, BLAZE_FLAG_CRPT,dropped, dev_id, port_id,
                                *packet_seq);
                break;

            /* Got an aborted frame. There are no more fragments */
            case EIO_EFRAG_ABT:
                stats->errors++;
                rx_b += cpy_frag(hdr,obuff + rx_b,ibuff,ibuff_len, snaplen);
                complete_packet(hdr, BLAZE_FLAG_ABRT,dropped, dev_id,  port_id,
                                *packet_seq);
                break;

            /* **** UNRECOVERABLE ERRORS BELOW THIS LINE **** */
            /* Software overflow happened, we're dead. Exit the function */
            case EIO_ESWOVFL:
                stats->swofl++;
                /* Forget what we were doing, just exit */
                eio_rd_rel(istream);

                /*Skip to a good place in the receive buffer*/
                err = eio_rd_acq(istream, NULL, NULL, NULL, NULL);
                eio_rd_rel(istream);
                return 0;

            /* Hardware overflow happened, we're dead. Exit the function */
            case EIO_EHWOVFL:
                stats->hwofl++;
                /* Forget what we were doing, just exit */
                eio_rd_rel(istream);

                /*Skip to a good place in the receive buffer*/
                err = eio_rd_acq(istream, NULL, NULL, NULL, NULL);
                eio_rd_rel(istream);
                return 0;

            default:
                ch_log_fatal("Unexpected error code %i\n", err);
        }

        /* When we get here, we have fragment(s), so we need to release the read
         * pointer, but this may fail. In which case we drop everything */
        if(eio_rd_rel(istream)){
            return 0;
        }

#ifndef NOIFASSERT
        ifassert(obuff + rx_b >= obuff_end)
            ch_log_fatal("Obuff %p + %li = %p exceeds max %p\n",
                     obuff, rx_b, obuff + rx_b, obuff_end);
#endif


        /* If there are no more frags to come, then we're done! */
        if(err != EIO_EFRAG_MOR){
            stats->packets_rx++;
            (*packet_seq) += 1;
            return rx_b;
        }

        /* There are more frags, go again!*/
    }

    /* Unreachable */
    ch_log_fatal("Error: Reached unreachable code!\n");
    return -1;
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

    int64_t dropped = 0;
    int64_t packet_seq = 0;

    const int64_t blaze_hdr_size = (int64_t)sizeof(blaze_hdr_t);
    const int64_t max_blaze_rec = lparams->snaplen + blaze_hdr_size;


    while (!*lparams->stop)
    {
        /*
         * The following code will flush the output buffer and send it across to
         * the writer thread and then obtain a new output buffer. It does so in
         * one of 2 circumstances:
         *
         * 1) There is less than 1 full packet plus a pcap_pkt_hdr_t left worth
         * of space in the output buffer. The pcap_pkthdr_t is required to ensure
         * there is enough space for a dummy packet to pad out the rest of this
         * buffer to be block aligned size for high speed writes to disk.
         *
         * 2) There has been a timeout and there are packets waiting (not just a
         * pre-prepared pcap header. We do this so that packets don't wait too
         * long before timestamp conversions and things happen.
         */

        const bool buff_full = obuff_len - bytes_added <  max_blaze_rec * 2;
        const bool timed_out = now >= timeout && bytes_added > blaze_hdr_size;
        ifunlikely( obuff && (buff_full || timed_out))
        {
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

        while(!obuff && !*lparams->stop)
        {
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
            iflikely(!obuff)
            {
                ch_log_debug2("No buffer, dropping packet..\n");
                eio_error_t err = EIO_ENONE;
                err = eio_rd_acq(nic, NULL, NULL, NULL, NULL);
                iflikely(err == EIO_ENONE)
                {
                    stats->dropped++;
                    dropped++;
                    packet_seq++;

                }
                ifunlikely(err == EIO_ESWOVFL)
                {
                    stats->swofl++;
                }
                err = eio_rd_rel(nic);
                if(err == EIO_ESWOVFL )
                {
                    stats->swofl++;
                }
            }
        }

        if(*lparams->stop){
            goto finished;
        }

        /* This func tries to rx one packet it returns the number of bytes RX'd
         * this may be zero if no packet was RX'd, or if there was an error */
        const int64_t rx_bytes = rx_packet(nic, obuff + bytes_added, obuff +
                                           obuff_len, &dropped, &packet_seq,
                                           lparams->stop, lparams->snaplen);

        ifunlikely(rx_bytes == 0)
        {
            /*Do this here so we don't do it too often. Only when we're
             * waiting around with nothing to do */
            eio_nowns(&now);
        }
        ifassert(rx_bytes > max_blaze_rec)
        {
            ch_log_fatal("RX %liB > full packet size %li\n",
                         rx_bytes, max_blaze_rec);

        }

        bytes_added += rx_bytes;

        ifassert(bytes_added > obuff_len)
        {
            ch_log_fatal("Wrote beyond end of buffer %li > %li\n",
                         rx_bytes, obuff_len);
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
