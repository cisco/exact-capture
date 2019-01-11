/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     4 Aug 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  The writer thread listens to a collection of circular queues connected to
 *  the listener threads. It  takes blocks 4K aliged, blaze file formatted data,
 *  writes to disk as quickly as it can.
 */


#include <netinet/ip.h>
#include <limits.h>
#include <errno.h>

#include "exact-capture-writer.h"
#include "data_structs/blaze_file.h"

/**
 * This function writes out a pcap file header to the given ostream. It pads
 * the write so that it is 4K aligned.
 */
static inline eio_error_t write_pcap_header (eio_stream_t* ostream)
{
    char dummy_data[DISK_BLOCK];
    init_dummy_data(dummy_data, DISK_BLOCK);


    ch_log_debug1("Creating blaze file header...\n");
    char* blaze_head_block = aligned_alloc (DISK_BLOCK, DISK_BLOCK);

    ch_log_debug1("Block size=%li\n", DISK_BLOCK);

    blaze_file_hdr_t* hdr = (blaze_file_hdr_t*) blaze_head_block;
    hdr->magic         = BLAZE_FILE_MAGIC;
    hdr->version_major = BLAZE_FILE_VERSION_MAJOR;
    hdr->version_minor = BLAZE_FILE_VERSION_MINOR;
    hdr->linktype = DLT_EN10MB;

    ch_log_debug1("Blaze file hdr size=%li\n", sizeof(blaze_file_hdr_t));
    blaze_hdr_t* pkt_hdr = (blaze_hdr_t*) (hdr + 1);
    int64_t dummy_packet_len = DISK_BLOCK - sizeof(blaze_file_hdr_t)
            - sizeof(blaze_hdr_t);
    ch_log_debug1("Dummy blaze packet len = %li (%li - %li - %li)\n",
                 dummy_packet_len, DISK_BLOCK,
                 sizeof(blaze_file_hdr_t), sizeof(blaze_hdr_t));

    pkt_hdr->flags   = BLAZE_FLAG_IGNR;
    pkt_hdr->caplen  = dummy_packet_len;
    pkt_hdr->wirelen = 0;
    char* pkt_data = (char*) (pkt_hdr + 1);
    memcpy (pkt_data, dummy_data, dummy_packet_len);

    char* wr_buff = blaze_head_block;
    int64_t len = DISK_BLOCK;

    eio_error_t err = eio_wr_acq (ostream, &wr_buff, &len);
    if (err)
    {
        ch_log_error("Could not get writer buffer with unexpected error %i\n",
                     err);
        goto finished;
    }

    //Now flush to disk
    err = eio_wr_rel (ostream, DISK_BLOCK);
    if (err)
    {
        ch_log_error("Could not write to disk with unexpected error %i\n", err);
    }

finished:
    free (blaze_head_block);
    return err;
}



/**
 * The writer thread listens to a collection of rings for listener threads. It
 * takes blocks 4K aliged, pcap formatted data, updates the timestamps and
 * writes to disk as quickly as it can.
 */
void* writer_thread (void* params)
{

    wparams_t* wparams = params;
    ch_log_debug1("Starting writer thread for %s\n", wparams->disk_ostream->name);
    //Raise this thread prioirty
    if(nice(-15) == -1)
    {
        ch_log_warn("Failed to change thread priority."
                       "Performance my be affected! (%s)\n", strerror(errno));
    }


    eio_stream_t** rings = wparams->rings;
    int64_t rings_count  = wparams->rings_count;

    eio_stream_t* ostream  = wparams->disk_ostream;

    if (write_pcap_header(ostream))
    {
        ch_log_error("Could not open new output file\n");
        goto finished;
    }


    //**************************************************************************
    //Writer - Real work begins here!
    //**************************************************************************
    /*
    * We set the current wistream to be equal to the thread id, so that by
    * default, different writer threads start to listen to different listener
    * queues. The modulus (%) is here because number of writer threads is not
    * necessarily equal to number of listener threads. The number of listener
    * threads is equal to rings_count.
    */
    int64_t curr_ring = wparams->wtid % rings_count;

    char* rd_buff = NULL;
    int64_t rd_buff_len = 0;

    while (!*wparams->stop)
    {

        //Find a buffer
        for (; !*wparams->stop  ; curr_ring++)
        {

            //ch_log_debug3("Looking at istream %li/%li\n", curr_istream,
            //              num_istreams);
            curr_ring = curr_ring >= rings_count ? 0 : curr_ring;
            eio_stream_t* istream = rings[curr_ring];
            eio_error_t err = eio_rd_acq (istream, &rd_buff, &rd_buff_len,
                                          NULL, NULL);
            iflikely(err == EIO_ETRYAGAIN)
            {
                /* relax the CPU in this tight loop */
                __asm__ __volatile__ ("pause");
                continue; /* Look at the next ring */
            }
            ifassert(err != EIO_ENONE)
            {
                ch_log_error(
                        "Unexpected error %i trying to get istream buffer\n",
                        err);
                return NULL;
            }

            ch_log_debug2("Got buffer of size %li (0x%08x)\n", rd_buff_len,
                          rd_buff_len);
            ifassert(rd_buff_len == 0)
            {
                ch_log_error("Unexpected ring size of 0\n");
                goto finished;
            }

            break;
        }
        if (*wparams->stop) goto finished;

        /* At this point we have a buffer full of packets */


        /* Write that buffer to disk */
        eio_error_t err = eio_wr_acq (ostream, &rd_buff, &rd_buff_len);
        if (err)
        {
            ch_log_error( "Could not get writer buffer with unexpected error %i\n", err);
            if (err == EIO_ECLOSED)
            {
                goto finished;
            }
        }

        /* Now flush to disk */
        err = eio_wr_rel (ostream, rd_buff_len);
        if (err)
        {
            ch_log_error( "Could not release writer buffer with unexpected error %i\n", err);
            if (err == EIO_ECLOSED)
            {
                ch_log_error( "Disk is full. Exiting writer thread\n");
                goto finished;
            }
        }

        /* Release the istream */
        eio_stream_t* istream = rings[curr_ring];
        eio_rd_rel (istream);
        /* Make sure we look at the next ring next time for fairness */

        curr_ring++;

    }

    finished:
    /* Flush old buffer if it exists */
    ch_log_debug1("Writer thread %s exiting\n", wparams->disk_ostream->name);

    return NULL;
}
