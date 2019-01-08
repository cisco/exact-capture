/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     4 Aug 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  The writer thread listens to a collection of circular queues connected to
 *  the listener threads. It  takes blocks 4K aliged, pcap formatted data,
 *  updates the timestamps and writes to disk as quickly as it can using
 *  O_DIRECT mode.
 */


#include <netinet/ip.h>
#include <limits.h>
#include <errno.h>

#include "exact-capture-writer.h"
#include "data_structs/expcap.h"

extern volatile bool wstop;
extern const bool nsec_pcap;
extern int64_t max_pkt_len;
extern int64_t max_file_size;
extern int64_t max_pcap_rec;

extern wstats_t wstats[MAX_WTHREADS];





/**
 * This function writes out a pcap file header to the given ostream. It pads
 * the write so that it is 4K aligned.
 */
static inline eio_error_t write_pcap_header (eio_stream_t* ostream,
                                             bool nsec_pcap, int16_t snaplen)
{

    char dummy_data[DISK_BLOCK];
    init_dummy_data(dummy_data, DISK_BLOCK);


    ch_log_debug1("*** Creating pcap header\n");
    char* pcap_head_block = aligned_alloc (DISK_BLOCK, DISK_BLOCK);

    ch_log_debug1("Block size=%li\n", DISK_BLOCK);

    pcap_file_header_t* hdr = (pcap_file_header_t*) pcap_head_block;
    hdr->magic = nsec_pcap ? NSEC_TCPDUMP_MAGIC : TCPDUMP_MAGIC;
    hdr->version_major = PCAP_VERSION_MAJOR;
    hdr->version_minor = PCAP_VERSION_MINOR;
    hdr->thiszone = 0;
    hdr->sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr->snaplen = snaplen;
    hdr->linktype = DLT_EN10MB;

    ch_log_debug1("*** PCAP HDR size=%li\n", sizeof(pcap_file_header_t));

    pcap_pkthdr_t* pkt_hdr = (pcap_pkthdr_t*) (hdr + 1);
    int64_t dummy_packet_len = DISK_BLOCK - sizeof(pcap_file_header_t)
            - sizeof(pcap_pkthdr_t);
    ch_log_debug1("*** Dummy pcaket len = %li (%li - %li - %li)\n",
                 dummy_packet_len, DISK_BLOCK,
                 sizeof(pcap_file_header_t), sizeof(pcap_pkthdr_t));
    pkt_hdr->caplen = dummy_packet_len;
    pkt_hdr->len = 0; //dummy_packet_len; // 0; make 0 to invalidate
    pkt_hdr->ts.ns.ts_sec = 0;
    pkt_hdr->ts.ns.ts_nsec = 0;
    char* pkt_data = (char*) (pkt_hdr + 1);
    memcpy (pkt_data, dummy_data, dummy_packet_len);

    char* wr_buff = pcap_head_block;
    int64_t len = DISK_BLOCK;
    eio_error_t err = eio_wr_acq (ostream, &wr_buff, &len, NULL);
    if (err)
    {
        ch_log_error("Could not get writer buffer with unexpected error %i\n",
                     err);
        goto finished;
    }

    //Now flush to disk
    err = eio_wr_rel (ostream, DISK_BLOCK, NULL);
    if (err)
    {
        ch_log_error("Could not write to disk with unexpected error %i\n", err);
    }

    finished: free (pcap_head_block);
    return err;
}



/**
 * The writer thread listens to a collection of rings for listener threads. It
 * takes blocks 4K aliged, pcap formatted data, updates the timestamps and
 * writes to disk as quickly as it can.
 */
void* writer_thread (void* params)
{

    writer_params_t* wparams = params;
    ch_log_debug1("Starting writer thread for %s\n", wparams->disk_ostream->name);
    //Raise this thread prioirty
    if(nice(-15) < 0)
    {
        ch_log_warn("Failed to change thread priority."
                       "Performance my be affected! (%s)\n", strerror(errno));
    }


    ring_istream_t* rings = wparams->rings;
    int64_t rings_count   = wparams->rings_count;

    eio_stream_t* ostream  = wparams->disk_ostream;

    if (write_pcap_header (ostream, nsec_pcap, max_pkt_len))
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

    wstats_t* stats = &wstats[curr_ring];

    while (!wstop)
    {

        //Find a buffer
        for (; !wstop; curr_ring++, stats->spins++)
        {

            //ch_log_debug3("Looking at istream %li/%li\n", curr_istream,
            //              num_istreams);
            curr_ring = curr_ring >= rings_count ? 0 : curr_ring;
            eio_stream_t* istream = rings[curr_ring].ring_istream;
            eio_error_t err = eio_rd_acq (istream, &rd_buff, &rd_buff_len,
                                          NULL);
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

            ch_log_debug1("Got buffer of size %li (0x%08x)\n", rd_buff_len,
                          rd_buff_len);
            ifassert(rd_buff_len == 0)
            {
                ch_log_error("Unexpected ring size of 0\n");
                goto finished;
            }

            break;
        }
        if (wstop) goto finished;

        /* At this point we have a buffer full of packets */


        /* Update the timestamps / stats in the packets */
        pcap_pkthdr_t* pkt_hdr = (pcap_pkthdr_t*) rd_buff;
        expcap_pktftr_t* pkt_ftr = NULL;
        eio_stream_t* nic_istream = rings[curr_ring].nic_istream;
        timespecps_t tsps = {0,0};

#if !defined(NDEBUG) || !defined(NOIFASSERT)
        int64_t hdrs_count = -1;
#endif

        for(; (char*) pkt_hdr < rd_buff + rd_buff_len;  )
        {
            ch_log_debug2("Looking at packet %i, offset %iB, len=%li ts=%li.%09li\n",
                          ++hdrs_count, ((char*)pkt_hdr-rd_buff), pkt_hdr->caplen,
                          pkt_hdr->ts.ns.ts_sec, pkt_hdr->ts.ns.ts_nsec);

            /* preload for performance */
            const pcap_pkthdr_t *  pkt_hdr_next = (pcap_pkthdr_t*)PKT_OFF(pkt_hdr,pkt_hdr->caplen);
            __builtin_prefetch(&pkt_hdr_next->caplen);

            iflikely(pkt_hdr->len)
            {
                //We don't need to count this packet beacuse it's a dummy
                stats->packets++;
                stats->pcbytes += pkt_hdr->caplen - sizeof(pcap_pkthdr_t);
                stats->plbytes += pkt_hdr->len;
            }

#ifndef NOIFASSERT
            ifassert(pkt_hdr->caplen > max_pcap_rec)
            {
                ch_log_fatal("Packet at %li is %liB, max length is %liB\n",
                             hdrs_count, pkt_hdr->caplen, max_pcap_rec);
            }
#endif


            pkt_ftr = (expcap_pktftr_t*)((char*)pkt_hdr_next - sizeof(expcap_pktftr_t));

            /* Convert the timestamp from cycles into UTC */
            exanic_cycles_t ts_cycles = pkt_hdr->ts.raw;
            eio_time_to_tsps(nic_istream, &ts_cycles, &tsps);

            /* Assign the corrected timestamp from one of the above modes */
            pkt_hdr->ts.ns.ts_nsec = tsps.psecs / 1000;
            pkt_hdr->ts.ns.ts_sec =  tsps.secs;

            pkt_ftr->ts_secs  = tsps.secs;
            pkt_ftr->ts_psecs = tsps.psecs;

            /* Skip to the next header, these should have been preloaded by now*/
            pkt_hdr = (pcap_pkthdr_t*)pkt_hdr_next;
        }


        eio_error_t err = eio_wr_acq (ostream, &rd_buff, &rd_buff_len, NULL);
        if (err)
        {
            ch_log_error( "Could not get writer buffer with unexpected error %i\n", err);
            if (err == EIO_ECLOSED)
            {
                goto finished;
            }
        }

        /* Now flush to disk */
        err = eio_wr_rel (ostream, rd_buff_len, NULL);
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
        eio_stream_t* istream = rings[curr_ring].ring_istream;
        eio_rd_rel (istream, NULL);
        /* Make sure we look at the next ring next time for fairness */

        curr_ring++;

        /*  Stats */
        stats->dbytes += rd_buff_len;

    }

    finished:
    /* Flush old buffer if it exists */
    ch_log_debug1("Writer thread %s exiting\n", wparams->disk_ostream->name);

    return NULL;
}
