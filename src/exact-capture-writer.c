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


#include "exact-capture-writer.h"
#include "data_structs/expcap.h"

#include <netinet/ip.h>


extern volatile bool wstop;
extern const bool nsec_pcap;
extern int64_t max_pkt_len;
extern int64_t max_file_size;
extern int64_t max_pcap_rec;

extern wstats_t wstats[MAX_OTHREADS];



/**
 * Helper function to set the writer fd into "O_DIRECT" mode. This mode bypasses
 * the kernel and syncs the buffers directly to the disk. However, it requires
 * that data is block aligned, a multiple of block size and written to a block
 * aligned offset. It's hard to know what the right block size is sometimes 512B
 * sometimes 4kB. For simplicity, 4kB is assumed.
 */
int set_direct (int desc, bool on)
{
    //ch_log_warn("O_DIRECT=%i\n", on);
    int oldflags = fcntl (desc, F_GETFL, 0);
    if (oldflags == -1)
        return -1;

    if (on)
        oldflags |= O_DIRECT;
    else
        oldflags &= ~O_DIRECT;

    return fcntl (desc, F_SETFL, oldflags);
}


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

/*
 * Open a new output file with the path "dest". An ISO timestamp is added to
 * the path and a PCAP header written into the file.
 */
eio_error_t open_file (char* dest, bool null_ostream,
                       eio_stream_t** ostream, int64_t file_id)
{

    char final_format[1024] = {0};
    snprintf(final_format, 1024, "%s-%li.expcap", dest, file_id  );


    /* Buffers are supplied buy the reader so no internal buffer is needed */
    const int64_t write_buff_size = 0;
    ch_log_debug3("Opening disk file %s\n", final_format);
    eio_args_t outargs = { 0 };
    outargs.type = EIO_FILE;

    outargs.args.file.filename = final_format;
    outargs.args.file.read_buff_size = 0;      //We don't read from this stream
    outargs.args.file.write_buff_size = write_buff_size;
    eio_error_t err = eio_new (&outargs, ostream);
    if (err)
    {
        ch_log_error("Could not create writer output %s\n", dest);
        goto finished;
    }

    /* Replace the output stream with a null stream, for testing */
    if (null_ostream)
    {
        ch_log_debug1("Creating null output stream in place of disk name: %s\n",
                    dest);
        outargs.type = EIO_DUMMY;
        outargs.args.dummy.read_buff_size = 0;   /* We don't read form this stream */
        outargs.args.dummy.write_buff_size = write_buff_size;
        err = eio_new (&outargs, ostream);
        if (err)
        {
            ch_log_error("Could not create writer output %s\n", dest);
            goto finished;
        }
    }

    set_direct ((*ostream)->fd, true);
    err = write_pcap_header ((*ostream), nsec_pcap, max_pkt_len);

    finished:
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
    ch_log_debug1("Setting up ostream %s\n", wparams->destination);

    CH_VECTOR(cstr)* ifaces = wparams->interfaces;
    char* dest = wparams->destination;

    char bring_name[BRING_NAME_LEN + 1]; /* +1 = space for null terminator */

    const int64_t num_istreams = ifaces->count;
    istream_state_t istreams[num_istreams];
    for (int iface_idx = 0; iface_idx < num_istreams; iface_idx++)
    {
        istreams[iface_idx].dev_id   = wparams->exanic_dev_id[iface_idx];
        istreams[iface_idx].port_num = wparams->exanic_port_id[iface_idx];

        const char* iface = ifaces->first[iface_idx];

        bzero (bring_name, BRING_NAME_LEN);
        ch_word bring_name_chars = sprintf(bring_name,"EXCAP_%04X", getpid());
        for (size_t i = 0;
                i < strlen (iface) && bring_name_chars < BRING_NAME_LEN; i++)
        {
            if (isalnum(iface[i]))
            {
                bring_name[bring_name_chars] = iface[i];
                bring_name_chars++;
            }
        }

        bring_name[bring_name_chars] = '_';
        bring_name_chars++;

        for (size_t i = 0;
                i < strlen (dest) && bring_name_chars < BRING_NAME_LEN; i++)
        {
            if (isalnum(dest[i]))
            {
                bring_name[bring_name_chars] = dest[i];
                bring_name_chars++;
            }
            else{
                bring_name[bring_name_chars] = '_';
                bring_name_chars++;
            }
        }


        eio_stream_t* istream = NULL;
        eio_args_t inargs = { 0 };
        ch_log_debug1("Connecting to bring input stream with name: %s\n", bring_name);
        inargs.type = EIO_BRING;
        inargs.args.bring.filename = bring_name;
        inargs.args.bring.isserver = 0;
        if (eio_new (&inargs, &istream))
        {
            ch_log_error("Could not create reader istream\n");
            return NULL;
        }

        /* Replace the bring with a null stream for testing, but make sure the
         * bring exists  so that other threads will continue */
        if (wparams->dummy_istream)
        {
            ch_log_debug1(
                    "Creating null input stream in place of bring name: %s\n",
                    bring_name);
            inargs.type = EIO_DUMMY;

            /* This must be a multiple of the disk block size (assume 4kB)
             * This value is imported across by the bring, so please be careful to
             * keep it up to date*/
            const int64_t bring_slot_size = 2 * 1024 * 1024; /* 1MB */
            inargs.args.dummy.read_buff_size = bring_slot_size;
            inargs.args.dummy.rd_mode = DUMMY_MODE_EXPCAP;
            inargs.args.dummy.expcap_bytes = 512;
            inargs.args.dummy.write_buff_size = 0;
            if (eio_new (&inargs, &istream))
            {
                ch_log_error("Could not create writer istream\n");
                return NULL;
            }
        }

        istreams[iface_idx].istream = istream;

        /*
         * The writer thread needs to know which exanic the data came from
         * so that it can do time stamp conversions
         */
        eio_stream_t* exa_stream = NULL;
        eio_args_t exaargs = { 0 };
        exaargs.type = EIO_EXA;
        exaargs.args.exa.interface_rx = (char*) iface;
        exaargs.args.exa.interface_tx = NULL;
        int err = eio_new (&exaargs, &exa_stream);
        if (err)
        {
            ch_log_error("Could not create listener input stream %s\n");
            return NULL;
        }
        istreams[iface_idx].exa_istream = exa_stream;
    }

    eio_stream_t* ostream = NULL;
    if (open_file (dest, wparams->dummy_ostream, &ostream, 0))
    {
        ch_log_error("Could not open new output file\n");
        goto finished;
    }


    //**************************************************************************
    //Writer - Real work begins here!
    //**************************************************************************

    int64_t curr_istream = wparams->wtid;
    char* rd_buff = NULL;
    int64_t rd_buff_len = 0;
    int64_t bytes_written = 0;

    wstats_t* stats = &wstats[curr_istream];

    while (!wstop)
    {

        //Find a buffer
        for (; !wstop; curr_istream++, stats->spins++)
        {
            //ch_log_debug3("Looking at istream %li/%li\n", curr_istream,
            //              num_istreams);
            curr_istream = curr_istream >= num_istreams ? 0 : curr_istream;
            eio_stream_t* istream = istreams[curr_istream].istream;
            eio_error_t err = eio_rd_acq (istream, &rd_buff, &rd_buff_len,
                                          NULL);
            if (err == EIO_ETRYAGAIN)
            {
                /* relax the CPU in this tight loop */
                __asm__ __volatile__ ("pause");
                continue; /* Look at the next ring */
            }
            if (err != EIO_ENONE)
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
                ch_log_error("Unexpected packet size of 0\n");
                goto finished;
            }

            break;
        }
        if (wstop) goto finished;

        /* At this point we have a buffer full of packets */


        /* Update the timestamps / stats in the packets */
        pcap_pkthdr_t* pkt_hdr = (pcap_pkthdr_t*) rd_buff;
        expcap_pktftr_t* pkt_ftr = NULL;
        eio_stream_t* exa_istream = istreams[curr_istream].exa_istream;
        struct exanic_timespecps tsps = {0,0};

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
            const exanic_cycles_t ts_cycles = pkt_hdr->ts.raw;
            exa_rxcycles_to_timespecps(exa_istream, ts_cycles, &tsps);

            /* Assign the corrected timestamp from one of the above modes */
            pkt_hdr->ts.ns.ts_nsec = tsps.tv_psec / 1000;
            pkt_hdr->ts.ns.ts_sec =  tsps.tv_sec;

            pkt_ftr->ts_secs  = tsps.tv_sec;
            pkt_ftr->ts_psecs = tsps.tv_psec;

            /* Skip to the next header, these should have been preloaded by now*/
            pkt_hdr = (pcap_pkthdr_t*)pkt_hdr_next;
        }



        /* Give the input buffer over to the outputs stream (zero copy)*/
        eio_error_t err = eio_wr_acq (ostream, &rd_buff, &rd_buff_len, NULL);
        if (err)
        {
            ch_log_error(
                    "Could not get writer buffer with unexpected error %i\n",
                    err);
            if (err == EIO_ECLOSED)
            {
                goto finished;
            }
        }

        /* Now flush to disk */
        eio_wr_rel (ostream, rd_buff_len, NULL);
        bytes_written += rd_buff_len;

        /* Release the istream */
        eio_stream_t* istream = istreams[curr_istream].istream;
        eio_rd_rel (istream, NULL);
        /* Make sure we look at the next ring next time for fairness */
        curr_istream++;

        /*  Stats */
        stats->dbytes += rd_buff_len;

        /* Is the file too big? Make a new one! */
        ifunlikely(max_file_size > 0 && bytes_written >= max_file_size)
        {
            eio_des (ostream);
            if (open_file (dest, wparams->dummy_ostream, &ostream,
                           ++istreams[curr_istream].file_id ))
            {
                ch_log_error("Could not open new output file\n");
                goto finished;
            }
            bytes_written = 0;
        }
    }

    finished:
    /* Flush old buffer if it exists */
    ch_log_debug1("Writer thread %s exiting\n", wparams->destination);

    return NULL;
}
