/*
 * Copyright (c) 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     1 March 2018
 *  Author:      Matthew P. Grosvenor
 *  Description: A tool for exacting pcaps form expcap files. It can also be
 *               used to filter expcaps, removing dummy packets and including
 *               only packets from a given device and port.
 *
 */


#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/timing/timestamp.h>
#include <chaste/utils/util.h>

#include "src/data_structs/pcap-structures.h"
#include "src/data_structs/expcap.h"
#include "tools/data_structs/pkt_buff.h"

USE_CH_LOGGER_DEFAULT; //(CH_LOG_LVL_DEBUG3, true, CH_LOG_OUT_STDERR, NULL);
USE_CH_OPTIONS;

bool lstop = 0;

static struct
{
    CH_VECTOR(cstr)* reads;
    char* write;
    ch_word max_file;
    ch_word max_count;
    char* format;
    ch_word usec;
    ch_word snaplen;
    ch_word port;
    ch_word device;
    ch_bool all;
    ch_bool skip_runts;
} options;

enum out_format_type {
    EXTR_OPT_FORM_UNKNOWN,
    EXTR_OPT_FORM_PCAP,
    EXTR_OPT_FORM_EXPCAP
};

typedef struct {
    char* cmdline;
    enum out_format_type type;
} out_format_t;


#define OUT_FORMATS_COUNT 5
out_format_t out_formats[5] = {
        {"pcap",  EXTR_OPT_FORM_PCAP},
        {"PCAP",  EXTR_OPT_FORM_PCAP},
        {"expcap",EXTR_OPT_FORM_EXPCAP},
        {"exPCAP",EXTR_OPT_FORM_EXPCAP},
        {"EXPCAP",EXTR_OPT_FORM_EXPCAP}
};


/*
 * Signal handler tells all threads to stop, but if you can force exit by
 * sending a second signal
 */
void signal_handler (int signum)
{
    ch_log_warn("Caught signal %li, shutting down\n", signum);
    if (lstop == 1)
    {
        ch_log_fatal("Hard exit\n");
    }
    lstop = 1;
}

/* Return packet with earliest timestamp */
int64_t min_packet_ts(int64_t buff_idx_lhs, int64_t buff_idx_rhs, pkt_buff_t* buffs)
{
    ch_log_debug1("checking minimum pcaksts on %li vs %li at %p\n", buff_idx_lhs, buff_idx_rhs, buffs);

#ifndef NDEBUG
    pcap_pkthdr_t* lhs_hdr = buffs[buff_idx_lhs].hdr;
    pcap_pkthdr_t* rhs_hdr = buffs[buff_idx_rhs].hdr;
    const int64_t lhs_caplen = lhs_hdr->caplen;
    const int64_t rhs_caplen = rhs_hdr->caplen;
    ch_log_debug1("lhr_caplen=%li, rhs_caplen=%li\n", lhs_caplen, rhs_caplen);
#endif

    expcap_pktftr_t* lhs_ftr = buffs[buff_idx_lhs].ftr;
    expcap_pktftr_t* rhs_ftr = buffs[buff_idx_rhs].ftr;

    ch_log_debug1("lhs ts = %lu.%lu vs rhs ts =%lu.%lu\n",
                  (uint64_t)lhs_ftr->ts_secs, (uint64_t)lhs_ftr->ts_psecs,
                  (uint64_t)rhs_ftr->ts_secs, (uint64_t)rhs_ftr->ts_psecs);

    if(lhs_ftr->ts_secs < rhs_ftr->ts_secs)
    {
        return buff_idx_lhs;
    }

    if(lhs_ftr->ts_secs > rhs_ftr->ts_secs)
    {
        return buff_idx_rhs;
    }

    /* Here the seconds components are the same */
    if(lhs_ftr->ts_psecs < rhs_ftr->ts_psecs)
    {
        return buff_idx_lhs;
    }

    if(lhs_ftr->ts_psecs > rhs_ftr->ts_psecs)
    {
        return buff_idx_rhs;
    }

    return buff_idx_lhs;
}

/**
 * Main loop sets up threads and listens for stats / configuration messages.
 */
int main (int argc, char** argv)
{
    signal (SIGHUP, signal_handler);
    signal (SIGINT, signal_handler);
    signal (SIGPIPE, signal_handler);
    signal (SIGALRM, signal_handler);
    signal (SIGTERM, signal_handler);


//    ch_opt_name("Exact Extract");
//    ch_opt_short_description("Extracts PCAP and exPCAP files out of exact cap ecap files.");

    ch_opt_addSU (CH_OPTION_UNLIMTED, 'i', "input",    "exact-capture expcap files to extract from", &options.reads);
    ch_opt_addsu (CH_OPTION_REQUIRED, 'w', "write",    "Destination to write output to", &options.write);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'p', "port",     "Port number to extract", &options.port,-1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'd', "device",   "Device number to extract", &options.device,-1);
    ch_opt_addbi (CH_OPTION_FLAG,     'a', "all",      "Output packets from all ports/devices", &options.all, false);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'f', "format",   "Output format. Valid values are [pcap, expcap]", &options.format, "expcap");
    ch_opt_addii (CH_OPTION_OPTIONAL, 'c', "count",    "Maxium number of packets to output (<=0 means no max)", &options.max_count, 0);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'M', "maxfile",  "Maximum file size in MB (<=0 means no max)", &options.max_file, 0); //128M
    ch_opt_addii (CH_OPTION_OPTIONAL, 'u', "usecpcap", "PCAP output in microseconds", &options.usec, false);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'S', "snaplen",  "Maximum packet length", &options.snaplen, 1518);
    ch_opt_addbi (CH_OPTION_FLAG,     'r', "skip-runts", "Skip runt packets", &options.skip_runts, false);
    ch_opt_parse (argc, argv);

    options.max_file *= 1024 * 1024; /* Convert max file size from MB to B */

    ch_log_settings.log_level = CH_LOG_LVL_DEBUG1;

    if(!options.all && (options.port == -1 || options.device == -1))
    {
        ch_log_fatal("Must supply a port and device number (--dev /--port) or use --all\n");
    }

    if(options.reads->count == 0){
        ch_log_fatal("Please supply input files\n");
    }

    ch_log_debug1("Starting packet extractor...\n");

    /* Parse the format type */
    enum out_format_type format = EXTR_OPT_FORM_UNKNOWN;
    for(int i = 0; i < OUT_FORMATS_COUNT; i++ ){
        if(strncmp(options.format, out_formats[i].cmdline, strlen(out_formats[i].cmdline))== 0 ){
            format = out_formats[i].type;
        }
    }

    if(format == EXTR_OPT_FORM_UNKNOWN){
        ch_log_fatal("Unknown output format type %s\n", options.format );
    }

    pkt_buff_t wr_buff;
    buff_error_t buff_err;
    /* No need for conserve_fds yet. */
    buff_err = pkt_buff_init(options.write, &wr_buff, options.snaplen, options.max_file, options.usec, false);
    if(buff_err != BUFF_ENONE){
        ch_log_fatal("Failed to initialize write buffer: %s\n", buff_strerror(buff_err));
    }

    /* Allocate N read buffers where */
    const int64_t rd_buffs_count = options.reads->count;
    pkt_buff_t* rd_buffs = (pkt_buff_t*)calloc(rd_buffs_count, sizeof(pkt_buff_t));
    if(!rd_buffs){
        ch_log_fatal("Could not allocate memory for read buffers table\n");
    }
    for(int i = 0; i < rd_buffs_count; i++){
        buff_err = pkt_buff_from_file(&rd_buffs[i], options.reads->first[i]);
        if(buff_err != BUFF_ENONE){
            ch_log_fatal("Failed to read %s into a pkt_buff_t: %s\n", options.reads->first[i], buff_strerror(buff_err));
        }
    }

    ch_log_info("starting main loop with %li buffers\n", rd_buffs_count);

    /* At this point we have read buffers ready for reading data and a write
     * buffer for outputting and file handles ready to go. Fun starts now.
     * Skip over the PCAP headers in each file */
    /* Process the merge */
    ch_log_info("Beginning merge\n");
    if(buff_err != BUFF_ENONE){
        ch_log_fatal("Failed to create new file for writer buff: %s\n", buff_strerror(buff_err));
    }

    int64_t packets_total   = 0;
    int64_t dropped_padding = 0;
    int64_t dropped_runts   = 0;
    int64_t dropped_errors  = 0;
    pkt_info_t pkt_info;
    i64 count = 0;
    for(int i = 0; !lstop ; i++)
    {
begin_loop:
        ch_log_debug1("\n%i ######\n", i );

        /* Check all the FD in case we've read everything  */
        ch_log_debug1("Checking for EOF\n");
        bool all_eof = true;
        for(int i = 0; i < rd_buffs_count; i++){
            all_eof &= pkt_buff_eof(&rd_buffs[i]);
        }
        if(all_eof){
            ch_log_info("All files empty, exiting now\n");
            break;
        }


        ch_log_debug1("Looking for minimum timestamp index on %i buffers\n",
                      rd_buffs_count);
        /* Find the read buffer with the earliest timestamp */
        int64_t min_idx          = 0;
        for(int buff_idx = 0; buff_idx < rd_buffs_count; buff_idx++ ){
            if(pkt_buff_eof(&rd_buffs[buff_idx])){
                if(min_idx == buff_idx){
                    min_idx = buff_idx+1;
                }
                continue;
            }

            pkt_info = pkt_buff_next_packet(&rd_buffs[buff_idx]);
            switch(pkt_info){
            case PKT_PADDING:
                ch_log_debug1("Skipping over packet %i (buffer %i) because len=0\n",pkt_idx , buff_idx);
                dropped_padding++;
                buff_idx--;
                continue;
            case PKT_RUNT:
                ch_log_debug1("Skipping over runt frame %i (buffer %i) \n", pkt_idx, buff_idx);
                dropped_runts++;
                if(options.skip_runts){
                    buff_idx--;
                    continue;
                }
                break;
            case PKT_ERROR:
                ch_log_debug1("Skipping over damaged packet %i (buffer %i) because flags = 0x%02x\n",
                              pkt_idx, buff_idx, pkt_ftr->flags);
                dropped_errors++;
                buff_idx--;
                continue;
            case PKT_EOF:
                ch_log_warn("End of file \"%s\"\n", pkt_buff_get_filename(&rd_buffs[buff_idx]));
                goto begin_loop;
                break;
            case PKT_OK:
                break;
            }

            min_idx = min_packet_ts(min_idx, buff_idx, rd_buffs);
            ch_log_debug1("Minimum timestamp index is %i \n", min_idx);
        }

        pcap_pkthdr_t* pkt_hdr = rd_buffs[min_idx].hdr;
        pcap_pkthdr_t wr_pkt_hdr;
        int64_t packet_copy_bytes = MIN(options.snaplen, (ch_word)pkt_hdr->caplen - (ch_word)sizeof(expcap_pktftr_t));
#ifndef NDEBUG
        const int64_t pcap_record_bytes = sizeof(pcap_pkthdr_t) + packet_copy_bytes + sizeof(expcap_pktftr_t);
#endif

        /* TODO add more comprehensive filtering in here */

        /* Extract the timestamp from the footer */
        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)((char*)(pkt_hdr + 1)
                + pkt_hdr->caplen - sizeof(expcap_pktftr_t));
        const uint64_t secs          = pkt_ftr->ts_secs;
        const uint64_t psecs         = pkt_ftr->ts_psecs;
        const uint64_t psecs_mod1000 = psecs % 1000;
        const uint64_t psecs_floor   = psecs - psecs_mod1000;
        const uint64_t psecs_rounded = psecs_mod1000 >= 500 ? psecs_floor + 1000 : psecs_floor ;
        const uint64_t nsecs         = psecs_rounded / 1000;

        wr_pkt_hdr.len = pkt_hdr->len;
        wr_pkt_hdr.ts.ns.ts_sec = secs;
        wr_pkt_hdr.ts.ns.ts_nsec = nsecs;

        /* Update the packet header in case snaplen is less than the original capture */
        wr_pkt_hdr.caplen = packet_copy_bytes;

        expcap_pktftr_t wr_pkt_ftr;
        /* Include the footer (if we want it) */
        if(format == EXTR_OPT_FORM_EXPCAP){
            wr_pkt_ftr = *pkt_ftr;
            wr_pkt_ftr.ts_secs = secs;
            wr_pkt_ftr.ts_psecs = psecs;
        }

        /* Copy the packet header, and upto snap len packet data bytes */
        ch_log_debug1("Copying %li bytes from buffer %li at index=%li into buffer at offset=%li\n", pcap_record_bytes, min_idx, rd_buffs[min_idx].pkt_idx, wr_buff.offset);

        buff_err = pkt_buff_write(&wr_buff, &wr_pkt_hdr, rd_buffs[min_idx].pkt, packet_copy_bytes, &wr_pkt_ftr);
        if(buff_err != BUFF_ENONE){
            ch_log_fatal("Failed to write packet data: %s\n", buff_strerror(buff_err));
        }

        packets_total++;
        count++;
        if(options.max_count && count >= options.max_count){
            break;
        }
    }

    ch_log_info("Finished writing %li packets total (Runts=%li, Errors=%li, Padding=%li). Closing\n", packets_total, dropped_runts, dropped_errors, dropped_padding);

    buff_err = pkt_buff_flush_to_disk(&wr_buff);
    if(buff_err != BUFF_ENONE){
        ch_log_fatal("Failed to flush buffer to disk: %s\n", buff_strerror(buff_err));
    }

    return 0;
}
