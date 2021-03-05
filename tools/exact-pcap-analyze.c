/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     28 Jul 2017
 *  Author:      Matthew P. Grosvenor
 *  Description: A tool for parsing pcaps and expcaps and outputting in ASCII
 *               for debugging and inspection.
 *
 */


#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <float.h>
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

#include "data_structs/pcap-structures.h"
#include "data_structs/pcap_buff.h"
#include "data_structs/expcap.h"
#include "utils.h"




/* Logger settings */
ch_log_settings_t ch_log_settings = {
    .log_level      = CH_LOG_LVL_DEBUG1,
    .use_color      = false,
    .output_mode    = CH_LOG_OUT_STDOUT,
    .filename       = NULL,
    .use_utc        = false,
    .incl_timezone  = false,
    .subsec_digits  = 3,
    .lvl_config  = { \
        { .color = CH_TERM_COL_NONE, .source = true,  .timestamp = false, .pid = false, .text = NULL }, /*FATAL*/\
        { .color = CH_TERM_COL_NONE, .source = false, .timestamp = false, .pid = false, .text = NULL }, /*ERROR*/\
        { .color = CH_TERM_COL_NONE, .source = false, .timestamp = false, .pid = false, .text = NULL }, /*WARNING*/\
        { .color = CH_TERM_COL_NONE, .source = false, .timestamp = false, .pid = false, .text = NULL }, /*INFO*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = false, .pid = true, .text = NULL }, /*DEBUG 1*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = false, .pid = true, .text = NULL }, /*DEBUG 2*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = false, .pid = true, .text = NULL }  /*DEBUG 3*/\
    },
};



USE_CH_OPTIONS;


struct {
    char*  input;
//    char* csv;
    bool verbose;
    char* format;
    double line_rate_gbps;
    ch_word offset;
    ch_word max;
    ch_word num;
    ch_word window_ms;
} options;


static volatile bool stop = false;
void signal_handler(int signum)
{
    ch_log_warn("Caught signal %li, shutting down\n", signum);
    if(stop == 1){
        ch_log_fatal("Hard exit\n");
    }
    stop = 1;
}

typedef struct
{
    double max_pps;
    double min_pps;
    double total_pps;

    double max_ifg;
    double min_ifg;
    double total_ifg;

    double min_ifg_theo_ns;

    int64_t max_bytes;
    int64_t min_bytes;

    int64_t packet_count;
    int64_t bytes_total;

} window_stats_t;

int64_t load_trace(bool expcap, timespecps_t* trace_start, timespecps_t* trace_stop, window_stats_t* total_stats)
{
    ch_log_info("PCAP analyser, opening file...\n");
    pcap_buff_t buff = {0};
    if(pcap_buff_from_file(&buff, options.input) != BUFF_ENONE){
        ch_log_fatal("Failed to createa new pcap buff from file: %s\n", options.input);
    }

    timespecps_t pkt_now    = {0};
    double windowstartns    = 0.0;
    double nowoffsetns      = 0.0;

    window_stats_t zero_ws  = {0};
    zero_ws.max_pps   = DBL_MIN;
    zero_ws.min_pps   = DBL_MAX;
    zero_ws.max_ifg   = DBL_MIN;
    zero_ws.min_ifg   = DBL_MAX;
    zero_ws.max_bytes = INT64_MIN;
    zero_ws.min_bytes = INT64_MAX;

    window_stats_t window_stats = zero_ws;

    /* Packet data */
    pcap_pkthdr_t* pkt_hdr;
    expcap_pktftr_t* pkt_ftr;
    pkt_info_t pkt_info;

    double prev_pkt_ts_ns = 0.0;
    double prev_pkt_size = 0;
    int64_t trace_pkt_count = 0;
    int window_start_pkt_num = 0;

    for(int pkt_num = 0; (!stop) && (pkt_num < options.offset + options.max); pkt_num++){
        if(pkt_num && pkt_num % (1000 * 1000) == 0){
            ch_log_info("Loaded %li,000,000 packets\n", pkt_num/1000/1000);
        }

        if(pkt_num < options.offset){
            continue;
        }

        //Skipping packets happens above this line
        /*-------------------------------------------------------------------*/
        trace_pkt_count++;

        pkt_info = pcap_buff_next_packet(&buff);
        pkt_hdr = buff.hdr;
        switch(pkt_info){
        case PKT_EOF:
            goto analysis_done;
        case PKT_OVER_SNAPLEN:
            ch_log_fatal("Packet with index %d does not comply with snaplen: %d (data len is %d)\n", pkt_num, buff.snaplen, buff.hdr->len);
            break;
        case PKT_SNAPPED:
            if(options.verbose){
                ch_log_warn("Packet has been snapped shorter (%d) than it's wire length (%d).\n", pkt_hdr->caplen, pkt_hdr->len);
            }
            break;
        case PKT_PADDING:
            ch_log_fatal("File %s still contains expcap padding. Use exact-pcap-extract to remove padding packets from this capture\n", options.input);
            break;
        case PKT_OK: // Fall through
        case PKT_RUNT:
        case PKT_ERROR:
            break;
        }

        pkt_ftr = buff.ftr;
        if(expcap){
            pkt_now.tv_sec = pkt_ftr->ts_secs;
            pkt_now.tv_psec = pkt_ftr->ts_psecs;
        } else{
            pkt_now.tv_sec = pkt_hdr->ts.ns.ts_sec;
            pkt_now.tv_psec = pkt_hdr->ts.ns.ts_nsec * 1000;
        }

        const int64_t pkt_size = pkt_hdr->len;
        const timespecps_t rel_time  = sub_tsps_tsps(&pkt_now,trace_start);

        if(trace_pkt_count == 1){
            *trace_start = pkt_now;
            windowstartns = 0;
            prev_pkt_ts_ns = 0;
            prev_pkt_size = pkt_size;
            continue;
        }

        nowoffsetns = tsps_to_double_ns(&rel_time);

        const double window_ns = nowoffsetns - windowstartns;

        /* Must wait until at least 2 packets have been seen in order to determine an IFG. */
        if( window_ns > options.window_ms * 1000 * 1000 && pkt_num > window_start_pkt_num + 1){
            //Output stats here
            double avg_ifg = (double)window_stats.total_ifg / (double)window_stats.packet_count;
            double mpps = (double)window_stats.packet_count / window_ns * 1000.0;
            double gbps = (double)window_stats.bytes_total / window_ns * 8.0;

            const int64_t secs  = pkt_hdr->ts.ns.ts_sec;
            const int64_t nsecs = pkt_hdr->ts.ns.ts_nsec;

            ch_log_info("[%lld.%lld]: offset=%i window=%.3lfms ipt=[%.3fns < %3.fns < %.3fns] size=[%iB < %0.3fB < %iB] rate=[%.3lfpps < %.3lfpps < %.3lfpps] %.3lfMpps %0.2lfGbps\n",
                        (long long)secs,
                        (long long)nsecs,
                        pkt_num,
                        window_ns /1000/1000.0,

                        window_stats.min_ifg,
                        avg_ifg,
                        window_stats.max_ifg,

                        window_stats.min_bytes,
                        (double)window_stats.bytes_total / (double)window_stats.packet_count,
                        window_stats.max_bytes,

                        window_stats.min_pps,
                        window_stats.total_pps / (double)window_stats.packet_count,
                        window_stats.max_pps,

                        mpps,
                        gbps);

            //Reset all the stats counters here.
            window_stats = zero_ws;
            const int64_t pkt_ifg_ps = 20 * 8 * 1000/options.line_rate_gbps;
            window_stats.min_ifg_theo_ns = (double)pkt_ifg_ps/1000;

            //Start again
            windowstartns = nowoffsetns;
            window_start_pkt_num = pkt_num;
        }


        window_stats.max_bytes = MAX(window_stats.max_bytes, pkt_size);
        window_stats.min_bytes = MIN(window_stats.min_bytes, pkt_size);
        window_stats.packet_count++;
        window_stats.bytes_total += pkt_size;

        const int64_t prev_pkt_ps = prev_pkt_size * 8 * 1000/options.line_rate_gbps;
        const int64_t curr_pkt_ps = pkt_size * 8 * 1000/options.line_rate_gbps;

        const double prev_pkt_end_ns = prev_pkt_ts_ns + prev_pkt_ps/1000;
        const double curr_pkt_end_ns = nowoffsetns + curr_pkt_ps/1000;

        const double packet_time = curr_pkt_end_ns - prev_pkt_end_ns;
        const double inst_mpps    = 1000.0/packet_time;

        window_stats.max_ifg = MAX(window_stats.max_ifg, packet_time);
        window_stats.min_ifg = MIN(window_stats.min_ifg, packet_time);
        window_stats.total_ifg += packet_time;

        window_stats.min_pps = MIN(window_stats.min_pps, inst_mpps);
        window_stats.max_pps = MAX(window_stats.max_pps, inst_mpps);
        window_stats.total_pps += inst_mpps;

        total_stats->max_ifg = MAX(window_stats.max_ifg, total_stats->max_ifg);
        total_stats->min_ifg = MIN(window_stats.min_ifg, total_stats->min_ifg);
        total_stats->min_ifg_theo_ns = MIN(window_stats.min_ifg_theo_ns, total_stats->min_ifg_theo_ns);
        total_stats->total_ifg += window_stats.total_ifg;

        total_stats->min_pps = MIN(total_stats->min_pps, window_stats.min_pps / (window_ns / NS_IN_SECS));
        total_stats->max_pps = MAX(total_stats->max_pps, window_stats.max_pps / (window_ns / NS_IN_SECS));
        total_stats->total_pps += window_stats.total_pps;

        total_stats->max_bytes = MAX(window_stats.max_bytes, total_stats->max_bytes);
        total_stats->min_bytes = MIN(window_stats.min_bytes, total_stats->min_bytes);

        total_stats->packet_count += window_stats.packet_count;
        total_stats->bytes_total += window_stats.bytes_total;

        prev_pkt_ts_ns = nowoffsetns;
        prev_pkt_size  = pkt_size;

    }
analysis_done:
    *trace_stop = pkt_now;

    return trace_pkt_count;
}



int main(int argc, char** argv)
{
    ch_word result = -1;

    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGTERM, signal_handler);

    ch_opt_addsu(CH_OPTION_REQUIRED,'i',"input","PCAP file to read", &options.input);
    ch_opt_addsu(CH_OPTION_REQUIRED,'f',"format","Input format [pcap | expcap]", &options.format);
    ch_opt_addfu(CH_OPTION_REQUIRED,'r',"line-rate","Line speed in gbps second e.g. 10 = 10Gb/s", &options.line_rate_gbps);
    ch_opt_addii(CH_OPTION_OPTIONAL,'o',"offset","Offset into the file to start ", &options.offset, 0);
    ch_opt_addii(CH_OPTION_OPTIONAL,'m',"max","Max packets to output (<0 means all)", &options.max, -1);
    ch_opt_addii(CH_OPTION_OPTIONAL,'w',"window","Window in milliseconds", &options.window_ms, 100);
    ch_opt_addbi(CH_OPTION_FLAG,'v',"verbose","Printout verbose output", &options.verbose, false);
    ch_opt_parse(argc,argv);

    bool expcap = false;
    if(strncmp(options.format, "pcap", strlen("pcap")) == 0){
        expcap = false;
    }
    else if(strncmp(options.format, "expcap", strlen("expcap")) == 0){
        expcap = true;
    }
    else{
        ch_log_fatal("Unknown format type =\"%s\". Must be \"pcap\" or \"expcap\"\n", options.format);
    }

    if(options.max < 0){
        options.max = INT64_MAX;
    }

    ch_log_info("PCAP analyser, starting...\n");


    timespecps_t trace_start    = {0};
    timespecps_t trace_stop     = {0};
    int64_t trace_pkt_count     = 0;

    window_stats_t stats  = {0};
    stats.max_pps         = DBL_MIN;
    stats.min_pps         = DBL_MAX;
    stats.max_ifg         = DBL_MIN;
    stats.min_ifg         = DBL_MAX;
    stats.min_ifg_theo_ns = DBL_MAX;
    stats.max_bytes       = INT64_MIN;
    stats.min_bytes       = INT64_MAX;
    ch_log_info("PCAP analyser, loading trace...\n");
    trace_pkt_count = load_trace(expcap, &trace_start, &trace_stop, &stats);
    if(trace_pkt_count == 0){
        ch_log_info("Found %li packets in trace \"%s\"\n", trace_pkt_count, options.input);
        return 0;
    }

    timespecps_t timedelta = sub_tsps_tsps(&trace_stop,&trace_start);
    const double timedelta_ns  = tsps_to_double_ns(&timedelta);
    const double timedelta_us  = timedelta_ns / 1000;
    const double timedelta_sec = timedelta_us / 1000 / 1000;

    const double pps          = trace_pkt_count / timedelta_sec;

    ch_log_info("PCAP analyser, processing trace...\n");

    ch_log_info("#########################################################\n");
    ch_log_info("Found %li packets in trace \"%s\"\n", trace_pkt_count, options.input);
    ch_log_info("PCAP trace is %0.2fns long (%0.4fus, %0.4fs)\n", timedelta_ns, timedelta_us, timedelta_sec);
    ch_log_info("Average packet rate is %0.4fpps (%0.4fMpps)\n", pps, pps / 1000 / 1000);
    ch_log_info("Packet sizes are in the range [%liB,%liB]\n", stats.min_bytes, stats.max_bytes);
    ch_log_info("Interfame gaps are in the range [%0.2fns,%0.2fns] note min IFG=%0.2fns\n", stats.min_ifg,stats.max_ifg, stats.min_ifg_theo_ns);
    ch_log_info("Packet rates are in the range [%0.2fpps,%0.2fpps] [%0.2fMpps,%0.2fMpps]\n", stats.min_pps, stats.max_pps, stats.min_pps/1000/1000, stats.max_pps/1000/1000);
    ch_log_info("#########################################################\n");

    ch_log_info("PCAP analyzer, finished\n");
    result = 0;
    return result;
}
