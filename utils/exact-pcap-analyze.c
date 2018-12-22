/*
 * Copyright (c) 2017, 2018 All rights reserved.
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

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>

#include "data_structs/pthread_vec.h"
#include "data_structs/eiostream_vec.h"
#include "data_structs/pcap-structures.h"

#include "data_structs/expcap.h"
#include "utils.h"




/* Logger settings */
ch_log_settings_t ch_log_settings = {
    .log_level      = CH_LOG_LVL_DEBUG1,
    .use_color      = false,
    .output_mode    = CH_LOG_OUT_STDERR,
    .filename       = NULL,
    .use_utc        = false,
    .incl_timezone  = false,
    .subsec_digits  = 3,
    .lvl_config  = { \
        { .color = CH_TERM_COL_NONE, .source = true,  .timestamp = true, .pid = false, .text = NULL }, /*FATAL*/\
        { .color = CH_TERM_COL_NONE, .source = false, .timestamp = true, .pid = false, .text = NULL }, /*ERROR*/\
        { .color = CH_TERM_COL_NONE, .source = false, .timestamp = true, .pid = false, .text = NULL }, /*WARNING*/\
        { .color = CH_TERM_COL_NONE, .source = false, .timestamp = true, .pid = false, .text = NULL }, /*INFO*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = true, .text = NULL }, /*DEBUG 1*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = true, .text = NULL }, /*DEBUG 2*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = true, .text = NULL }  /*DEBUG 3*/\
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

#define EOF_NORMAL 1
#define EOF_UNEXPECT 2

int read_expect(int fd, void* buff, ssize_t len, int64_t* offset)
{

    ssize_t total_bytes = 0;

    do{
        ch_log_debug1("Trying to read %liB\n", len);
        ssize_t bytes = read(fd, (char*)buff + total_bytes, len - total_bytes);
        total_bytes += bytes;

        if(bytes == 0 && total_bytes < len){
            if(total_bytes ){
                ch_log_warn("Expecting %li bytes, but read %li and reached end of file\n", len, total_bytes);
                return EOF_UNEXPECT;
            }
            ch_log_debug1("Reached end of file\n");
            return EOF_NORMAL;
        }
    }
    while(total_bytes < len);

    *offset += total_bytes;

    return 0;
}


int read_packet(int fd, int64_t* offset, int64_t snaplen, pcap_pkthdr_t* pkt_hdr,
                char* pbuf, bool expcap, expcap_pktftr_t** pkt_ftr, timespecps_t* tsps )
{

    int err = read_expect(fd, pkt_hdr, sizeof(pcap_pkthdr_t), offset);
    if(err){
        return err;
    }


    if(pkt_hdr->caplen > snaplen){
        ch_log_warn("Error, packet length out of range [0,%li] %u at offset=%li\n", snaplen, pkt_hdr->len, offset);
    }

    err = read_expect(fd, pbuf, pkt_hdr->caplen, offset);
    /*
     * It doesn't matter which error type we get, we've got a header and no
     * packet body, so this is unexpected
     */
    if(err){
        return EOF_UNEXPECT;
    }

    if(expcap){
        *pkt_ftr = (expcap_pktftr_t*)(pbuf + pkt_hdr->caplen - sizeof(expcap_pktftr_t));
       const int64_t secs  = (*pkt_ftr)->ts_secs;
       const int64_t psecs = (*pkt_ftr)->ts_psecs;
       tsps->tv_sec  = secs;
       tsps->tv_psec = psecs;
   }
   else{
       const int64_t secs  = pkt_hdr->ts.ns.ts_sec;
       const int64_t nsecs = pkt_hdr->ts.ns.ts_nsec;
       tsps->tv_sec  = secs;
       tsps->tv_psec = nsecs * 1000;
   }

    return 0;
}


int64_t load_trace(bool expcap, timespecps_t* trace_start, timespecps_t* trace_stop,
                CH_VECTOR(float)* rel_times, CH_VECTOR(i64)*  pkt_sizes )
{

    ch_log_info("PCAP analyser, opening file...\n");
    int fd = open(options.input,O_RDONLY);
    if(fd < 0){
        ch_log_fatal("Could not open PCAP %s (%s)\n", options.input, strerror(errno));
    }

    timespecps_t pkt_start      = {0};
    int64_t offset = 0;

    pcap_file_header_t fhdr;
    if(read_expect(fd, &fhdr, sizeof(fhdr), &offset)){
        ch_log_fatal("Could not read enough bytes from %s at offset %li, (%li required)\n", options.input, offset, sizeof(pcap_file_header_t));
    }

    char* magic_str = fhdr.magic == NSEC_TCPDUMP_MAGIC ? "Nansec TCP Dump" :  "UNKNOWN";
    magic_str = fhdr.magic == TCPDUMP_MAGIC ? "TCP Dump" :  magic_str;
    if(options.verbose){
        printf("Magic    0x%08x (%i) (%s)\n", fhdr.magic, fhdr.magic, magic_str);
        printf("Ver Maj  0x%04x     (%i)\n", fhdr.version_major, fhdr.version_major);
        printf("Ver Min  0x%04x     (%i)\n", fhdr.version_minor, fhdr.version_minor);
        printf("Thiszone 0x%08x (%i)\n", fhdr.thiszone, fhdr.thiszone);
        printf("SigFigs  0x%08x (%i)\n", fhdr.sigfigs, fhdr.sigfigs);
        printf("Snap Len 0x%08x (%i)\n", fhdr.snaplen, fhdr.snaplen);
        printf("Link typ 0x%08x (%i)\n", fhdr.linktype, fhdr.linktype);
    }


    /* Packet data */
    pcap_pkthdr_t pkt_hdr;
    expcap_pktftr_t* pkt_ftr;
    char pbuf[1024 * 64] = {0};
    int err = 0;

    int64_t trace_pkt_count     = 0;

    for(int pkt_num = 0; !stop && pkt_num < options.offset + options.max;
            pkt_num++  )
    {
        ch_log_debug1("Looking at packet number %li\n", pkt_num);

        if(pkt_num && pkt_num % (1000 * 1000) == 0){
            ch_log_info("Loaded %li,000,000 packets\n", pkt_num/1000/1000);
        }

        err = read_packet(fd, &offset, fhdr.snaplen, &pkt_hdr, pbuf, expcap, &pkt_ftr,&pkt_start);
        if(err == EOF_NORMAL){
            break;
        }

        if(err == EOF_UNEXPECT){
            ch_log_error("Unexpected end of file\n");
            break;
        }

        if(pkt_num < options.offset){
            continue;
        }

        //Skipping packets happens above this line
        /*-------------------------------------------------------------------*/
        trace_pkt_count++;

        if(trace_pkt_count == 1)
        {
            *trace_start = pkt_start;
        }

        timespecps_t rel_time  = sub_tsps_tsps(&pkt_start,trace_start);
        rel_times->push_back(rel_times,tsps_to_double_ns(&rel_time));
        pkt_sizes->push_back(pkt_sizes,pkt_hdr.len);
    }
    *trace_stop = pkt_start;

    close(fd);

    return trace_pkt_count;


}

static struct
{
    double maxwind_rate_pps;
    double minwind_rate_pps;

    double max_ifg;
    double min_ifg;

    double min_ifg_theo_ns;

    int64_t max_packet_bytes;
    int64_t min_packet_bytes;

} stats;


void process_trace(CH_VECTOR(float)* rel_times, CH_VECTOR(i64)* pkt_sizes)
{
    (void)pkt_sizes;
    const int64_t wind_sz = 30;

    stats.maxwind_rate_pps = DBL_MIN;
    stats.minwind_rate_pps = DBL_MAX;
    stats.max_ifg          = DBL_MIN;
    stats.min_ifg          = DBL_MAX;
    stats.max_packet_bytes = INT64_MIN;
    stats.min_packet_bytes = INT64_MAX;

    for(int i = 0; i < rel_times->count; i++){
        double pkt_ts_ns = rel_times->first[i];
        i64 pkt_size = pkt_sizes->first[i];
        stats.max_packet_bytes = MAX(stats.max_packet_bytes, pkt_size);
        stats.min_packet_bytes = MIN(stats.min_packet_bytes, pkt_size);


        int64_t pkt_ifg_ps = 20 * 8 * 1000/options.line_rate_gbps;
        stats.min_ifg_theo_ns = (double)pkt_ifg_ps/1000;
        //int64_t pkt_ps = pkt_size * 8 * 1000/options.line_rate_gbps;
        //int64_t pkt_total_ps = pkt_ps + pkt_ifg_ps;



        if(i > 0){
            double prev_pkt_ts_ns = rel_times->first[i-1];
            double prev_pkt_size  = pkt_sizes->first[i-1];
            int64_t prev_pkt_ps = prev_pkt_size * 8 * 1000/options.line_rate_gbps;
            double prev_pkt_end_ns = prev_pkt_ts_ns + prev_pkt_ps/1000;
            double ipg_ns = pkt_ts_ns - prev_pkt_end_ns;
            //double ipg_ns = pkt_delta_ns - (double)pkt_ps/1000.0;
//            printf("ipg = %0.2fns\n",
//                   ipg_ns);

            stats.max_ifg = MAX(stats.max_ifg, ipg_ns);
            stats.min_ifg = MIN(stats.min_ifg, ipg_ns);
        }

        //printf("### %0.2fns %lliB %0.2fns\n",pkti0, pkt_size, pkt_ps/1000.0);

        if(i < rel_times->count - wind_sz){
            double wind_pkt_ts_ns = rel_times->first[i+wind_sz - 1];
            double time_delta = wind_pkt_ts_ns - pkt_ts_ns;
            double pps10 = wind_sz / time_delta * 1000 * 1000 * 1000;
            stats.maxwind_rate_pps = MAX(stats.maxwind_rate_pps, pps10);
            stats.minwind_rate_pps = MIN(stats.minwind_rate_pps, pps10);
        }
    }

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

    CH_VECTOR(float)* rel_times  = CH_VECTOR_NEW(float,1024,CH_VECTOR_CMP(float));
    CH_VECTOR(i64)*   pkt_sizes  = CH_VECTOR_NEW(i64,1024,CH_VECTOR_CMP(i64));

    ch_log_info("PCAP analyser, loading trace...\n");
    trace_pkt_count = load_trace(expcap, &trace_start, &trace_stop, rel_times, pkt_sizes);
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
    process_trace(rel_times, pkt_sizes);

    ch_log_info("#########################################################\n");
    ch_log_info("Found %li packets in trace \"%s\"\n", trace_pkt_count, options.input);
    ch_log_info("PCAP trace is %0.2fns long (%0.4fus, %0.4fs)\n", timedelta_ns, timedelta_us, timedelta_sec);
    ch_log_info("Average packet rate is %0.4fpps (%0.4fMpps)\n", pps, pps / 1000 / 1000);
    ch_log_info("Packet sizes are in the range [%liB,%liB]\n", stats.min_packet_bytes,stats.max_packet_bytes);
    ch_log_info("Interfame gaps are in the range [%0.2fns,%0.2fns] note min IFG=%0.2fns\n", stats.min_ifg,stats.max_ifg, stats.min_ifg_theo_ns);
    ch_log_info("Packet rates are in the range [%0.2fpps,%0.2fpps] [%0.2fMpps,%0.2fMpps]\n", stats.minwind_rate_pps, stats.maxwind_rate_pps, stats.minwind_rate_pps/1000/1000, stats.maxwind_rate_pps/1000/1000);
    ch_log_info("#########################################################\n");



    ch_log_info("PCAP analyzer, finished\n");
    return result;

}
