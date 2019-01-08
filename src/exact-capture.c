/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description: A high rate capture application for ExaNICs and ExaDisks.
 */

#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <time.h>

#include <exanic/port.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/log/log_levels.h>
#include <chaste/timing/timestamp.h>

#include "data_structs/pthread_vec.h"
#include "data_structs/eiostream_vec.h"
#include "data_structs/pcap-structures.h"
#include "data_structs/expcap.h"

#include "exactio/exactio.h"
#include "exactio/exactio_exanic.h"
#include "exact-capture.h"
#include "exact-capture-listener.h"
#include "exact-capture-writer.h"
#include "exactio/exactio_timing.h"
#include "exactio/exactio_bring.h"

#define EXACT_MAJOR_VER 1
#define EXACT_MINOR_VER 1
#define EXACT_VER_TEXT ""


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
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = false, .text = NULL }, /*ERROR*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = false, .text = NULL }, /*WARNING*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = false, .text = NULL }, /*INFO*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = true, .text = NULL }, /*DEBUG 1*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = true, .text = NULL }, /*DEBUG 2*/\
        { .color = CH_TERM_COL_NONE, .source = true, .timestamp = true, .pid = true, .text = NULL }  /*DEBUG 3*/\
    },
};



USE_CH_OPTIONS;

#define CALIB_MODE_MASK_NIC  0x001
#define CALIB_MODE_MASK_RING 0x002
#define CALIB_MODE_MASK_DISK 0x004



static struct
{
    CH_VECTOR(cstr)* interfaces;
    CH_VECTOR(cstr)* dests;
    ch_cstr cpus_str;
    ch_word snaplen;
    ch_word calib_flags;
    ch_word max_file;
    ch_cstr log_file;
    ch_bool verbose;
    ch_word more_verbose_lvl;
    ch_float log_report_int_secs;
    ch_bool no_log_ts;
    ch_bool no_kernel;
    ch_bool no_promisc;
    ch_bool clear_buff;
    ch_word verbosity;
    bool no_overflow_warn;
    bool debug_log;
    bool no_spinner;

} options;

volatile bool lstop = false;
volatile bool wstop = false;
const bool nsec_pcap = true; /* This may become an option later? */
int64_t max_pkt_len;
int64_t min_pcap_rec;
int64_t max_pcap_rec;
int64_t max_file_size;

typedef exanic_port_stats_t pstats_t;


/*Assumes there there never more than 64 listener threads!*/
volatile lstats_t lstats_all[MAX_LTHREADS];
pstats_t port_stats[MAX_LTHREADS];

listener_params_t lparams_list[MAX_LTHREADS];


volatile wstats_t wstats[MAX_LTHREADS];
writer_params_t wparams_list[MAX_LTHREADS];

int device_ids[MAX_LTHREADS] = {0};
int port_ids[MAX_WTHREADS] = {0};


/* Statically define this for now, the numbers will be small */
eio_stream_t*    nic_istreams[MAX_LTHREADS]   = {0};
eio_stream_t*    ring_ostreams[MAX_LWCONNS]  = {0};

ring_istream_t   ring_istreams[MAX_LWCONNS]   = {0};
eio_stream_t*    disk_ostreams[MAX_WTHREADS]  = {0};



/* Get the next valid CPU from a CPU set */
static int64_t get_next_cpu (cpu_set_t* cpus)
{
    for (int i = 0; i < CPU_SETSIZE; i++)
    {
        if (CPU_ISSET (i, cpus))
        {
            ch_log_debug1("Found available cpu %i\n", i);
            CPU_CLR (i, cpus);
            return i;
        }
    }

    return -1;
}

/*
 * Start a thread, giving it a CPU and setting its scheduling parameters
 */
static int start_thread (cpu_set_t* avail_cpus, pthread_t *thread,
                  void *(*start_routine) (void *), void *arg)
{
    pthread_attr_t attr;
    pthread_attr_init (&attr);

    /* Figure out which core the thread will be on */
    cpu_set_t cpus;
    CPU_ZERO (&cpus);

    int64_t cpu = get_next_cpu (avail_cpus);
    CPU_SET (cpu, &cpus);
    pthread_attr_setaffinity_np (&attr, sizeof(cpu_set_t), &cpus);

    if (pthread_create (thread, &attr, start_routine, arg))
    {
        ch_log_fatal("Could not start thread on core %li\n", cpu);
        return -1;
    }
    ch_log_debug1("Started thread on core %li\n", cpu);

    return 0;

}

/*
 * Signal handler tells all threads to stop, but you can force exit by
 * sending a second signal
 */

int64_t hw_stop_ns;
pstats_t pstats_stop[MAX_LTHREADS] = {{0}};
bstats_t bstats_wr_stop[MAX_LWCONNS] = {{0}};

static void signal_handler (int signum)
{
    ch_log_debug1("Caught signal %li, sending shut down signal\n", signum);
    printf("\n");
    const ch_word listeners_count = options.interfaces->count;
    if(!lstop)
    {
        for (int tid = 0; tid < listeners_count ; tid++)
        {
            eio_rd_hw_stats(lparams_list[tid].nic_istream,&pstats_stop[tid]);
            const int64_t rings_count = lparams_list[tid].rings_count;
            for(int ring = 0; ring < rings_count; ring++){
                eio_wr_hw_stats(lparams_list[tid].rings[ring],
                                &bstats_wr_stop[tid * rings_count + ring]);
            }

        }

        hw_stop_ns = time_now_ns();
        lstop = 1;
        return;

    }

    /* We've been here before. Hard stop! */
    wstop = 1;
    ch_log_info("Caught hard exit. Stopping now. \n");
    exit(1);


}

static inline bstats_t bstats_subtract(bstats_t* lhs, bstats_t* rhs)
{
    bstats_t result = {0};
    result.minflt = lhs->minflt - rhs->minflt;
    result.majflt = lhs->majflt - rhs->majflt;
    result.utime  = lhs->utime  - rhs->utime;
    result.stime  = lhs->stime  - rhs->stime;
    return result;
}


static inline bstats_t bstats_add(bstats_t* lhs, bstats_t* rhs)
{
    bstats_t result = {0};
    result.minflt = lhs->minflt + rhs->minflt;
    result.majflt = lhs->majflt + rhs->majflt;
    result.utime  = lhs->utime  + rhs->utime;
    result.stime  = lhs->stime  + rhs->stime;
    return result;
}



static inline lstats_t lstats_subtract(lstats_t* lhs, lstats_t* rhs)
{
    lstats_t result;
    result.spins1_rx   = lhs->spins1_rx       - rhs->spins1_rx;
    result.spinsP_rx   = lhs->spinsP_rx       - rhs->spinsP_rx;
    result.packets_rx  = lhs->packets_rx      - rhs->packets_rx;
    result.bytes_rx    = lhs->bytes_rx        - rhs->bytes_rx;
    result.dropped     = lhs->dropped         - rhs->dropped;
    result.errors      = lhs->errors          - rhs->errors;
    result.swofl       = lhs->swofl           - rhs->swofl;
    result.hwofl       = lhs->hwofl           - rhs->hwofl;

    return result;
}


static inline lstats_t lstats_add(lstats_t* lhs, lstats_t* rhs)
{
    lstats_t result;
    result.spins1_rx   = lhs->spins1_rx       + rhs->spins1_rx;
    result.spinsP_rx   = lhs->spinsP_rx       + rhs->spinsP_rx;
    result.packets_rx  = lhs->packets_rx      + rhs->packets_rx;
    result.bytes_rx    = lhs->bytes_rx        + rhs->bytes_rx;
    result.dropped     = lhs->dropped         + rhs->dropped;
    result.swofl       = lhs->swofl           + rhs->swofl;
    result.hwofl       = lhs->hwofl           + rhs->hwofl;

    return result;
}


static inline pstats_t pstats_subtract(const pstats_t* lhs, const pstats_t* rhs)
{
    pstats_t result;
    result.rx_count          = lhs->rx_count         - rhs->rx_count;
    result.rx_dropped_count  = lhs->rx_dropped_count - rhs->rx_dropped_count;
    result.rx_error_count    = lhs->rx_error_count   - rhs->rx_error_count;
    result.rx_ignored_count  = lhs->rx_ignored_count - rhs->rx_ignored_count;

    return result;
}

static inline pstats_t pstats_add(const pstats_t* lhs, const pstats_t* rhs)
{
    pstats_t result;
    result.rx_count          = lhs->rx_count         + rhs->rx_count;
    result.rx_dropped_count  = lhs->rx_dropped_count + rhs->rx_dropped_count;
    result.rx_error_count    = lhs->rx_error_count   + rhs->rx_error_count;
    result.rx_ignored_count  = lhs->rx_ignored_count + rhs->rx_ignored_count;
    return result;
}


static inline wstats_t wstats_subtract(wstats_t* lhs, wstats_t* rhs)
{
    wstats_t result;
    result.spins   = lhs->spins   - rhs->spins;
    result.dbytes  = lhs->dbytes  - rhs->dbytes;
    result.pcbytes = lhs->pcbytes - rhs->pcbytes;
    result.plbytes = lhs->plbytes - rhs->plbytes;
    result.packets = lhs->packets - rhs->packets;
    return result;
}


static inline wstats_t wstats_add(wstats_t* lhs, wstats_t* rhs)
{
    wstats_t result;
    result.spins   = lhs->spins   + rhs->spins;
    result.dbytes  = lhs->dbytes   + rhs->dbytes;
    result.pcbytes = lhs->pcbytes + rhs->pcbytes;
    result.plbytes = lhs->plbytes + rhs->plbytes;
    result.packets = lhs->packets + rhs->packets;
    return result;
}


typedef struct {
    cpu_set_t listeners;
    cpu_set_t writers;
} cpus_t;



/*CPUs are in the following form
 * managemet:listener1,listener2,listenerN:writer1,writer2,writerN*/

static void parse_cpus(char* cpus_str, cpus_t* cpus)
{

    char* listeners_str = strtok(cpus_str, ":");
    if(listeners_str == NULL)
        goto fail;

    char* writers_str = strtok(NULL, ":");
    if(writers_str == NULL)
        goto fail;

    char* listener_str = strtok(listeners_str, ",");
    while(listener_str)
    {
        const int64_t lcpu = strtoll(listener_str, NULL, 10);
        ch_log_debug1("Setting listener CPU to %li\n", lcpu);
        CPU_SET(lcpu, &cpus->listeners);
        listener_str = strtok(NULL, ",");
    }

    char* writer_str = strtok(writers_str, ",");
    while(writer_str)
    {
        const int64_t wcpu = strtoll(writer_str, NULL, 10);
        ch_log_debug1("Setting writer CPU to %li\n", wcpu);
        CPU_SET(wcpu, &cpus->writers);
        writer_str = strtok(NULL, ",");
    }

    return;

fail:
    ch_log_fatal("Error: Expecting CPU string in format r,r,r:w,w,w");

}



static void print_lstats(lstats_t lstats_delta, listener_params_t lparams,
                  pstats_t pstats_delta,  bstats_t* bstats_deltas,
                  ch_word bstats_count, int tid, int64_t delta_ns)
{
    const double sw_rx_rate_gbs  = ((double) lstats_delta.bytes_rx * 8) /
            delta_ns;
    const double sw_rx_rate_mpps = ((double) lstats_delta.packets_rx ) /
            (delta_ns / 1000.0);
    const double hw_rx_rate_mpps = ((double) pstats_delta.rx_count ) /
            (delta_ns / 1000.0);

    int64_t maybe_lost     = pstats_delta.rx_count - lstats_delta.packets_rx;
    /* Can't have lost -ve lost packets*/
    maybe_lost = maybe_lost < 0 ? 0 : maybe_lost;

    if(options.more_verbose_lvl == 1 )
    {
        ch_log_info("Listener:%02i %s -- %.2fGbps %.2fMpps %.2fMB %li Pkts %lierrs %lidrp %liswofl\n",
               tid,
               lparams.nic_istream->name,

               sw_rx_rate_gbs,
               sw_rx_rate_mpps,

               lstats_delta.bytes_rx / 1024.0 / 1024.0,
               lstats_delta.packets_rx ,

               lstats_delta.errors, lstats_delta.dropped, lstats_delta.swofl);
    }
    else if(options.more_verbose_lvl == 2)
    {


        const int MAX_CHARS = 1024;
        char page_faults_str[MAX_CHARS];
        int offset = 0;
        offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "[");
        for(int wid = 0; wid < bstats_count; wid++)
        {
            offset += snprintf(page_faults_str + offset,MAX_CHARS - offset, "%li.%li ", bstats_deltas[wid].majflt, bstats_deltas[wid].minflt );
        }
        offset--; //Remove trailing space.
        offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "] ");


        ch_log_info("Listener:%02i %-15s -- %.2fGbps %.2fMpps (HW:%.2fiMpps) %.2fMB %li Pkts (HW:%i Pkts) [lost?:%li] (%.3fM Spins1 %.3fM SpinsP ) %lierrs %lidrp %liswofl %lihwofl Faults:%s\n",
               tid,
               lparams.nic_istream->name,

               sw_rx_rate_gbs,
               sw_rx_rate_mpps,
               hw_rx_rate_mpps,

               lstats_delta.bytes_rx / 1024.0 / 1024.0,
               lstats_delta.packets_rx ,
               pstats_delta.rx_count,

               maybe_lost,
               lstats_delta.spins1_rx / 1000.0 / 1000.0,
               lstats_delta.spinsP_rx / 1000.0 / 1000.0,

               lstats_delta.errors, lstats_delta.dropped, lstats_delta.swofl,
               lstats_delta.hwofl,

               page_faults_str

        );

    }

}



static void print_wstats(wstats_t wstats_delta,writer_params_t wparams,
                         bstats_t* bstats_deltas, int64_t bstats_count,
                         int tid, int64_t delta_ns )
{

    if(!wparams.disk_ostream->name)
    {
        //This writer has been cleaned up
        return;
    }

    const double w_rate_mpps  = ((double) wstats_delta.packets ) / (delta_ns / 1000.0);

    const double w_pcrate_gbs = ((double) wstats_delta.pcbytes * 8) / delta_ns;
    const double w_plrate_gbs = ((double) wstats_delta.plbytes * 8) / delta_ns;
    const double w_drate_gbs  = ((double) wstats_delta.dbytes  * 8) / delta_ns;



    const int dst_str_len = strlen(wparams.disk_ostream->name);
    char file_pretty[dst_str_len+1];
    bzero(file_pretty, dst_str_len+1);
    strncpy(file_pretty,wparams.disk_ostream->name, dst_str_len);

    char* pretty = file_pretty;
    if(dst_str_len > 17){
        pretty = file_pretty + dst_str_len - 17;
        file_pretty[0] = '.';
        file_pretty[1] = '.';
        file_pretty[2] = '.';
    }


    if(options.more_verbose_lvl == 1 )
    {
        ch_log_info("Writer:%02i %-17s -- %.2fGbps %.2fMpps %.2fMB %li Pkts\n",
                    tid,
                    pretty,
                    w_pcrate_gbs, w_rate_mpps,
                    wstats_delta.pcbytes / 1024.0 / 1024.0,
                    wstats_delta.packets);
    }
    else if(options.more_verbose_lvl == 2)
    {

        const int MAX_CHARS = 1024;
        char page_faults_str[MAX_CHARS];
        int offset = 0;
        offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "[");
        for(int wid = 0; wid < bstats_count; wid++)
        {
            offset += snprintf(page_faults_str + offset,MAX_CHARS - offset, "%li.%li ", bstats_deltas[wid].majflt, bstats_deltas[wid].minflt );
        }
        offset--; //Remove trailing space.
        offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "] ");


        ch_log_info("Writer:%02i %-17s -- %.2fGbps %.2fMpps (%.2fGbps wire %.2fGbps disk) %.2fMB (%.2fMB %.2fMB) %li Pkts %.3fM Spins Faults:%s\n",
                    tid,
                    pretty,
                    w_pcrate_gbs, w_rate_mpps, w_plrate_gbs, w_drate_gbs,
                    wstats_delta.pcbytes / 1024.0 / 1024.0,
                    wstats_delta.plbytes / 1024.0 / 1024.0,
                    wstats_delta.dbytes / 1024.0 / 1024.0,
                    wstats_delta.packets,
                    wstats_delta.spins / 1000.0 / 1000.0,
                    page_faults_str);

    }
}

static void print_lstats_totals(lstats_t ldelta_total,
                         pstats_t pdelta_total,
                         int64_t delta_ns)
{
    const double sw_rx_rate_gbs  = ((double) ldelta_total.bytes_rx * 8)
            / delta_ns;
    const double sw_rx_rate_mpps = ((double) ldelta_total.packets_rx ) /
            (delta_ns / 1000.0);
    const double hw_rx_rate_mpps = ((double) pdelta_total.rx_count ) /
            (delta_ns / 1000.0);
    int64_t maybe_lost     = pdelta_total.rx_count - ldelta_total.packets_rx;
    /* Can't have lost -ve lost packets*/
    maybe_lost = maybe_lost < 0 ? 0 : maybe_lost;

    if(options.more_verbose_lvl == 0)
    {
        ch_log_info("%-27s -- %.2fGbps %.2fMpps %.2fMB %li Pkts %lierrs %lidrp %liswofl\n",
           "Total - All Listeners",
           sw_rx_rate_gbs,
           sw_rx_rate_mpps,

           ldelta_total.bytes_rx / 1024.0 / 1024.0,
           ldelta_total.packets_rx,
           ldelta_total.errors, ldelta_total.dropped, ldelta_total.swofl);
    }
    if(options.more_verbose_lvl == 2 )
    {
        ch_log_info("%-27s -- %.2fGbps %.2fMpps (HW:%.2fiMpps) %.2fMB %li Pkts (HW:%i Pkts) [lost?:%li] (%.3fM Spins1 %.3fM SpinsP ) %lierrs %lidrp %liswofl %lihwofl\n",
           "Total - All Listeners",
           sw_rx_rate_gbs,
           sw_rx_rate_mpps,
           hw_rx_rate_mpps,

           ldelta_total.bytes_rx / 1024.0 / 1024.0,
           ldelta_total.packets_rx,
           pdelta_total.rx_count,

           maybe_lost,
           ldelta_total.spins1_rx / 1000.0 / 1000.0,
           ldelta_total.spinsP_rx / 1000.0 / 1000.0,
           ldelta_total.errors, ldelta_total.dropped, ldelta_total.swofl,
           ldelta_total.hwofl);
    }

}


static void print_wstats_totals(wstats_t wdelta_total, int64_t delta_ns )
{
    const double w_rate_mpps = ((double) wdelta_total.packets ) /
            (delta_ns / 1000.0);

    const double w_pcrate_gbs = ((double) wdelta_total.pcbytes * 8) / delta_ns;
    const double w_plrate_gbs = ((double) wdelta_total.plbytes * 8) / delta_ns;
    const double w_drate_gbs  = ((double) wdelta_total.dbytes  * 8) / delta_ns;

    if(options.more_verbose_lvl == 0 )
    {
        ch_log_info("%-27s -- %.2fGbps %.2fMpps %.2fMB %li Pkts\n",
                "Total - All Writers",
                w_pcrate_gbs, w_rate_mpps,
                wdelta_total.pcbytes / 1024.0 / 1024.0,
                wdelta_total.packets);
    }
    else if(options.more_verbose_lvl == 2)
    {
        ch_log_info("%-27s -- %.2fGbps %.2fMpps (%.2fGbps wire %.2fMGbps disk) %.2fMB (%.2fMB %.2fMB) %li Pkts %.3fM Spins\n",
                    "Total - All Writers",
                    w_pcrate_gbs, w_rate_mpps,
                    w_plrate_gbs, w_drate_gbs,
                    wdelta_total.pcbytes / 1024.0 / 1024.0,
                    wdelta_total.plbytes / 1024.0 / 1024.0,
                    wdelta_total.dbytes / 1024.0 / 1024.0,
                    wdelta_total.packets,
                    wdelta_total.spins / 1000.0 / 1000.0);

    }
}




static void print_stats_basic_totals(lstats_t ldelta_total, wstats_t wdelta_total,
                              pstats_t pdelta_total, int64_t delta_ns,
                              int64_t hw_delta_ns)
{
    const double sw_rx_rate_mpps = ((double) ldelta_total.packets_rx ) /
            (delta_ns / 1000.0);
    const double sw_rx_rate_gbps = ((double) ldelta_total.bytes_rx * 8 )
            / delta_ns;

    const double hw_rx_rate_mpps = ((double) pdelta_total.rx_count ) /
            (hw_delta_ns / 1000.0);

    const double w_rate_mpps = ((double) wdelta_total.packets ) /
            (delta_ns / 1000.0);
    const double w_pcrate_gbs = ((double) wdelta_total.pcbytes * 8) / delta_ns;

    int64_t maybe_lost_hwsw     = pdelta_total.rx_count - ldelta_total.packets_rx;
    /* Can't have lost -ve lost packets*/
    maybe_lost_hwsw = maybe_lost_hwsw < 0 ? 0 : maybe_lost_hwsw;

    const double maybe_lost_hwsw_mpps = ((double) maybe_lost_hwsw) / delta_ns / 1000;

    int64_t lost_rxwr_packets = ldelta_total.packets_rx - wdelta_total.packets;
    /* Can't have lost -ve lost packets*/
    lost_rxwr_packets = lost_rxwr_packets < 0 ? 0 : lost_rxwr_packets;
    const double lost_rxwr_mpps = ((double) lost_rxwr_packets) / delta_ns / 1000;

    int64_t lost_rxwr_bytes = ldelta_total.bytes_rx - wdelta_total.pcbytes;
    /* Can't have lost -ve lost bytes*/
    lost_rxwr_bytes = lost_rxwr_bytes < 0 ? 0 : lost_rxwr_bytes;
    const double lost_rxwr_gbps = ((double) lost_rxwr_bytes * 8) / delta_ns;

    const double dropped_rate_mpps = ((double) ldelta_total.dropped ) /
            (delta_ns / 1000.0);
    const double overflow_rate_ps = ((double) ldelta_total.swofl )
            / (delta_ns / 1000.0 / 1000.0 / 1000.0);


    const int col1_digits = max_digitsll(pdelta_total.rx_count,
                                        ldelta_total.packets_rx,
                                        ldelta_total.bytes_rx / 1024 / 1024,
                                        wdelta_total.packets,
                                        wdelta_total.pcbytes / 1024 / 1024,
                                        maybe_lost_hwsw,
                                        lost_rxwr_packets,
                                        lost_rxwr_bytes / 1024 / 1024,
                                        ldelta_total.dropped,
                                        ldelta_total.swofl);


    const int col2_digits = 3 + max_digitsf (hw_rx_rate_mpps, sw_rx_rate_mpps,
                                         sw_rx_rate_gbps, w_rate_mpps,
                                         w_pcrate_gbs, maybe_lost_hwsw_mpps,
                                         lost_rxwr_mpps, lost_rxwr_gbps,
                                         dropped_rate_mpps, overflow_rate_ps);

    fprintf(stderr,"Exact Capture finished\n");
    if(options.more_verbose_lvl == 2)
        fprintf(stderr,"%15s:%*u packets ( %*.3f MP/s )\n",
                "HW Received",
                col1_digits,
                pdelta_total.rx_count,
                col2_digits,
                hw_rx_rate_mpps);
    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
                "SW Received",
                col1_digits,
                ldelta_total.packets_rx,
                col2_digits,
                sw_rx_rate_mpps);
    fprintf(stderr,"%15s %*li MB      ( %*.3f Gb/s )\n",
                "",
                col1_digits,
                ldelta_total.bytes_rx / 1024 / 1024,
                col2_digits,
                sw_rx_rate_gbps);
    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
                "SW Wrote",
                col1_digits,
                wdelta_total.packets,
                col2_digits,
                w_rate_mpps);
    fprintf(stderr,"%15s %*li MB      ( %*.3f Gb/s )\n",
                "",
                col1_digits,
                wdelta_total.pcbytes / 1024 / 1024,
                col2_digits,
                w_pcrate_gbs);
    if(options.more_verbose_lvl == 2)
        fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
                "Lost HW/SW (?)",
                col1_digits,
                maybe_lost_hwsw ,
                col2_digits,
                maybe_lost_hwsw_mpps);
    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
                "Lost RX/WR",
                col1_digits,
                lost_rxwr_packets ,
                col2_digits,
                lost_rxwr_mpps);
    fprintf(stderr,"%15s %*li MB      ( %*.3f Gb/s )\n",
                "",
                col1_digits,
                lost_rxwr_bytes / 1024 / 1024,
                col2_digits,
                lost_rxwr_gbps);
    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
                "Dropped",
                col1_digits,
                ldelta_total.dropped ,
                col2_digits,
                dropped_rate_mpps);
    fprintf(stderr,"%15s:%*li times   ( %*.3f /s   )\n",
                "SW Overflows",
                col1_digits,
                ldelta_total.swofl ,
                col2_digits,
                overflow_rate_ps);


    /* TODO - There must be a better way to do this... */
    if(options.log_file)
    {
        ch_log_info("Exact Capture finished\n");
        if(options.more_verbose_lvl == 2)
            ch_log_info("%15s:%*u packets ( %*.3f MP/s )\n",
                    "HW Received",
                    col1_digits,
                    pdelta_total.rx_count,
                    col2_digits,
                    hw_rx_rate_mpps);
        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
                    "SW Received",
                    col1_digits,
                    ldelta_total.packets_rx,
                    col2_digits,
                    sw_rx_rate_mpps);
        ch_log_info("%15s %*li MB      ( %*.3f Gb/s )\n",
                    "",
                    col1_digits,
                    ldelta_total.bytes_rx / 1024 / 1024,
                    col2_digits,
                    sw_rx_rate_gbps);
        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
                    "SW Wrote",
                    col1_digits,
                    wdelta_total.packets,
                    col2_digits,
                    w_rate_mpps);
        ch_log_info("%15s %*li MB      ( %*.3f Gb/s )\n",
                    "",
                    col1_digits,
                    wdelta_total.pcbytes / 1024 / 1024,
                    col2_digits,
                    w_pcrate_gbs);
        if(options.more_verbose_lvl == 2 )
            ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
                    "Lost HW/SW (?)",
                    col1_digits,
                    maybe_lost_hwsw ,
                    col2_digits,
                    maybe_lost_hwsw_mpps);
        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
                    "Lost RX/WR",
                    col1_digits,
                    lost_rxwr_packets ,
                    col2_digits,
                    lost_rxwr_mpps);
        ch_log_info("%15s %*li MB      ( %*.3f Gb/s )\n",
                    "",
                    col1_digits,
                    lost_rxwr_bytes / 1024 / 1024,
                    col2_digits,
                    lost_rxwr_gbps);
        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
                    "Dropped",
                    col1_digits,
                    ldelta_total.dropped ,
                    col2_digits,
                    dropped_rate_mpps);
        ch_log_info("%15s:%*li times   ( %*.3f /s   )\n",
                    "SW Overflows",
                    col1_digits,
                    ldelta_total.swofl ,
                    col2_digits,
                    overflow_rate_ps);

    }


}


static CH_VECTOR(pthread)* start_listener_threads(cpu_set_t listener_cpus)
{
    ch_log_debug1("Setting up listener threads vector\n");
    CH_VECTOR(pthread)* lthreads = CH_VECTOR_NEW(pthread, 16, NULL);
    if (!lthreads)
    {
        ch_log_fatal("Could not allocate memory listener threads vector\n");
    }


    if(CPU_COUNT(&listener_cpus) < options.interfaces->count)
    {
        ch_log_fatal("Not enough listener CPUs available. Require %li, but only have %li\n",
                options.interfaces->count, CPU_COUNT(&listener_cpus));
    }


    ch_log_debug1("Starting up listener %li threads\n",
                  options.interfaces->count);
    ch_word disks_count = options.dests->count;
    int64_t listener_idx = 0;
    for (ch_cstr* opt_int = options.interfaces->first;
            opt_int < options.interfaces->end;
            opt_int = options.interfaces->next (options.interfaces, opt_int),
            listener_idx++)
    {

        ch_log_debug1("Starting listener thread on interface %s\n", *opt_int);

        listener_params_t* lparams = lparams_list + listener_idx;
        lparams->ltid         = lthreads->count;
        lparams->stop        = &lstop;
        lparams->nic_istream = nic_istreams[listener_idx];
        lparams->rings       = &ring_ostreams[listener_idx * disks_count];
        lparams->rings_count = disks_count;


        pthread_t thread = { 0 };
        if (start_thread (&listener_cpus, &thread, listener_thread,
                          (void*) lparams))
        {
            ch_log_fatal("Fatal: Could not start listener thread %li\n",
                         lthreads->count);
        }


        ch_log_debug1("Finished starting listener thread %li\n", lthreads->count);
        lthreads->push_back (lthreads, thread);
    }

    return lthreads;

}


static CH_VECTOR(pthread)* start_writer_threads(cpu_set_t writers)
{
    ch_log_debug1("Setting up writer threads vector\n");
    CH_VECTOR(pthread)* wthreads = CH_VECTOR_NEW(pthread, 16, NULL);
    if (!wthreads)
    {
        ch_log_fatal("Could not allocate disk writer threads vector\n");
    }

    /* Make a copy of this so that we do not limit the number of writer threads
     * from sharing cores */
    cpu_set_t writer_cpus = writers;


    ch_log_debug1("Starting up writer threads\n");
    ch_word nics_count = options.interfaces->count;
    ch_word writer_idx = 0;
    for (ch_cstr* opt_dest = options.dests->first;
            opt_dest < options.dests->end;
            opt_dest = options.dests->next (options.dests, opt_dest), writer_idx++)
    {

        writer_params_t* wparams = wparams_list + writer_idx;
        wparams->wtid         = wthreads->count;
        wparams->stop         = &lstop;
        wparams->disk_ostream = disk_ostreams[writer_idx];
        wparams->rings        = &ring_istreams[writer_idx * nics_count];
        wparams->rings_count  = nics_count;

        pthread_t thread = { 0 };

        /* allow reuse of the writer CPUs*/
        if(CPU_COUNT(&writer_cpus) == 0){
            writer_cpus = writers;
        }
        if (start_thread (&writer_cpus, &thread, writer_thread, (void*) wparams))
        {
            ch_log_error("Fatal: Could not start writer thread %li\n",
                         wthreads->count);
        }

        ch_log_debug1("Finished starting writer thread %li\n", wthreads->count);
        wthreads->push_back (wthreads, thread);
    }

    return wthreads;
}


static void remove_dups(CH_VECTOR(cstr)* opt_vec)
{
    for(int i = 0; i < opt_vec->count; i++)
    {
        char** lhs = opt_vec->off(opt_vec, i);
        for(int j = i+1; j < opt_vec->count; j++)
        {
            char** rhs = opt_vec->off(opt_vec, j);
            if(strcmp(*lhs, *rhs) == 0)
            {
                ch_log_warn("Warning: Ignoring duplicate argument \"%s\"\n", *lhs);
                opt_vec->remove(opt_vec,rhs);
            }
        }
    }
}



eio_stream_t* alloc_nic(char* iface, bool use_dummy  )
{

    eio_stream_t* istream = NULL;
    eio_args_t args = {0};
    bzero(&args,sizeof(args));
    eio_error_t err = EIO_ENONE;

    if (use_dummy)
    {
        /* Replace the input stream with a dummy stream */
        ch_log_debug1("Creating null output stream in place of exanic name: %s\n",
                      iface);
        args.type = EIO_DUMMY;
        args.args.dummy.read_buff_size = 64;
        args.args.dummy.rd_mode = DUMMY_MODE_EXANIC;
        args.args.dummy.exanic_pkt_bytes = args.args.dummy.read_buff_size;
        args.args.dummy.write_buff_size = 0;   /* We don't write to this stream */
        args.args.dummy.name = iface;
        err = eio_new (&args, &istream);
        if (err)
        {
            ch_log_fatal("Could not create listener input stream %s\n");
            return NULL;
        }
    }
    else
    {

        ch_log_debug1("New EIO stream %s\n", iface);
        args.type                     = EIO_EXA;
        args.args.exa.interface_rx    = iface;
        args.args.exa.interface_tx    = NULL;
        args.args.exa.kernel_bypass   = options.no_kernel;
        args.args.exa.promisc         = !options.no_promisc;
        args.args.exa.clear_buff      = options.clear_buff;
        eio_new (&args, &istream);
        if (err)
        {
            ch_log_fatal("Could not create listener input stream %s\n");
            return NULL;
        }

    }
    ch_log_debug1("Done. Setting up exanic listener for interface %s\n", iface);

    return istream;
}




eio_stream_t* alloc_disk(char* filename, bool use_dummy)
{

        eio_stream_t* ostream = NULL;

        /* Buffers are supplied buy the reader so no internal buffer is needed */
        const int64_t write_buff_size = 0;
        ch_log_debug3("Opening disk file %s\n", filename);
        eio_args_t args = {0};
        bzero(&args,sizeof(args));
        eio_error_t err = EIO_ENONE;

        /* Replace the output stream with a null stream, for testing */
        if (use_dummy)
        {
            ch_log_debug1("Creating null output stream in place of disk name: %s\n",
                        filename);
            args.type = EIO_DUMMY;
            args.args.dummy.read_buff_size = 0;   /* We don't read this stream */
            args.args.dummy.write_buff_size = write_buff_size;
            args.args.dummy.name = filename;
            err = eio_new (&args, &ostream);
            if (err)
            {
                ch_log_fatal("Could not create dummy writer output %s\n", filename);
                return NULL;
            }
        }
        else
        {
            args.type = EIO_FILE;
            args.args.file.filename              = filename;
            args.args.file.read_buff_size        = 0; //We don't read from this stream
            args.args.file.write_buff_size       = write_buff_size;
            args.args.file.write_directio        = true; //Use directio mode
            args.args.file.write_max_file_size   = max_file_size;
            err = eio_new (&args, &ostream);
            if (err)
            {
                ch_log_fatal("Could not create writer output %s\n", filename);
                return NULL;
            }
        }
        return ostream;
}



eio_stream_t* alloc_ring(bool use_dummy, char* iface, char* fname,
                         int64_t id_major, int64_t id_minor)
{
    eio_args_t args = {0};
    bzero(&args,sizeof(args));
    eio_stream_t* iostream = NULL;

    int namelen = snprintf(NULL,0,"%s:%s", iface, fname );

    if(use_dummy)
    {
        args.type = EIO_DUMMY;
        args.args.dummy.write_buff_size = BRING_SLOT_SIZE;
        args.args.dummy.read_buff_size  = BRING_SLOT_SIZE;
        args.args.dummy.rd_mode         = DUMMY_MODE_EXPCAP;
        args.args.dummy.expcap_bytes    = 512;
        args.args.dummy.name            = calloc(1,namelen + 1);
        args.args.dummy.id_major        = id_major;
        args.args.dummy.id_minor        = id_minor;
        snprintf(args.args.dummy.name, 128, "%s:%s", iface, fname);

        ch_log_debug1("Creating dummy ring %s with write_size=%li, read_sizet=%li\n",
                      args.args.dummy.name,
                      args.args.dummy.write_buff_size,
                      args.args.dummy.read_buff_size);

        if (eio_new (&args, &iostream))
        {
            ch_log_fatal("Could not create dummy ring\n");
            return NULL;
        }

        free(args.args.dummy.name);
    }
    else
    {
        args.type = EIO_BRING;
        /* This must be a multiple of the disk block size (assume 4kB)*/
        args.args.bring.slot_size  = BRING_SLOT_SIZE;
        args.args.bring.slot_count = BRING_SLOT_COUNT;
        args.args.bring.name       = calloc(1,namelen + 1);
        args.args.bring.id_major   = id_major;
        args.args.bring.id_minor   = id_minor;

        snprintf(args.args.bring.name, 128, "%s:%s", iface, fname);

        ch_log_debug1("Creating ring %s with slots=%li, slot_count=%li\n",
                      args.args.bring.name,
                      args.args.bring.slot_size,
                      args.args.bring.slot_count);

        if (eio_new (&args, &iostream))
        {
            ch_log_fatal("Could not create ring\n" );
            return NULL;
        }

        free(args.args.bring.name);
    }



    return iostream;
}



void allocate_iostreams()
{
    const int64_t nics  = options.interfaces->count;
    const int64_t disks = options.dests->count;
    const int64_t rings = nics * disks;


    if(nics > MAX_LTHREADS )
    {
        ch_log_fatal("Too many NICs requested. Increase the value of MAX_LTHREADS and recompile\n");
    }
    if(nics > MAX_LTHREADS )
    {
        ch_log_fatal("Too many disks requested. Increase the value of MAX_WTHREADS and recompile\n");
    }
    if(rings > MAX_LWCONNS)
    {
        ch_log_fatal("Too many rings requested. Increase the value of MAX_LWCONNS and recompile\n");
    }

    const ch_word dummy_nic   = CALIB_MODE_MASK_NIC  & options.calib_flags;
    const ch_word dummy_disk  = CALIB_MODE_MASK_DISK & options.calib_flags;
    const ch_word dummy_ring  = CALIB_MODE_MASK_RING & options.calib_flags;

    uint64_t nic_idx = 0;
    uint64_t disk_idx = 0;
    for (ch_cstr* interface = options.interfaces->first;
            interface < options.interfaces->end;
            interface = options.interfaces->next (options.interfaces, interface),
            nic_idx++)
    {

        ch_log_info("Allocating NIC interface %s at NIC index %i\n", *interface, nic_idx);


        //Allocate / connect each NIC to an istream
        nic_istreams[nic_idx] = alloc_nic(*interface, dummy_nic);

        //Allocate rings to connect each listener thread a writer thread
        disk_idx = 0;
        for (ch_cstr* filename = options.dests->first;
                   filename < options.dests->end;
                   filename = options.dests->next (options.dests, filename),
                   disk_idx++)
        {
            const uint64_t ring_idx = nic_idx * disks + disk_idx;
            ch_log_debug1("Allocating ring %s:%s (%i:%i) at ring index %i\n",
                        *interface,
                        *filename,
                        nic_idx,
                        disk_idx,
                        ring_idx);

            ring_ostreams[ring_idx] = alloc_ring(dummy_ring, *interface, *filename, nic_idx, disk_idx);
        }

    }


    disk_idx = 0;
    for (ch_cstr* filename = options.dests->first;
            filename < options.dests->end;
            filename = options.dests->next (options.dests, filename),
            disk_idx++)
    {

        ch_log_debug1("Allocating disk %s at disk index %i\n", *filename, disk_idx);

        disk_ostreams[disk_idx] = alloc_disk( *filename, dummy_disk);

        //Allocate rings to connect each listener thread a writer thread
        nic_idx = 0;
        for (ch_cstr* interface = options.interfaces->first;
                   interface < options.interfaces->end;
                   interface = options.interfaces->next (options.interfaces, interface),
                   nic_idx++)
       {

            const int64_t listen_ring_idx = nic_idx * disks + disk_idx;
            ch_log_debug1("Getting ring %s:%s (%i:%i) at listener ring index %i\n",
                                   *interface,
                                   *filename,
                                   nic_idx,
                                   disk_idx,
                                   listen_ring_idx);

            eio_stream_t* ring = ring_ostreams[listen_ring_idx];
            eio_stream_t* nic  = nic_istreams[nic_idx];


            const int64_t writer_ring_idx = disk_idx * nics + nic_idx;
            ch_log_debug1("Setting ring %s:%s (%i:%i) at writer ring index %i\n",
                                   *interface,
                                   *filename,
                                   nic_idx,
                                   disk_idx,
                                   writer_ring_idx);

            ring_istreams[writer_ring_idx].ring_istream = ring;
            ring_istreams[writer_ring_idx].nic_istream  = nic;
        }

    }

}



/**
 * Main loop sets up threads and listens for stats / configuration messages.
 */
int main (int argc, char** argv)
{
    ch_word result = -1;

    signal (SIGHUP, signal_handler);
    signal (SIGINT, signal_handler);
    signal (SIGPIPE, signal_handler);
    signal (SIGALRM, signal_handler);
    signal (SIGTERM, signal_handler);

    ch_opt_addSU (CH_OPTION_REQUIRED, 'i', "interface",         "Interface(s) to listen on",                        &options.interfaces);
    ch_opt_addSU (CH_OPTION_REQUIRED, 'o', "output",            "Destination(s) to write to",                       &options.dests);
    ch_opt_addsu (CH_OPTION_REQUIRED, 'c', "cpus",              "CPUs in the form m:l,l,l:w,w,w",                   &options.cpus_str);
    ch_opt_addii (CH_OPTION_OPTIONAL, 's', "snaplen",           "Maximum capture length",                           &options.snaplen, 2048);
    ch_opt_addbi (CH_OPTION_FLAG,     'n', "no-promisc",        "Do not enable promiscuous mode on the interface",  &options.no_promisc, false);
    ch_opt_addbi (CH_OPTION_FLAG,     'k', "no-kernel",         "Do not allow packets to reach the kernel",         &options.no_kernel, false);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'm', "maxfile",           "Maximum file size (<=0 means no max)",             &options.max_file, -1);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'l', "logfile",           "Log file to log output to",                        &options.log_file, NULL);
    ch_opt_addfi (CH_OPTION_OPTIONAL, 't', "log-report-int",    "Log reporting interval (in secs)",                 &options.log_report_int_secs, 1);
    ch_opt_addbi (CH_OPTION_FLAG,     'v', "verbose",           "Verbose output",                                   &options.verbose, false);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'V', "more-verbose-lvl",  "More verbose output level [1-2]",                  &options.more_verbose_lvl, 0);
    ch_opt_addbi (CH_OPTION_FLAG,     'T', "no-log-ts",         "Do not use timestamps on logs",                    &options.no_log_ts, false);
    ch_opt_addbi (CH_OPTION_FLAG,     'd', "debug-logging",     "Turn on debug logging output",                     &options.debug_log, false);
    ch_opt_addbi (CH_OPTION_FLAG,     'w', "no-warn-overflow",  "No warning on overflows",                          &options.no_overflow_warn, false);
    ch_opt_addbi (CH_OPTION_FLAG,     'S', "no-spin",           "No spinner on the output",                         &options.no_spinner, false);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'p', "perf-test",         "Performance test mode [0-7]",                      &options.calib_flags, 0);
    ch_opt_addbi (CH_OPTION_FLAG,     'C', "clear-buff",        "Clear all pending rx packets before starting",     &options.clear_buff, false);

    ch_opt_parse (argc, argv);

    fprintf(stderr,"Exact-Capture %i.%i%s (%08X-%08X)\n",
                EXACT_MAJOR_VER, EXACT_MINOR_VER, EXACT_VER_TEXT,
                BRING_SLOT_SIZE, BRING_SLOT_COUNT);
    fprintf(stderr,"Copyright Exablaze Pty Ltd 2018\n");


#ifndef NDEBUG
    fprintf(stderr,"Warning: This is a debug build, performance may be affected\n");
#endif

#ifndef NOIFASSERT
    fprintf(stderr,"Warning: This is an assertion build, performance may be affected\n");
#endif

    if(!options.no_kernel)
        fprintf(stderr,"Warning: --no-kernel flag is not set, performance may be affected\n");


    for(int i = 0; i < CH_LOG_LVL_COUNT; i++)
    {
        ch_log_settings.lvl_config[i].timestamp = !options.no_log_ts;
        ch_log_settings.lvl_config[i].source    = options.debug_log;
        ch_log_settings.lvl_config[i].pid       = options.debug_log;
    }

    if( options.log_file )
    {
        ch_log_settings.output_mode = CH_LOG_OUT_FILE;
        ch_log_settings.fd          = -1;
        ch_log_settings.filename    = options.log_file;

        ch_log_info("Exact-Capture %i.%i%s (%08X-%08X)\n",
                    EXACT_MAJOR_VER, EXACT_MINOR_VER, EXACT_VER_TEXT,
                    BRING_SLOT_SIZE, BRING_SLOT_COUNT);
        ch_log_info("Copyright Exablaze Pty Ltd 2018\n");

#ifndef NDEBUG
        ch_log_warn("Warning: This is a debug build, performance may be affected\n");
#endif

#ifndef NOIFASSERT
        ch_log_warn("Warning: This is an assertion build, performance may be affected\n");
#endif

        if(!options.no_kernel)
            fprintf(stderr,"Warning: --no-kernel flag is not set, performance may be affected\n");

    }

    remove_dups(options.interfaces);
    remove_dups(options.dests);


    max_file_size = options.max_file;
    max_pkt_len = options.snaplen;
    min_pcap_rec = MIN(sizeof(pcap_pkthdr_t) + sizeof(expcap_pktftr_t),MIN_ETH_PKT);
    max_pcap_rec = min_pcap_rec + max_pkt_len;

    cpus_t cpus = {{{0}}};
    parse_cpus(options.cpus_str, &cpus);

    if (options.calib_flags < 0 || options.calib_flags > 7)
    {
        ch_log_fatal("Calibration mode must be between 0 and 7\n");
    }

    cpu_set_t cpus_tmp;
    CPU_ZERO(&cpus_tmp);
    CPU_AND(&cpus_tmp, &cpus.listeners, &cpus.writers);
    if(CPU_COUNT(&cpus_tmp))
    {
        ch_log_warn("Warning: Sharing listener and writer CPUs is not recommended\n");
    }

    //Allocate all I/O streams (NICs, Disks and rings to join threads)
    allocate_iostreams();
    CH_VECTOR(pthread)* lthreads = start_listener_threads(cpus.listeners);
    CH_VECTOR(pthread)* wthreads = start_writer_threads(cpus.writers);

    /* Set the management thread CPU cores. Allow management to run on any
     * CPU, but not on listener CPU */
    cpu_set_t cpus_man;
    CPU_ZERO(&cpus_tmp);
    for(int i = 0; i < 16; i++) CPU_SET(i,&cpus_man); //Assume no more than 256 cores...
    CPU_XOR(&cpus_man, &cpus.listeners,&cpus_man); //Invert the listener CPUs
    if (sched_setaffinity (0, sizeof(cpu_set_t), &cpus_man))
    {
        ch_log_fatal("Could not set management CPUs affinity\n");
    }
    nice(-10); //Stats is lower priority than anything else
    /*************************************************************************/
    /* Main thread - Real work begins here!                                  */
    /*************************************************************************/
    result = 0;
    lstats_t lstats_start[MAX_LTHREADS] = {{0}};
    lstats_t lstats_prev[MAX_LTHREADS] = {{0}};
    lstats_t lstats_now[MAX_LTHREADS] = {{0}};

    lstats_t lempty = {0};
    lstats_t ldelta_total = {0};

    pstats_t pstats_start[MAX_LTHREADS] = {{0}};
    pstats_t pstats_prev [MAX_LTHREADS] = {{0}};
    pstats_t pstats_now  [MAX_LTHREADS] = {{0}};

    bstats_t bstats_wr_start[MAX_LWCONNS] = {{0}};
    bstats_t bstats_wr_prev[MAX_LWCONNS]  = {{0}};
    bstats_t bstats_wr_now[MAX_LWCONNS]   = {{0}};

    bstats_t bstats_rd_start[MAX_LWCONNS] = {{0}};
    bstats_t bstats_rd_prev[MAX_LWCONNS]  = {{0}};
    bstats_t bstats_rd_now[MAX_LWCONNS]   = {{0}};


    pstats_t pempty = {0};
    pstats_t pdelta_total = {0};

    bstats_t bempty = {0};
    bstats_t bdelta_total = {0};

    wstats_t wstats_prev[MAX_WTHREADS] = {{0}};
    wstats_t wstats_now[MAX_LTHREADS] = {{0}};

    wstats_t wempty = {0};
    wstats_t wdelta_total = {0};

    int64_t now_ns          = time_now_ns();
    int64_t start_ns        = now_ns;
    int64_t sample_start_ns = now_ns;
    int64_t delta_ns        = 0;
    int64_t sleep_time_ns   = (int64_t)(options.log_report_int_secs * 1000 * 1000 * 1000);


    for (int tid = 0; tid < lthreads->count; tid++)
    {
        eio_rd_hw_stats(nic_istreams[tid], &pstats_start[tid]);
        pstats_prev[tid] = pstats_start[tid];

        const int64_t rings_count = lparams_list[tid].rings_count;
        for(int ring = 0; ring < rings_count; ring++){
            eio_wr_hw_stats(lparams_list[tid].rings[ring],
                            &bstats_wr_start[tid * rings_count + ring]);
            bstats_wr_prev[tid * rings_count + ring] =
                    bstats_wr_start[tid * rings_count + ring];
        }
    }


    for (int wid = 0; wid < wthreads->count; wid++)
    {
        const int64_t rings_count = wparams_list[wid].rings_count;
        for(int ring = 0; ring < rings_count; ring++){
            eio_rd_hw_stats(wparams_list[wid].rings[ring].ring_istream,
                            &bstats_rd_start[wid * rings_count + ring]);
            bstats_rd_prev[wid * rings_count + ring] =
                    bstats_rd_start[wid * rings_count + ring];
        }
    }


    int spinner_idx = 0;
#define spinner_len 4
    char spinner[spinner_len] = {'|','/', '-', '\\'};
    if(!(options.verbose || options.more_verbose_lvl) && !options.no_spinner)
        fprintf(stderr,"Exact Capture running... %c \r", spinner[spinner_idx]);

    if(options.log_file)
        ch_log_info("Exact Capture running...\n");



    while (!lstop)
    {

        if(!(options.verbose || options.more_verbose_lvl) && !options.no_spinner)
        {
            fprintf(stderr,"Exact Capture running... %c \r", spinner[spinner_idx]);
            spinner_idx++;
            spinner_idx %= spinner_len;
        }



        /* Grab the begining of the next time sample once everything is done */
        sample_start_ns = time_now_ns();
        usleep(sleep_time_ns/1000);
        now_ns = time_now_ns();
        delta_ns = now_ns - sample_start_ns;

        /* Collect data as close together as possible before starting processing */
        for (int tid = 0; tid < lthreads->count; tid++)
        {

            eio_rd_hw_stats(nic_istreams[tid], &pstats_now[tid]);
            lstats_now[tid] = lstats_all[tid];

            const int64_t rings_count = lparams_list[tid].rings_count;
            for(int ring = 0; ring < rings_count; ring++){
                 eio_wr_hw_stats(lparams_list[tid].rings[ring],
                                 &bstats_wr_now[tid * rings_count + ring]);
             }
        }
        for (int tid = 0; tid < wthreads->count; tid++)
        {
            wstats_now[tid] = wstats[tid];

            const int64_t rings_count = wparams_list[tid].rings_count;
            for(int ring = 0; ring < rings_count; ring++){
                eio_rd_hw_stats(wparams_list[tid].rings[ring].ring_istream,
                                &bstats_rd_now[tid * rings_count + ring]);
                bstats_rd_prev[tid * rings_count + ring] =
                        bstats_rd_now[tid * rings_count + ring];
            }

        }


        /* Start processing the listener thread stats */
        ldelta_total = lempty;
        pdelta_total = pempty;
        for (int tid = 0; tid < lthreads->count;
                lstats_prev[tid] = lstats_now[tid],
                pstats_prev[tid] = pstats_now[tid],
                tid++)
        {
            lstats_t lstats_delta = lstats_subtract(
                    &lstats_now[tid],
                    &lstats_prev[tid]);

            ldelta_total = lstats_add(&ldelta_total, &lstats_delta);

            pstats_t pstats_delta = pstats_subtract(
                    &pstats_now[tid],
                    &pstats_prev[tid]);

            pdelta_total = pstats_add(&pdelta_total, &pstats_delta );

            bstats_t bstats_deltas[MAX_WTHREADS] = {0};
            bstats_t bstats_totals[MAX_WTHREADS] = {0};
            const ch_word  wthreads_count = wthreads->count;
            for(int wid = 0; wid < wthreads_count; wid++)
            {
                const int bstats_idx = tid* wthreads_count + wid;
                bstats_deltas[wid] = bstats_subtract(&bstats_wr_now[bstats_idx],&bstats_wr_prev[bstats_idx]);
                bstats_totals[wid] = bstats_add(&bstats_totals[wid],&bstats_deltas[wid]);
                bdelta_total       = bstats_add(&bdelta_total, &bstats_deltas[wid]);
                bstats_wr_prev[bstats_idx] = bstats_wr_now[bstats_idx];
            }


            if(!options.more_verbose_lvl)
                continue;

            print_lstats(lstats_delta, lparams_list[tid], pstats_delta,
                         bstats_deltas, wthreads_count, tid, delta_ns);

        }

        if(options.verbose)
        {
            print_lstats_totals(ldelta_total,pdelta_total, delta_ns);
        }

        /* Process the writer thread stats */
        wdelta_total = wempty;
        for (int tid = 0;
                (options.more_verbose_lvl || options.verbose) && tid < wthreads->count;
                wstats_prev[tid] = wstats_now[tid], tid++)
        {
            wstats_t wstats_delta = wstats_subtract(&wstats_now[tid], &wstats_prev[tid]);
            wdelta_total = wstats_add(&wdelta_total, &wstats_delta);

            bstats_t bstats_deltas[MAX_WTHREADS] = {0};
            bstats_t bstats_totals[MAX_WTHREADS] = {0};
            const ch_word  wthreads_count = wthreads->count;
            for(int wid = 0; wid < wthreads_count; wid++)
            {
                const int bstats_idx = tid* wthreads_count + wid;
                bstats_deltas[wid] = bstats_subtract(&bstats_rd_now[bstats_idx],&bstats_rd_prev[bstats_idx]);
                bstats_totals[wid] = bstats_add(&bstats_totals[wid],&bstats_deltas[wid]);
                bdelta_total       = bstats_add(&bdelta_total, &bstats_deltas[wid]);
                bstats_rd_prev[bstats_idx] = bstats_rd_now[bstats_idx];
            }


            if(!options.more_verbose_lvl)
                continue;

            print_wstats(wstats_delta, wparams_list[tid], bstats_deltas,
                         wthreads_count, tid, delta_ns);

        }

        if(options.verbose)
        {
            print_wstats_totals(wdelta_total, delta_ns);
        }

        if(!options.no_overflow_warn && (ldelta_total.swofl || ldelta_total.hwofl)){
            ch_log_warn("Warning: Overflow(s) occurred (SW:%li, HW:%li). Many packets lost!\n",
                    ldelta_total.swofl, ldelta_total.hwofl);
        }


    }


    ch_log_debug1("Stopping all listener threads.\n");
    lstop = true;
    ch_log_debug1("Waiting for listener threads to die...\n");
    for (pthread_t* lthread = lthreads->first; lthread < lthreads->end;
            lthread = lthreads->next (lthreads, lthread))
    {
        pthread_join (*lthread, NULL);
    }
    ch_log_debug1("All listener threads dead.\n");

    /* Give the writers some time to finish dumping packets */
    usleep(100 * 1000);

    ch_log_debug1("Stopping all writer threads.\n");
    wstop = true;
    ch_log_debug1("Waiting for writer threads to die...\n");
    for (pthread_t* wthread = wthreads->first; wthread < wthreads->end;
            wthread = wthreads->next (wthreads, wthread))
    {
        pthread_join (*wthread, NULL);
    }
    ch_log_debug1("All writer threads dead.\n");


    now_ns = time_now_ns();
    delta_ns = now_ns - start_ns;
    const int64_t hw_delta_ns = hw_stop_ns - start_ns;

    /* Start processing the listener thread stats */
    ldelta_total = lempty;
    pdelta_total = pempty;
    bdelta_total = bempty;
    for (int tid = 0; tid < lthreads->count; tid++)
    {

        lstats_now[tid] = lstats_all[tid];
        lstats_t lstats_delta = lstats_subtract(&lstats_now[tid], &lstats_start[tid]);
        ldelta_total = lstats_add(&ldelta_total, &lstats_delta);

        pstats_t pstats_delta = pstats_subtract(&pstats_stop[tid], &pstats_start[tid]);
        pdelta_total = pstats_add(&pdelta_total, &pstats_delta);

        bstats_t bstats_deltas[MAX_WTHREADS] = {0};
        bstats_t bstats_totals[MAX_WTHREADS] = {0};
        const ch_word  wthreads_count = wthreads->count;
        for(int wid = 0; wid < wthreads_count; wid++)
        {
            const int bstats_idx = tid* wthreads_count + wid;
            bstats_deltas[wid] = bstats_subtract(&bstats_wr_stop[bstats_idx],&bstats_wr_start[bstats_idx]);
            bstats_totals[wid] = bstats_add(&bstats_totals[wid],&bstats_deltas[wid]);
            bdelta_total       = bstats_add(&bdelta_total, &bstats_deltas[wid]);
        }


        if(!options.more_verbose_lvl)
            continue;

        print_lstats(lstats_delta, lparams_list[tid], pstats_delta, bstats_deltas, wthreads_count, tid,  delta_ns);

    }

    if(options.verbose)
        print_lstats_totals(ldelta_total,pdelta_total, delta_ns);


    /* Process the writer thread stats */
    wdelta_total = wempty;
    for (int tid = 0; tid < wthreads->count; tid++)
    {
        wstats_t wstats_delta = wstats[tid];
        wdelta_total = wstats_add(&wdelta_total, &wstats_delta);

        if(!options.more_verbose_lvl)
            continue;


        bstats_t bstats_deltas[MAX_WTHREADS] = {0};
        bstats_t bstats_totals[MAX_WTHREADS] = {0};
        const ch_word  wthreads_count = wthreads->count;
        for(int wid = 0; wid < wthreads_count; wid++)
        {
            const int bstats_idx = tid* wthreads_count + wid;
            bstats_deltas[wid] = bstats_subtract(&bstats_rd_now[bstats_idx],&bstats_rd_prev[bstats_idx]);
            bstats_totals[wid] = bstats_add(&bstats_totals[wid],&bstats_deltas[wid]);
            bdelta_total       = bstats_add(&bdelta_total, &bstats_deltas[wid]);
            bstats_rd_prev[bstats_idx] = bstats_rd_now[bstats_idx];
        }

        print_wstats(wstats_delta, wparams_list[tid], bstats_deltas,
                     wthreads_count, tid, delta_ns);

    }


    if(options.verbose)
        print_wstats_totals(wdelta_total, delta_ns);


    print_stats_basic_totals(ldelta_total, wdelta_total, pdelta_total,delta_ns,
                             hw_delta_ns);

    return result;
}
