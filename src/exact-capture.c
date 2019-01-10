/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
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
#include <errno.h>

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
#include "exactio/exactio_timing.h"

#include "exact-capture.h"
#include "exact-capture-listener.h"
#include "exact-capture-writer.h"
#include "exact-capture-stats.h"



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
    CH_VECTOR(cstr)* ifaces;
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
    ch_bool no_color;
    ch_word verbosity;
    bool no_overflow_warn;
    bool debug_log;
    bool no_spinner;

} options;



static volatile bool listener_stop = false;
static volatile bool writer_stop   = false;


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




static CH_VECTOR(pthread)* start_listener_threads(cpu_set_t listener_cpus,
                                                  lparams_t* lparams_list,
                                                  eio_stream_t** nic_istreams,
                                                  eio_stream_t** ring_ostreams,
                                                  volatile bool* stop)
{
    ch_log_debug1("Setting up listener threads vector\n");
    CH_VECTOR(pthread)* lthreads = CH_VECTOR_NEW(pthread, 16, NULL);
    if (!lthreads)
    {
        ch_log_fatal("Could not allocate memory listener threads vector\n");
    }


    if(CPU_COUNT(&listener_cpus) < options.ifaces->count)
    {
        ch_log_fatal("Not enough listener CPUs available. Require %li, but only have %li\n",
                options.ifaces->count, CPU_COUNT(&listener_cpus));
    }


    ch_log_debug1("Starting up listener %li threads\n",
                  options.ifaces->count);
    ch_word disks_count = options.dests->count;
    int64_t listener_idx = 0;
    for (ch_cstr* opt_int = options.ifaces->first;
            opt_int < options.ifaces->end;
            opt_int = options.ifaces->next (options.ifaces, opt_int),
            listener_idx++)
    {

        ch_log_debug1("Starting listener thread on interface %s\n", *opt_int);

        lparams_t* lparams = lparams_list + listener_idx;
        lparams->ltid        = lthreads->count;
        lparams->stop        = stop;
        lparams->nic_istream = nic_istreams[listener_idx];
        lparams->rings       = &ring_ostreams[listener_idx * disks_count];
        lparams->rings_count = disks_count;
        lparams->snaplen     = options.snaplen;


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


static CH_VECTOR(pthread)* start_writer_threads(cpu_set_t writers,
                                                wparams_t* wparams_list,
                                                eio_stream_t** ring_istreams,
                                                eio_stream_t** disk_ostreams,
                                                volatile bool* stop)
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
    ch_word nics_count = options.ifaces->count;
    ch_word writer_idx = 0;
    for (ch_cstr* opt_dest = options.dests->first;
            opt_dest < options.dests->end;
            opt_dest = options.dests->next (options.dests, opt_dest), writer_idx++)
    {

        wparams_t*wparams = wparams_list + writer_idx;
        wparams->wtid           = wthreads->count;
        wparams->stop           = stop;
        wparams->disk_ostream   = disk_ostreams[writer_idx];
        wparams->rings          = &ring_istreams[writer_idx * nics_count];
        wparams->rings_count    = nics_count;

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



eio_stream_t* alloc_nic(char* iface, bool use_dummy, int64_t snaplen  )
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
        args.args.exa.snaplen         = snaplen;
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




eio_stream_t* alloc_disk(char* filename, bool use_dummy, int64_t max_file_size)
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



void allocate_iostreams(eio_stream_t** nic_istreams,  eio_stream_t** ring_ostreams,
                        eio_stream_t** ring_istreams, eio_stream_t** disk_ostreams,
                        int64_t snaplen, int64_t max_file_size)
{
    const int64_t nics  = options.ifaces->count;
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
    for (ch_cstr* interface = options.ifaces->first;
            interface < options.ifaces->end;
            interface = options.ifaces->next (options.ifaces, interface),
            nic_idx++)
    {

        ch_log_info("Allocating NIC interface %s at NIC index %i\n", *interface, nic_idx);


        //Allocate / connect each NIC to an istream
        nic_istreams[nic_idx] = alloc_nic(*interface, dummy_nic, snaplen);

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

        disk_ostreams[disk_idx] = alloc_disk( *filename, dummy_disk, max_file_size);

        //Allocate rings to connect each listener thread a writer thread
        nic_idx = 0;
        for (ch_cstr* interface = options.ifaces->first;
                   interface < options.ifaces->end;
                   interface = options.ifaces->next (options.ifaces, interface),
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

            const int64_t writer_ring_idx = disk_idx * nics + nic_idx;
            ch_log_debug1("Setting ring %s:%s (%i:%i) at writer ring index %i\n",
                                   *interface,
                                   *filename,
                                   nic_idx,
                                   disk_idx,
                                   writer_ring_idx);

            ring_istreams[writer_ring_idx] = ring;
        }

    }

}


/*
 * Signal handler tells all threads to stop, but you can force exit by
 * sending a second signal
 */

static exact_stats_t* stats = NULL;
static exact_stats_sample_t stats_sample_stop  = {0};
static void signal_handler (int signum)
{
    ch_log_debug1("Caught signal %li, sending shut down signal\n", signum);
    printf("\n");
    if(!listener_stop)
    {
        listener_stop = 1;

        //Take a sample immediately after stopping
        estats_take_sample(stats, &stats_sample_stop);

        return;
    }

    /* We've been here before. Hard stop! */
    writer_stop = 1;
    ch_log_warn("Caught hard exit. Stopping now without cleanup. \n");
    exit(1);

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

    ch_opt_addSU (CH_OPTION_REQUIRED, 'i', "interface",         "Interface(s) to listen on",                        &options.ifaces);
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
    ch_opt_addbi (CH_OPTION_FLAG,     'N', "no-color",          "Disable colored logging",                          &options.no_color, false);

    ch_opt_parse (argc, argv);

    fprintf(stderr,"Exact-Capture %i.%i%s (%08X-%08X)\n",
                EXACT_MAJOR_VER, EXACT_MINOR_VER, EXACT_VER_TEXT,
                BRING_SLOT_SIZE, BRING_SLOT_COUNT);
    fprintf(stderr,"Copyright Exablaze Pty Ltd 2018\n");

    /*************************************************************************/
    /* Check preconditions and options arguments                             */
    /*************************************************************************/


#ifndef NDEBUG
    fprintf(stderr,"Warning: This is a debug build, performance may be affected\n");
#endif

#ifndef NOIFASSERT
    fprintf(stderr,"Warning: This is an assertion build, performance may be affected\n");
#endif

    if(!options.no_kernel)
        fprintf(stderr,"Warning: --no-kernel flag is not set, performance may be affected\n");


    ch_log_settings_t ch_log_settings_default = _ch_log_settings_default_color;

    ch_log_settings.use_color = !options.no_color;
    for(int i = 0; i < CH_LOG_LVL_COUNT; i++)
    {
        ch_log_settings.lvl_config[i].timestamp = !options.no_log_ts;
        ch_log_settings.lvl_config[i].source    = options.debug_log;
        ch_log_settings.lvl_config[i].pid       = options.debug_log;
        if(!options.no_color)
        {
            ch_log_settings.lvl_config[i].color     =
                    ch_log_settings_default.lvl_config[i].color;

        }
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

    remove_dups(options.ifaces);
    remove_dups(options.dests);

    const int64_t ifaces_count = options.ifaces->count;
    const int64_t dests_count  = options.dests->count;
    const int64_t conns_count  = ifaces_count * dests_count;

//    max_file_size = options.max_file;
//    max_pkt_len = options.snaplen;
//    min_pcap_rec = MIN(sizeof(pcap_pkthdr_t) + sizeof(expcap_pktftr_t),MIN_ETH_PKT);
//    max_pcap_rec = min_pcap_rec + max_pkt_len;

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


    /*************************************************************************/
    /* Initialize state and kick off listener / writer threads               */
    /*************************************************************************/

//    int64_t max_pkt_len;
//    int64_t min_pcap_rec;
//    int64_t max_pcap_rec;
//    int64_t max_file_size;



    /* Statically define these for now, the numbers will be small */
    lparams_t* const lparams_list = calloc(sizeof(lparams_t), ifaces_count);
    wparams_t* const wparams_list = calloc(sizeof(wparams_t), ifaces_count);
    if(!lparams_list || !wparams_list)
    {
        ch_log_fatal("Could not allocate memory for thread parameters\n");
    }

    int64_t sleep_time_ns = (int64_t)(options.log_report_int_secs * 1000 * 1000 * 1000);

    exact_stats_sample_t stats_sample_start = {0};
    exact_stats_sample_t stats_sample_now   = {0};
    exact_stats_sample_t stats_sample_prev  = {0};

    stats = estats_init(options.verbose,
                        options.more_verbose_lvl,
                        lparams_list,
                        ifaces_count,
                        wparams_list,
                        dests_count
                        );

    if(!stats)
    {
        ch_log_fatal("Could not allocate statistics keeping memory\n");
    }

    //Allocate all I/O streams (NICs, Disks and rings to join threads)
    eio_stream_t** const nic_istreams  = calloc(sizeof(eio_stream_t*), ifaces_count);
    eio_stream_t** const ring_ostreams = calloc(sizeof(eio_stream_t*), conns_count);
    eio_stream_t** const ring_istreams = calloc(sizeof(eio_stream_t*), conns_count);
    eio_stream_t** const disk_ostreams = calloc(sizeof(eio_stream_t*), dests_count);

    if(!nic_istreams || !ring_ostreams || !ring_istreams || !disk_ostreams)
    {
        ch_log_fatal("Could not allocate memory iostreams\n");
    }


    allocate_iostreams(nic_istreams, ring_ostreams, ring_istreams, disk_ostreams, options.snaplen, options.max_file);
    CH_VECTOR(pthread)* lthreads = start_listener_threads(cpus.listeners,lparams_list,nic_istreams,ring_ostreams,&listener_stop);
    CH_VECTOR(pthread)* wthreads = start_writer_threads(cpus.writers, wparams_list,ring_istreams,disk_ostreams,&writer_stop);

    /* Allow management to run on any core, but not on listener cores */
    cpu_set_t cpus_man;
    CPU_ZERO(&cpus_tmp);
    for(int i = 0; i < 16; i++) CPU_SET(i,&cpus_man); //Assume no more than 256 cores...
    CPU_XOR(&cpus_man, &cpus.listeners,&cpus_man); //Invert the listener CPUs
    if (sched_setaffinity (0, sizeof(cpu_set_t), &cpus_man))
    {
        ch_log_fatal("Could not set management CPUs affinity\n");
    }
    if(nice(-10) == -1)
    {
        ch_log_warn("Failed to change thread priority."
                       "Performance my be affected! (%s)\n", strerror(errno));
    }

    /*************************************************************************/
    /* Main thread - Real work begins here!                                  */
    /*************************************************************************/
    result = 0;

    estats_take_sample(stats, &stats_sample_start);
    stats_sample_prev = stats_sample_start;

    int spinner_idx = 0;
    #define spinner_len 4
    char spinner[spinner_len] = {'|','/', '-', '\\'};
    if(!(options.verbose || options.more_verbose_lvl) && !options.no_spinner)
        fprintf(stderr,"Exact Capture running... %c \r", spinner[spinner_idx]);

    if(options.log_file)
        ch_log_info("Exact Capture running...\n");


    while (!listener_stop)
    {

        if(!(options.verbose || options.more_verbose_lvl) && !options.no_spinner)
        {
            fprintf(stderr,"Exact Capture running... %c \r", spinner[spinner_idx]);
            spinner_idx++;
            spinner_idx %= spinner_len;
        }

        /*
         * Thead spends most of its time sleeping, except when it wakes up
         * to do stats (if at all)
         */
        usleep(sleep_time_ns/1000);

        if(options.verbose || options.more_verbose_lvl)
        {
            estats_take_sample(stats, &stats_sample_now);
            estats_output(stats, &stats_sample_now, &stats_sample_prev);
            stats_sample_prev = stats_sample_now;
        }
    }


    /*************************************************************************/
    /* Main thread - Clean up after main thread exit                         */
    /*************************************************************************/

    ch_log_debug1("Stopping all listener threads.\n");
    listener_stop = true;
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
    writer_stop = true;
    ch_log_debug1("Waiting for writer threads to die...\n");
    for (pthread_t* wthread = wthreads->first; wthread < wthreads->end;
            wthread = wthreads->next (wthreads, wthread))
    {
        pthread_join (*wthread, NULL);
    }
    ch_log_debug1("All writer threads dead.\n");



    estats_output(stats, &stats_sample_stop, &stats_sample_prev);
//    estats_output_summary(stats, &stats_sample_stop, &stats_sample_start);
//    estats_destroy(stats);

    return result;
}
