/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Implementation of a memory mapped "blocking ring" or circular queue to join
 *  listener and writer threads.
 */

#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/shm.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */



#include <chaste/chaste.h>
#include <chaste/utils/util.h>

#include "exactio_bring.h"

#include "exactio_timing.h"



typedef struct slot_header_s{
    volatile int64_t seq_no;
    //Pad out to a single cacheline size to avoid cachline boundcing
    char padding_1[64 - sizeof(int64_t)];
    int64_t data_size;
    char padding_2[4096 - sizeof(int64_t) - 64];
} bring_slot_header_t;


//Uses integer division to round up
#define round_up( value, nearest) ((( value + nearest -1) / nearest ) * nearest )
#define getpagesize() sysconf(_SC_PAGESIZE)

typedef struct bring_priv {
    int fd;
    bool eof;
    bool closed;
    int64_t slot_size;
    int64_t slot_count;

    bool expand;

    char* ring_mem;             //location of the memory region for reads
    int64_t ring_mem_len;       //length of the read memory region
    int64_t slots;              //number of slots in the read region
    int64_t slots_size;         //Size of each slot including the slot header
    int64_t slot_usr_size;      //Size of the slot as restured to the user

    //Read side variables
    bool reading;
    int64_t rd_sync_counter;    //Synchronization counter to protect against loop around
    int64_t rd_index;           //Current index receiving data
    bring_slot_header_t* rd_head;

    //Write side variables
    bool writing;
    int64_t wr_sync_counter;    //Synchronization counter. The assumptions is that this will never wrap around.
    int64_t wr_index;           //Current slot for sending data
    bring_slot_header_t* wr_head;


    //Variables for statistics keeping
    int rd_pid;                 //Linux PID for the read thread, used for stats
    FILE* rd_proc_stats_f;      //FD for the proc stats file
    int wr_pid;                 //Linux PID for the write thread, used for stats
    FILE* wr_proc_stats_f;      //FD for the proc stats file
    bring_stats_sw_t stats_sw_rd; //Software based statistics for read side
    bring_stats_sw_t stats_sw_wr; //Software based statistics for write side

    int64_t id_major;
    int64_t id_minor;

} bring_priv_t;

static void bring_destroy(eio_stream_t* this)
{

    //Basic sanity checks -- TODO XXX: Should these be made into (compile time optional?) asserts for runtime performance?
    if( NULL == this){
        ch_log_error("This null???\n"); //WTF?
        return;
    }
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        ch_log_error( "Error, stream is closed\n");
        return;
    }

    if(priv->rd_proc_stats_f){
        fclose(priv->rd_proc_stats_f);
        priv->rd_proc_stats_f = NULL;
    }

    if(priv->wr_proc_stats_f){
        fclose(priv->wr_proc_stats_f);
        priv->wr_proc_stats_f = NULL;
    }

    if(this->fd > -1){
        close(this->fd);
        this->fd = -1; //Make this reentrant safe
    }


    if(this->name)
    {
        free(this->name);
        this->name = NULL;
    }


    free(this);

    priv->closed = true;

}


//Read operations
static inline eio_error_t bring_read_acquire(eio_stream_t* this, char** buffer, int64_t* len,  int64_t* ts, int64_t* ts_hz)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(priv->closed){
        ch_log_debug3( "Error, stream now closed\n");
        return EIO_ECLOSED;
    }

    ifassert(priv->reading){ //Release buffer before acquire
        ch_log_fatal( "Error, release buffer before acquiring\n");
        return EIO_ERELEASE;
    }

    ifunlikely(!priv->rd_pid){
        pid_t tid;
        tid = syscall(SYS_gettid);
        priv->rd_pid = tid;
    }

    //ch_log_debug3("Doing read acquire, looking at index=%li/%li\n", priv->rd_index, priv->rd_slots );
    const bring_slot_header_t* curr_slot_head = priv->rd_head;

    ifassert( (volatile int64_t)(curr_slot_head->data_size) > priv->slot_usr_size){
        ch_log_fatal("Data size (%li)(0x%016X) is larger than memory size (%li), corruption has happened!\n",
                     curr_slot_head->data_size,curr_slot_head->data_size, priv->slot_usr_size);
        return EIO_ETOOBIG;
    }

    ifassert( (volatile int64_t)curr_slot_head->seq_no > priv->rd_sync_counter){
        ch_log_fatal( "Ring overflow. This should never happen with a blocking ring current slot seq=%li (0x%016X) to rd_sync=%li\n",
                curr_slot_head->seq_no,
                curr_slot_head->seq_no,
                priv->rd_sync_counter
        );
    }

    //This path is actually very likely, but we want to preference the alternative path
    ifunlikely( (volatile int64_t)curr_slot_head->seq_no < priv->rd_sync_counter){
        //ch_log_debug3( "Nothing yet to read, slot has not yet been updated\n");
        priv->stats_sw_rd.aq_miss++;
        return EIO_ETRYAGAIN;
    }
    //If we get here, the slot number is ready for reading, look it up

    (void)ts;
    (void)ts_hz;

    ch_log_debug2("Got a valid slot seq=%li (%li/%li)\n", curr_slot_head->seq_no, priv->rd_index, priv->slots);
    *buffer = (char*)(curr_slot_head + 1);
    *len    = curr_slot_head->data_size;
    priv->stats_sw_rd.aq_hit++;
    priv->stats_sw_rd.aq_bytes += *len;

    priv->reading = true;
    return EIO_ENONE;
}

static inline eio_error_t bring_read_release(eio_stream_t* this)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(!priv->reading){
        ch_log_fatal( "Error, acquire before release\n");
        return EIO_EACQUIRE;
    }

    const bring_slot_header_t * curr_slot_head = priv->rd_head;
    priv->stats_sw_rd.rl_bytes += curr_slot_head->data_size;

    //Apply an atomic update to tell the write end that we received this data
    //Do a word aligned single word write (atomic)
    (*(volatile uint64_t*)&curr_slot_head->seq_no) = 0x0ULL;

    //ch_log_debug3("Done doing read release, at %p index=%li/%li, curreslot seq=%li\n", curr_slot_head, priv->rd_index, priv->rd_slots, curr_slot_head->seq_no);

    priv->reading = false;

    //We're done. Increment the buffer index and wrap around if necessary -- this is faster than using a modulus (%)
    priv->rd_index++;
    priv->rd_index = priv->rd_index < priv->slots ? priv->rd_index : 0;
    priv->rd_head = (bring_slot_header_t*)(priv->ring_mem + (priv->slots_size * priv->rd_index));
    priv->rd_sync_counter++; //Assume this will never overflow. ~200 years for 1 nsec per op


    return EIO_ENONE;
}

static inline eio_error_t bring_read_sw_stats(eio_stream_t* this, void* stats)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    bring_stats_sw_t* bstats_sw = (bring_stats_sw_t*)stats;
    *bstats_sw = priv->stats_sw_rd;
	return EIO_ENONE;
}

static inline eio_error_t bring_hw_stats(int* pid, FILE** proc_stats_fp, bring_stats_hw_t* stats)
{
    ch_log_debug1("Trying to read bring hw stats on pid = %i with fd=%p\n", *pid, *proc_stats_fp);
    ifunlikely(!*pid){
        return EIO_ETRYAGAIN; //Nobody has called read aquire in the read thread
    }

    ifunlikely(!*proc_stats_fp){
        ch_log_debug1("Proc FD does not exist, allocating\n");

        int len = snprintf(NULL, 0, "/proc/%d/stat", *pid);
        char* proc_stat_file_path = calloc(len+1,1);
        if(!proc_stat_file_path){
            return EIO_ENOMEM;
        }
        snprintf(proc_stat_file_path, len+1, "/proc/%d/stat", *pid);


        ch_log_debug1("Opening \"%s\"\n", proc_stat_file_path);
        *proc_stats_fp = fopen(proc_stat_file_path,"r");

        if(*proc_stats_fp ==  NULL){
            ch_log_error("Could not open %s with error %s\n",
                         proc_stat_file_path, strerror(errno));
            *pid = 0;
            free(proc_stat_file_path);
            return EIO_EINVALID;
        }

        free(proc_stat_file_path);
    }

    fseek(*proc_stats_fp,0,0);

    int err = 0;
    err = fscanf(*proc_stats_fp,"%d %s %c %d %d %d %d %d %u %li %li %li %li %li %li",
                 &stats->pid, stats->comm, &stats->state, &stats->ppid, &stats->pgrp,
                 &stats->session, &stats->tty_nr, &stats->tpgid, &stats->flags,
                 &stats->minflt, &stats->cmajflt, &stats->majflt, &stats->cmajflt,
                 &stats->utime, &stats->stime);


    if(err == EOF){
        ch_log_error("Error reading proc/stats\n");
        *pid = 0;
        fclose(*proc_stats_fp);
        *proc_stats_fp = NULL;
        return EIO_EEOF;
    }

    return EIO_ENONE;

}


static inline eio_error_t bring_read_hw_stats(eio_stream_t* this, void* stats)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    return bring_hw_stats(&priv->rd_pid, &priv->rd_proc_stats_f, stats);
}



//Write operations
static inline eio_error_t bring_write_acquire(eio_stream_t* this, char** buffer, int64_t* len)
{
    //ch_log_debug3("Doing write acquire\n");

    ifassert( NULL == this){
        ch_log_fatal("This null???\n"); //WTF?
        return EIO_EINVALID;
    }

    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(priv->closed){
        ch_log_debug3( "Error, bring is closed\n");
        return EIO_ECLOSED;
    }

    ifassert(priv->writing){
        ch_log_fatal("Call release before calling acquire\n");
        return EIO_ERELEASE;
    }

    ifunlikely(!priv->wr_pid){
       pid_t tid;
       tid = syscall(SYS_gettid);
       priv->wr_pid = tid;
    }

    //Is there a new slot ready for writing?
    ch_log_debug3("Doing write acquire, looking at index=%li/%li %p\n", priv->wr_index, priv->slots, priv->wr_head);
    const bring_slot_header_t * curr_slot_head = priv->wr_head;

    //ch_log_debug3("Doing write acquire, looking at %p index=%li, curreslot seq=%li\n",  hdr_mem, priv->wr_index,  curr_slot_head.seq_no);
    //This is actually a very likely path, but we want to preference the path when there is a slot
    ifunlikely( (volatile int64_t)curr_slot_head->seq_no != 0x00ULL){
        priv->stats_sw_wr.aq_miss++;
        return EIO_ETRYAGAIN;
    }

    priv->stats_sw_wr.aq_hit++;

    ifassert(*len > priv->slot_usr_size){
        return EIO_ETOOBIG;
    }

    //We're all good. A buffer is ready and waiting to to be acquired
    *buffer = (char*)(curr_slot_head + 1);
    *len    = priv->slot_usr_size;
    priv->stats_sw_wr.aq_bytes += *len;

    priv->writing = true;

    ch_log_debug3(" Write acquire success - new buffer of size %li at %p (index=%li/%li)\n",   *len, *buffer, priv->wr_index, priv->slots);
    return EIO_ENONE;
}

static inline eio_error_t bring_write_release(eio_stream_t* this, int64_t len)
{
    ch_log_debug2("Doing write release %li\n", len); //WTF?

    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(priv->closed){
        return EIO_ECLOSED;
    }

    ifassert(!priv->writing){
        ch_log_fatal("Call acquire before calling release\n");
        return EIO_EACQUIRE;
    }

    ifassert(len > priv->slot_usr_size){
        ch_log_fatal("Error: length supplied (%li) is larger than length of buffer (%li). Corruption likely. Aborting\n",  len, priv->slot_usr_size );
        exit(-1);
    }

    //Abort sending
    ifunlikely(len == 0){
        priv->writing = false;
        return EIO_ENONE;
    }

    const bring_slot_header_t* curr_slot_head = priv->wr_head;

    priv->wr_sync_counter++;

    //Apply an atomic update to tell the read end that there is new data ready
    (*(volatile uint64_t*)&curr_slot_head->data_size) = len;
    __sync_synchronize();

    //Do a word aligned single word write (atomic)
    (*(volatile uint64_t*)&curr_slot_head->seq_no) = priv->wr_sync_counter;
    __sync_synchronize();


    ch_log_debug2("Done doing write release, at %p index=%li/%li, curreslot seq=%li (%li)\n", curr_slot_head, priv->wr_index, priv->slots, curr_slot_head->seq_no, priv->wr_sync_counter);

    //Increment and wrap around if necessary, this is faster than a modulus
    priv->wr_index++;
    priv->wr_index = priv->wr_index < priv->slots ? priv->wr_index : 0;
    priv->wr_head = (bring_slot_header_t*)(priv->ring_mem + (priv->slots_size * priv->wr_index));
    priv->stats_sw_wr.rl_bytes += len;

    priv->writing = false;

    return EIO_ENONE;
}

static inline eio_error_t bring_write_sw_stats(eio_stream_t* this, void* stats)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    bring_stats_sw_t* bstats_sw = (bring_stats_sw_t*)stats;
    *bstats_sw = priv->stats_sw_wr;

    return EIO_ENONE;
}

static inline eio_error_t bring_write_hw_stats(eio_stream_t* this, void* stats)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    return bring_hw_stats(&priv->wr_pid, &priv->wr_proc_stats_f, stats);
}



static inline eio_error_t eio_bring_allocate(eio_stream_t* this)
{

    int64_t result = 0;
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ch_log_debug3("Making a bring\n");

    ch_log_debug1("Making bring with %lu slots of size %lu\n",
            priv->slot_count,
            priv->slot_size
    );

    //Calculate the amount of memory we will need
    //Each slot has a requested size, plus some header
    const int64_t mem_per_slot      = priv->slot_size + sizeof(bring_slot_header_t);
    //Round up each slot so that it's a multiple of 64bits.
    const int64_t slot_aligned_size = round_up(mem_per_slot, getpagesize());
    //Figure out the total memory commitment for the ring
    const int64_t ring_mem_len      = slot_aligned_size * priv->slot_count;


    ch_log_debug1("Calculated memory requirements\n");
    ch_log_debug1("-------------------------\n");
    ch_log_debug1("mem_per_slot   %li     (%3.2fMB)\n",   mem_per_slot, mem_per_slot / 1024.0/ 1024.0);
    ch_log_debug1("slot_aligned   %li     (%3.2fMB)\n",   slot_aligned_size, slot_aligned_size/ 1024.0/ 1024.0);
    ch_log_debug1("ring_mem_len   %li     (%3.2fMB)\n",   ring_mem_len, ring_mem_len / 1024.0/ 1024.0);
    ch_log_debug1("ring_mem_len   %li Pgs (%3.2f 2MPgs)\n",   ring_mem_len / 4096, ring_mem_len / (1024 * 2048.0));
    ch_log_debug1("-------------------------\n");

    //Map the file into memory
    // MAP_PRIVATE   - This mapping
    // MAP_ANONYMOUS - there is no file to back this memory
    // MAP_LOCKED - we want to lock the pages into memory, so they aren't swapped out at runtime
    // MAP_NORESERVE - if pages are locked, there's no need for swap memeory to back this mapping
    // MAP_POPULATE -  We want to all the page table entries to be populated so that we don't get page faults at runtime
    // MAP_HUGETLB - Use huge TBL entries to minimize page faults at runtime.
    //
    void* mem = mmap( NULL, ring_mem_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_LOCKED | MAP_HUGETLB | MAP_POPULATE, -1, 0);
    //void* mem = mmap( NULL, ring_mem_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(mem == MAP_FAILED){
        ch_log_error("Could not create memory for bring \"%s\". Error=%s\n",  this->name, strerror(errno));
        result = EIO_EINVALID;
        goto error_no_cleanup;
    }

    //Memory must be page aligned otherwise we're in trouble
    ch_log_debug1("memory mapped at address =%p\n",   mem);
    if( ((uint64_t)mem) != (((uint64_t)mem) & ~0xFFF)){
        ch_log_error("Memory map is not page aligned. Is your systems strange??");
        result = EIO_EINVALID;
        goto error_unmap;
    }

    //Pin the pages so that they don't get swapped out
    if(mlock(mem,ring_mem_len)){
        //ch_log_warn("Could not lock memory map. Error=%s\n",   strerror(errno));
        ch_log_fatal("Could not lock memory map. Error=%s\n",   strerror(errno));
        result = EIO_EINVALID;
        goto error_unmap;

    }

    //Populate all the right values
    priv->ring_mem      = mem;
    priv->ring_mem_len  = priv->expand ? round_up(ring_mem_len,getpagesize()): ring_mem_len;
    priv->slots_size    = slot_aligned_size;
    priv->slot_usr_size = priv->slot_size;
    priv->slots         = ring_mem_len / priv->slots_size;

    ch_log_debug1("Done creating bring with %lu slots of size %lu, usable size %lu\n",
            priv->slots,
            priv->slots_size,
            priv->slots_size - sizeof(bring_slot_header_t)
    );

    priv->fd = -1;
    priv->closed = 0;
    result = EIO_ENONE;
    return result;


//error_unlock:
//    munlock(mem,total_mem_req);

error_unmap:
    munmap(mem,ring_mem_len);

error_no_cleanup:
    return result;

}


static eio_error_t bring_get_id(eio_stream_t* this, int64_t* id_major, int64_t* id_minor)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);


    ifassert(!id_major || !id_minor){
        return EIO_EINVALID;
    }

    *id_major = priv->id_major;
    *id_minor = priv->id_minor;

    return EIO_ENONE;
}

/*
 * Arguments
 * [0] filename
 * [1] slot size
 * [2] slot count
 * [3] isserver (bool)
 */
static eio_error_t bring_construct(eio_stream_t* this, bring_args_t* args)
{

    const uint64_t slot_size   = args->slot_size;
    const uint64_t slot_count  = args->slot_count;
    const uint64_t dontexpand  = args->dontexpand;
    const int64_t id_major     = args->id_major;
    const int64_t id_minor     = args->id_minor;
    const char* name           = args->name;
    const int64_t name_len = strnlen(name, 1024);
    this->name = calloc(name_len + 1, 1);
    memcpy(this->name, name, name_len);


    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    priv->slot_count = slot_count;
    priv->slot_size  = slot_size;
    priv->eof        = 0;
    priv->expand     = !dontexpand;
    priv->id_major   = id_major;
    priv->id_minor   = id_minor;
    priv->rd_sync_counter = 1; //This will be the first valid value


    int64_t err = EIO_ETRYAGAIN;
    err = eio_bring_allocate(this);
    if(!err){
        priv->rd_head = (bring_slot_header_t*)priv->ring_mem;
        priv->wr_head = (bring_slot_header_t*)priv->ring_mem;
    }

    return err;
}


NEW_IOSTREAM_DEFINE(bring, bring_args_t, bring_priv_t)
