/*
 * Copyright (c) 2017, 2018 All rights reserved.
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

#define BRING_SEQ_MASK (~0xFFFFFFFFULL)

//_Static_assert(
//    (sizeof(bring_slot_header_t) / sizeof(uint64_t)) * sizeof(uint64_t) == sizeof(bring_slot_header_t),
 //   "Slot header must be a multiple of 1 word for atomicity"
//);
//_Static_assert( sizeof(void*) == sizeof(uint64_t) , "Machine word must be 64bits");
//_Static_assert( sizeof(bring_slot_header_t) == 4096 , "Bring slot header must be 4kB");

//Header structure -- There is one of these for every
#define BRING_MAGIC_SERVER 0xC5f7C37C69627EFLL //Any value here is good as long as it's not zero
#define BRING_MAGIC_CLIENT ~(BRING_MAGIC_SERVER) //Any value here is good as long as it's not zero and not the same as above

typedef struct bring_header {
    volatile int64_t magic;                  //Is this memory ready yet?
    int64_t total_mem;              //Total amount of memory needed in the mmapped region


    int64_t rd_mem_start_offset;    //location of the memory region for reads
    int64_t rd_mem_len;             //length of the read memory region
    int64_t rd_slots;               //number of slots in the read region
    int64_t rd_slots_size;          //Size of each slot including the slot header
    int64_t rd_slot_usr_size;

    int64_t wr_mem_start_offset;
    int64_t wr_mem_len;
    int64_t wr_slots;
    int64_t wr_slots_size;
    int64_t wr_slot_usr_size;

} bring_header_t;

//Uses integer division to round up
#define round_up( value, nearest) ((( value + nearest -1) / nearest ) * nearest )
#define getpagesize() sysconf(_SC_PAGESIZE)

typedef struct bring_priv {
    int fd;
    char* name;
    bool eof;
    bool closed;
    bool isserver;
    int64_t slot_size;
    int64_t slot_count;

    bool expand;

    volatile bring_header_t* bring_head;
    //Read side variables
    char* rd_mem;          //Underlying memory to support shared mem transport
    int64_t rd_sync_counter;        //Synchronization counter to protect against loop around
    int64_t rd_index;               //Current index receiving data

    //Write side variables
    char* wr_mem;          //Underlying memory for the shared memory transport
    int64_t wr_sync_counter;        //Synchronization counter. The assumptions is that this will never wrap around.
    int64_t wr_index;               //Current slot for sending data

    //These values are returned to users
    bool writing;
    bool reading;

    bring_slot_header_t* rd_head;

    bring_slot_header_t* wr_head;


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

    if(priv->bring_head){
        munlock((void*)priv->bring_head,priv->bring_head->total_mem);
        munmap((void*)priv->bring_head,priv->bring_head->total_mem);
    }

    if(this->fd > -1){
        close(this->fd);
        this->fd = -1; //Make this reentrant safe
    }

    free(this);

    priv->closed = true;

}


//Read operations
static inline eio_error_t bring_read_acquire(eio_stream_t* this, char** buffer, int64_t* len,  int64_t* ts)
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

    //ch_log_debug3("Doing read acquire, looking at index=%li/%li\n", priv->rd_index, priv->bring_head->rd_slots );
    const bring_slot_header_t* curr_slot_head = priv->rd_head;

    ifassert( (volatile int64_t)(curr_slot_head->data_size) > priv->bring_head->rd_slot_usr_size){
        ch_log_fatal("Data size (%li)(0x%016X) is larger than memory size (%li), corruption has happened!\n",
                     curr_slot_head->data_size,curr_slot_head->data_size, priv->bring_head->rd_slot_usr_size);
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
        return EIO_ETRYAGAIN;
    }
    //If we get here, the slot number is ready for reading, look it up

    //Grab a timestamp as soon as we know there is data
    (void)ts;
    //eio_nowns(ts);

    ch_log_debug2("Got a valid slot seq=%li (%li/%li)\n", curr_slot_head->seq_no, priv->rd_index, priv->bring_head->rd_slots);
    *buffer = (char*)(curr_slot_head + 1);
    *len    = curr_slot_head->data_size;

    priv->reading = true;
    return EIO_ENONE;
}

static inline eio_error_t bring_read_release(eio_stream_t* this,  int64_t* ts)
{
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(!priv->reading){
        ch_log_fatal( "Error, acquire before release\n");
        return EIO_EACQUIRE;
    }

    const bring_slot_header_t * curr_slot_head = priv->rd_head;

    //Apply an atomic update to tell the write end that we received this data
    //Do a word aligned single word write (atomic)
    (*(volatile uint64_t*)&curr_slot_head->seq_no) = 0x0ULL;

    //ch_log_debug3("Done doing read release, at %p index=%li/%li, curreslot seq=%li\n", curr_slot_head, priv->rd_index, priv->bring_head->rd_slots, curr_slot_head->seq_no);

    priv->reading = false;

    //We're done. Increment the buffer index and wrap around if necessary -- this is faster than using a modulus (%)
    priv->rd_index++;
    priv->rd_index = priv->rd_index < priv->bring_head->rd_slots ? priv->rd_index : 0;
    priv->rd_head = (bring_slot_header_t*)(priv->rd_mem + (priv->bring_head->rd_slots_size * priv->rd_index));
    priv->rd_sync_counter++; //Assume this will never overflow. ~200 years for 1 nsec per op

    //Grab time stamp for this operation
    (void)ts;
    //eio_nowns(ts);
    return EIO_ENONE;
}

//Write operations
static inline eio_error_t bring_write_acquire(eio_stream_t* this, char** buffer, int64_t* len,  int64_t* ts)
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

    //Is there a new slot ready for writing?
    ch_log_debug3("Doing write acquire, looking at index=%li/%li %p %li\n", priv->wr_index, priv->bring_head->wr_slots, priv->wr_head, (char*)priv->wr_head - (char*)priv->bring_head );
    const bring_slot_header_t * curr_slot_head = priv->wr_head;

    //ch_log_debug3("Doing write acquire, looking at %p index=%li, curreslot seq=%li\n",  hdr_mem, priv->wr_index,  curr_slot_head.seq_no);
    //This is actually a very likely path, but we want to preference the path when there is a slot
    ifunlikely( (volatile int64_t)curr_slot_head->seq_no != 0x00ULL){
        return EIO_ETRYAGAIN;
    }

    ifassert(*len > priv->bring_head->wr_slot_usr_size){
        return EIO_ETOOBIG;
    }

    //We're all good. A buffer is ready and waiting to to be acquired
    (void)ts;
    //eio_nowns(ts);
    *buffer = (char*)(curr_slot_head + 1);
    *len    = priv->bring_head->wr_slot_usr_size;
    priv->writing = true;

    ch_log_debug3(" Write acquire success - new buffer of size %li at %p (index=%li/%li)\n",   *len, *buffer, priv->wr_index, priv->bring_head->wr_slots);
    return EIO_ENONE;
}

static inline eio_error_t bring_write_release(eio_stream_t* this, int64_t len,  int64_t* ts)
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

    ifassert(len > priv->bring_head->wr_slot_usr_size){
        ch_log_fatal("Error: length supplied (%li) is larger than length of buffer (%li). Corruption likely. Aborting\n",  len, priv->bring_head->wr_slot_usr_size );
        exit(-1);
    }

    //Abort sending
    ifunlikely(len == 0){
        priv->writing = false;
        eio_nowns(ts);
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


    ch_log_debug2("Done doing write release, at %p index=%li/%li, curreslot seq=%li (%li)\n", curr_slot_head, priv->wr_index, priv->bring_head->wr_slots, curr_slot_head->seq_no, priv->wr_sync_counter);

    //Increment and wrap around if necessary, this is faster than a modulus
    priv->wr_index++;
    priv->wr_index = priv->wr_index < priv->bring_head->wr_slots ? priv->wr_index : 0;
    priv->wr_head = (bring_slot_header_t*)(priv->wr_mem + (priv->bring_head->wr_slots_size * priv->wr_index));
    priv->writing = false;

    (void)ts;
    //eio_nowns(ts);
    return EIO_ENONE;
}


static inline eio_error_t eio_bring_server_connect(eio_stream_t* this)
{

    int64_t result = 0;
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ch_log_debug3("Making bring server called %s\n",   priv->name);

    //See if a bring file already exists, if so, get rid of it.
    ch_log_debug1("Checking for a stale bring called %s\n",priv->name );
    int bring_fd = shm_open(priv->name, O_RDONLY,(mode_t)(0666));
    if(bring_fd > 0){
        ch_log_error("Found stale bring file at \"/dev/shm/%s\". Please restart in a clean state\n", priv->name  );
        close(bring_fd);
        if( shm_unlink(priv->name) < 0){
            ch_log_error("Could not remove stale bring file \"/dev/shm/%s\". Error=%s\n",   priv->name, strerror(errno));
            result = EIO_EINVALID;
            goto error_no_cleanup;
        }
        //Since there is a stale bring, kill everyting and start again
        exit(1);
        return EIO_ECLOSED;
    }

    ch_log_debug1("Making bring called %s with %lu slots of size %lu\n",
            priv->name,
            priv->slot_count,
            priv->slot_size
    );
    bring_fd = shm_open(priv->name, O_RDWR | O_CREAT | O_TRUNC , (mode_t)(0666));
    if(bring_fd < 0){
        ch_log_fatal("Could not open file \"%s\". Error=%s\n",   priv->name, strerror(errno));
        result = EIO_EINVALID;
        goto error_no_cleanup;

    }

    //Calculate the amount of memory we will need
    //Each slot has a requested size, plus some header
    const int64_t mem_per_slot      = priv->slot_size + sizeof(bring_slot_header_t);
    //Round up each slot so that it's a multiple of 64bits.
    const int64_t slot_aligned_size = round_up(mem_per_slot, getpagesize());
    //Figure out the total memory commitment for slots
    const int64_t mem_per_ring      = slot_aligned_size * priv->slot_count;
    //Allocate for both server-->client and client-->server connections
    const int64_t total_ring_mem    = mem_per_ring * 2;
    //Include the memory required for the headers -- Make sure there's a place for the synchronization pointer
    const int64_t header_mem        = round_up(sizeof(bring_header_t),getpagesize());
    //All memory required
    const int64_t total_mem_req     = total_ring_mem + header_mem;

    ch_log_debug1("Server calculated memory requirements\n");
    ch_log_debug1("-------------------------\n");
    ch_log_debug1("mem_per_slot   %li\n",   mem_per_slot);
    ch_log_debug1("slot_sligned   %li\n",   slot_aligned_size);
    ch_log_debug1("mem_per_ring   %li\n",   mem_per_ring);
    ch_log_debug1("total_ring_mem %li\n",   total_ring_mem);
    ch_log_debug1("header_mem     %li\n",   header_mem);
    ch_log_debug1("total_mem_req  %li\n",   total_mem_req);
    ch_log_debug1("-------------------------\n");

    //Resize the file
    if(ftruncate(bring_fd,sizeof(bring_header_t))){
        ch_log_error( "Could not resize shared region \"%s\" to size=%li. Error=%s\n",
                priv->name,
                sizeof(bring_header_t),
                strerror(errno)
        );
        result = EIO_EINVALID;
        goto close_file_error;
    }

    //Map the file into memory
    void* mem = mmap( NULL, total_mem_req, PROT_READ | PROT_WRITE, MAP_SHARED, bring_fd, 0);
    if(mem == MAP_FAILED){
        ch_log_error("Could not memory map bring file \"%s\". Error=%s\n",   priv->name, strerror(errno));
        result = EIO_EINVALID;
        goto  close_file_error;
    }

    //Memory must be page aligned otherwise we're in trouble (TODO - could pass alignment though the file and check..)
    ch_log_debug1("memory mapped at address =%p\n",   mem);
    if( ((uint64_t)mem) != (((uint64_t)mem) & ~0xFFF)){
        ch_log_error("Could not memory map bring file \"%s\". Error=%s\n",   priv->name, strerror(errno));
        result = EIO_EINVALID;
        goto  close_file_error;
    }


    //Populate all the right offsets
    volatile bring_header_t* bring_head = (volatile void*)mem;;
    priv->bring_head                    = bring_head;
    bring_head->total_mem               = total_mem_req;
    bring_head->rd_mem_start_offset     = header_mem;
    bring_head->rd_mem_len              = priv->expand ? round_up(mem_per_ring,getpagesize()) : mem_per_ring;
    bring_head->rd_slots_size           = slot_aligned_size;
    bring_head->rd_slot_usr_size        = priv->slot_size;
    bring_head->rd_slots                = bring_head->rd_mem_len / bring_head->rd_slots_size;
    bring_head->wr_mem_start_offset     = round_up(bring_head->rd_mem_start_offset + bring_head->rd_mem_len, getpagesize());
    bring_head->wr_mem_len              = priv->expand ? round_up(mem_per_ring,getpagesize()) : mem_per_ring;
    bring_head->wr_slots_size           = slot_aligned_size;
    bring_head->wr_slot_usr_size        = priv->slot_size;
    bring_head->wr_slots                = bring_head->wr_mem_len / bring_head->wr_slots_size;



    //Here's some debug to figure out if the mappings are correct
//    const int64_t rd_end_offset = bring_head->rd_mem_start_offset + bring_head->rd_mem_len -1;
//    const int64_t wr_end_offset = bring_head->wr_mem_start_offset + bring_head->wr_mem_len -1;
//    (void)rd_end_offset;
//    (void)wr_end_offset;
//    ch_log_debug3("Server set bring memory offsets\n");
//    ch_log_debug3("-------------------------\n");
//    ch_log_debug3("total_mem            %016lx (%li)\n",   bring_head->total_mem, bring_head->total_mem);
//    ch_log_debug3("rd_slots             %016lx (%li)\n",   bring_head->rd_slots,  bring_head->rd_slots);
//    ch_log_debug3("rd_slots_size        %016lx (%li)\n",   bring_head->rd_slots_size, bring_head->rd_slots_size);
//    ch_log_debug3("rd_slots_usr_size    %016lx (%li)\n",   bring_head->rd_slot_usr_size, bring_head->rd_slot_usr_size);
//    ch_log_debug3("rd_mem_start_offset  %016lx (%li)\n",   bring_head->rd_mem_start_offset, bring_head->rd_mem_start_offset);
//    ch_log_debug3("rd_mem_len           %016lx (%li)\n",   bring_head->rd_mem_len, bring_head->rd_mem_len);
//    ch_log_debug3("rd_mem_end_offset    %016lx (%li)\n",   rd_end_offset, rd_end_offset);
//
//    ch_log_debug3("wr_slots             %016lx (%li)\n",   bring_head->wr_slots,  bring_head->wr_slots);
//    ch_log_debug3("wr_slots_size        %016lx (%li)\n",   bring_head->wr_slots_size, bring_head->wr_slots_size);
//    ch_log_debug3("wr_slots_usr_size    %016lx (%li)\n",   bring_head->wr_slot_usr_size, bring_head->wr_slot_usr_size);
//    ch_log_debug3("wr_mem_start_offset  %016lx (%li)\n",   bring_head->wr_mem_start_offset,bring_head->wr_mem_start_offset);
//    ch_log_debug3("wr_mem_len           %016lx (%li)\n",   bring_head->wr_mem_len, bring_head->wr_mem_len);
//    ch_log_debug3("wr_mem_end_offset    %016lx (%li)\n",   wr_end_offset, wr_end_offset);
//    ch_log_debug3("-------------------------\n");


    ch_log_debug1("Done creating bring called %s with %lu slots of size %lu, usable size %lu\n",
            priv->name,
            priv->bring_head->rd_slots,
            priv->bring_head->rd_slots_size,
            priv->bring_head->rd_slots_size - sizeof(bring_slot_header_t)
    );

    priv->fd = bring_fd;

    //Finally, tell the client that we're ready to party
    //1 - Make sure all the memory writes are done
    __sync_synchronize();
    //2 - Do a word aligned single word write (atomic)
    priv->bring_head->magic = BRING_MAGIC_SERVER;
    __sync_synchronize();


    ch_log_debug1("Waiting for client to connect to bring %s...\n",  priv->name);
    for(int i = 0; ; i++){
        __sync_synchronize();
        if( priv->bring_head->magic == BRING_MAGIC_CLIENT){
            break;
        }
        __sync_synchronize();

        usleep(100*1000);
        if(i > 100 && i % 100 == 0){
            ch_log_warn("Still waiting for client to connect magic=%li, expecting %lli\n",
                        priv->bring_head->magic,BRING_MAGIC_CLIENT);
        }

        if( i > 1000){
            ch_log_error("Timed out waiting for client to connect\n");
            goto close_file_error;
        }
    }
    ch_log_debug1("Waiting for client to connect to bring %s...Done\n", priv->name);



    priv->closed = 0;
    result = EIO_ENONE;
    return result;

close_file_error:
    close(bring_fd);
    return result;

error_no_cleanup:
    return result;

}

static eio_error_t eio_bring_client_connect(eio_stream_t* this)
{
    int64_t result = 0;
    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);


    //Calculate the amount of memory we will need
    //Each slot has a requested size, plus some header
    const int64_t mem_per_slot      = priv->slot_size + sizeof(bring_slot_header_t);
    //Round up each slot so that it's a multiple of 64bits.
    const int64_t slot_aligned_size = round_up(mem_per_slot, getpagesize());
    //Figure out the total memory commitment for slots
    const int64_t mem_per_ring      = slot_aligned_size * priv->slot_count;
    //Allocate for both server-->client and client-->server connections
    const int64_t total_ring_mem    = mem_per_ring * 2;
    //Include the memory required for the headers -- Make sure there's a place for the synchronization pointer
    const int64_t header_mem        = round_up(sizeof(bring_header_t),getpagesize());
    //All memory required
    const int64_t total_mem_req     = total_ring_mem + header_mem;

    ch_log_debug1("Client calculated memory requirements\n");
    ch_log_debug1("-------------------------\n");
    ch_log_debug1("mem_per_slot   %li\n",   mem_per_slot);
    ch_log_debug1("slot_sligned   %li\n",   slot_aligned_size);
    ch_log_debug1("mem_per_ring   %li\n",   mem_per_ring);
    ch_log_debug1("total_ring_mem %li\n",   total_ring_mem);
    ch_log_debug1("header_mem     %li\n",   header_mem);
    ch_log_debug1("total_mem_req  %li\n",   total_mem_req);
    ch_log_debug1("-------------------------\n");


    //Now there is a bring file and it should have a header in it
    int bring_fd = shm_open(priv->name, O_RDWR, (mode_t)(0666));
    if(bring_fd < 0){
        //ch_log_debug3("Could not open named shared memory file \"%s\". Error=%s\n",   priv->filename, strerror(errno));
        result = EIO_ETRYAGAIN;
        goto error_no_cleanup;
    }

    ch_log_debug1("Doing bring connect client on %s\n",   priv->name);
//
//    //Resize the file big enough to read the bring header only
//    if(ftruncate(bring_fd,sizeof(bring_header_t))){
//        ch_log_error( "Could not resize shared region \"%s\" to size=%li. Error=%s\n",
//                priv->name,
//                sizeof(bring_header_t),
//                strerror(errno)
//        );
//        result = EIO_EINVALID;
//        goto error_close_file;
//    }
//
//    //Map the file into memory
//    void* mem_tmp = mmap( NULL, sizeof(bring_header_t), PROT_READ, MAP_SHARED, bring_fd, 0);
//    if(mem_tmp == MAP_FAILED){
//        ch_log_error("Could not memory map bring file \"%s\". Error=%s\n",   priv->name, strerror(errno));
//        result = EIO_EINVALID;
//        goto  error_close_file;
//    }
//
//    //Memory must be page aligned otherwise we're in trouble (TODO - could pass alignment though the file and check..)
//    //ch_log_debug3("memory mapped at address =%p\n",   mem);
//    if( ((uint64_t)mem_tmp) != (((uint64_t)mem_tmp) & ~0xFFF)){
//        ch_log_error("Could not memory map bring file \"%s\". Error=%s\n",   priv->name, strerror(errno));
//        result = EIO_EINVALID;
//        goto  error_close_file;
//    }
//
//    //This is a sort of nasty atomic access. Which doesn't leave crap lying around like POSIX semaphores do
//    ch_log_debug1("Looking for bring header on %s\n", priv->name);
//    bring_header_t* header_tmp_ptr = mem_tmp;
//    __sync_synchronize();
//    while(header_tmp_ptr->magic != BRING_MAGIC_SERVER){
//        __sync_synchronize();
//        usleep(100 * 1000);
//    }
//    ch_log_debug1("Looking for bring header... Done.\n");
//
//    bring_header_t header_tmp = *(bring_header_t*)(mem_tmp);
////    ch_log_debug1("Got bring header\n");
////    ch_log_debug1("Client read bring memory offsets\n");
////    ch_log_debug1("-------------------------\n");
////    ch_log_debug1("total_mem            %016lx (%li)\n",   header_tmp.total_mem, header_tmp.total_mem);
////    ch_log_debug1("rd_slots             %016lx (%li)\n",   header_tmp.rd_slots,  header_tmp.rd_slots);
////    ch_log_debug1("rd_slots_size        %016lx (%li)\n",   header_tmp.rd_slots_size, header_tmp.rd_slots_size);
////    ch_log_debug1("rd_slots_usr_size    %016lx (%li)\n",   header_tmp.rd_slot_usr_size, header_tmp.rd_slot_usr_size);
////    ch_log_debug1("rd_mem_start_offset  %016lx (%li)\n",   header_tmp.rd_mem_start_offset, header_tmp.rd_mem_start_offset);
////    ch_log_debug1("rd_mem_len           %016lx (%li)\n",   header_tmp.rd_mem_len, header_tmp.rd_mem_len);
////    ch_log_debug1("wr_slots             %016lx (%li)\n",   header_tmp.wr_slots,  header_tmp.wr_slots);
////    ch_log_debug1("wr_slots_size        %016lx (%li)\n",   header_tmp.wr_slots_size, header_tmp.wr_slots_size);
////    ch_log_debug1("wr_slots_usr_size    %016lx (%li)\n",   header_tmp.wr_slot_usr_size, header_tmp.wr_slot_usr_size);
////    ch_log_debug1("wr_mem_start_offset  %016lx (%li)\n",   header_tmp.wr_mem_start_offset,header_tmp.wr_mem_start_offset);
////    ch_log_debug1("wr_mem_len           %016lx (%li)\n",   header_tmp.wr_mem_len, header_tmp.wr_mem_len);
////    ch_log_debug1("-------------------------\n");
//
//    munmap(mem_tmp, sizeof(bring_header_t));//Done with the temporary mapping, do the real one now

    if(ftruncate(bring_fd,total_mem_req)){
        ch_log_error( "Could not resize shared region \"%s\" to size=%li. Error=%s\n",
                      priv->name,
                      total_mem_req,
                      strerror(errno)
        );
        result = EIO_EINVALID;
        goto error_close_file;
    }

    void* mem = mmap( NULL, total_mem_req, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB , bring_fd, 0);
    if(mem == MAP_FAILED){
        ch_log_error("Could not memory map bring file \"%s\". Error=%s\n",   priv->name, strerror(errno));
        result = EIO_EINVALID;
        goto  error_close_file;
    }

    //Memory must be page aligned otherwise we're in trouble (TODO - could pass alignment though the file and check..)
    //ch_log_debug3("memory mapped at address =%p\n",   mem);
    if( ((uint64_t)mem) != (((uint64_t)mem) & ~0xFFF)){
        ch_log_error("Could not memory map bring file \"%s\". Error=%s\n",   priv->name, strerror(errno));
        result = EIO_EINVALID;
        goto  error_close_file;
    }

    //Pin the pages so that they don't get swapped out
    if(mlock(mem,total_mem_req)){
        ch_log_fatal("Could not lock memory map. Error=%s\n",   strerror(errno));
        //result = EIO_EINVALID;
        //goto  error_unmap_file;
    }

    //Remove the filename from the filesystem. Since the and reader are both still connected
    //to the file, the space will continue to be available until they both exit.
    if(shm_unlink(priv->name) < 0){
        ch_log_error("Could not remove bring file \"%s\". Error = \"%s\"\n",   priv->name, strerror(errno));
        result = EIO_EINVALID;
        goto error_unlock_mem;
    }

    priv->closed     = false;
    priv->fd         = bring_fd;
    priv->bring_head = mem;

    //Finally, tell the client that we're ready to party
    //1 - Make sure all the memory writes are done
    __sync_synchronize();
    //2 - Do a word aligned single word write (atomic)
    priv->bring_head->magic = BRING_MAGIC_CLIENT;
    __sync_synchronize();

    ch_log_debug1("Done connecting to bring called %s with %lu slots of size %lu, usable size %lu\n",
            priv->name,
            priv->bring_head->rd_slots,
            priv->bring_head->rd_slots_size,
            priv->bring_head->rd_slots_size - sizeof(bring_slot_header_t),
            priv->bring_head->magic
    );

    return EIO_ENONE;

error_unlock_mem:
    munlock(mem, total_mem_req);

//error_unmap_file:
    munmap(mem, total_mem_req);

error_close_file:
    close(bring_fd);

error_no_cleanup:
    return result;
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

    const char* filename       = args->filename;
    const uint64_t slot_size   = args->slot_size;
    const uint64_t slot_count  = args->slot_count;
    const uint64_t isserver    = args->isserver;
    const uint64_t dontexpand  = args->dontexpand;

    bring_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    //Make a local copy of the filename in case the supplied name goes away
    const uint16_t name_len = strnlen(filename,1024); //Safety bug here? What's a reasonable max on filename size?
    priv->name = calloc(1, name_len + 1);
    if(!priv->name){
        ch_log_debug3("Could allocate filename buffer for file \"%s\". Error=%s\n",   filename, strerror(errno));
        bring_destroy(this);
        return -2;
    }
    memcpy(priv->name, filename, name_len);

    priv->slot_count = slot_count;
    priv->slot_size  = slot_size;
    priv->isserver   = isserver;
    priv->eof        = 0;
    priv->expand     = !dontexpand;
    priv->rd_sync_counter = 1; //This will be the first valid value
    ch_log_debug3("priv->rd_sync_counter=%i\n", priv->rd_sync_counter);


    int64_t err = EIO_ETRYAGAIN;
    while(err == EIO_ETRYAGAIN){
        if(isserver){
            err = eio_bring_server_connect(this);
            if(!err){
                priv->rd_mem  = (char*)priv->bring_head + priv->bring_head->rd_mem_start_offset;
                priv->wr_mem  = (char*)priv->bring_head + priv->bring_head->wr_mem_start_offset;
                priv->rd_head = (bring_slot_header_t*)priv->rd_mem;
                priv->wr_head = (bring_slot_header_t*)priv->wr_mem;
                return err;
            }
        }
        else{
            err = eio_bring_client_connect(this);
            if(!err){
                //Swap read and write pointers here for the client
                priv->wr_mem = (char*)priv->bring_head + priv->bring_head->rd_mem_start_offset;
                priv->rd_mem = (char*)priv->bring_head + priv->bring_head->wr_mem_start_offset;
                priv->rd_head = (bring_slot_header_t*)priv->rd_mem;
                priv->wr_head = (bring_slot_header_t*)priv->wr_mem;
                return err;
            }
        }
        //usleep(100); //No point in spinning too hard here
    }

    return err;
}


NEW_IOSTREAM_DEFINE(bring, bring_args_t, bring_priv_t)
