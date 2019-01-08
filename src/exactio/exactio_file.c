/*
 * Copyright (c) 2017, 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Implementation of a file read/write interface using the exactio abstract I/O
 *  interface.
 */


#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <memory.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include <chaste/chaste.h>

#include "exactio_file.h"

#include "exactio_timing.h"

#define getpagesize() sysconf(_SC_PAGESIZE)

typedef enum {
    EXACTIO_FILE_MOD_IGNORE = 0,
    EXACTIO_FILE_MOD_RESET  = 1,
    EXACTIO_FILE_MOD_TAIL   = 2,
} exactio_file_mod_t;

typedef struct file_priv {
    int fd;
    char* filename;
    bool eof;
    bool closed;
    bool reading;
    bool writing;

    char* read_buff;

    int64_t read_buff_size;

    char* write_buff;
    int64_t write_buff_size;
    bool write_directio;
    int64_t write_max_file_size;
    int64_t total_bytes_written;
    uint64_t write_file_num;

    char* usr_write_buff;
    int64_t usr_write_buff_size;


    int64_t filesize;
    int64_t blocksize;

    exactio_file_mod_t read_on_mod; //0 ignore, 1 reset, 2, tail
    int notify_fd;
    int watch_descr;
    int watch_descr_delete;

} file_priv_t;


static void file_destroy(eio_stream_t* this)
{
    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    if(priv->read_buff){
        munlock(priv->read_buff, priv->read_buff_size);
        free(priv->read_buff);
        priv->read_buff = NULL;
    }

    if(priv->write_buff){
        munlock(priv->write_buff, priv->write_buff_size);
        free(priv->write_buff);
        priv->write_buff = NULL;
    }

    if(priv->notify_fd){
        close(priv->notify_fd);
        priv->notify_fd = -1;
    }

    if(priv->fd){
        close(priv->fd);
        priv->fd = -1;
    }

    if(this->name)
    {
        free(this->name);
        this->name = NULL;
    }

    priv->closed = true;

}

/**
 * Helper function to set the writer fd into "O_DIRECT" mode. This mode bypasses
 * the kernel and syncs the buffers directly to the disk. However, it requires
 * that data is block aligned, a multiple of block size and written to a block
 * aligned offset. It's hard to know what the right block size is sometimes 512B
 * sometimes 4kB. For simplicity, 4kB is assumed.
 */
static int set_direct (int desc, bool on)
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

static int file_open(eio_stream_t* this, bool allow_open_error)
{
    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    const char* filename = this->name;
    priv->fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, (mode_t)(0666));
    if(priv->fd < 0){
        if(!allow_open_error){
            return EIO_ETRYAGAIN;
        }

        ch_log_error("Could not open file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -7;
    }

    if(priv->write_directio){
        if(set_direct(priv->fd, true) < 0){
            ch_log_warn("Could not set O_DIRECTIO, performance may be affected\n");
        }

    }

    struct stat st;
    if(fstat(priv->fd,&st) < 0){
        ch_log_error("Cannot stat file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -8;
    }
    priv->filesize  = st.st_size;
    priv->blocksize = st.st_blksize;
    //ch_log_info("File size=%li, blocksize=%li\n", st.st_size, st.st_blksize);

    priv->eof          = 0;
    priv->closed      = false;

    this->fd          = priv->fd;

    if(priv->read_on_mod == 0){
        return 0; //Early exit, success!
    }

    //We'll be listening to notify operations, so set it up
    priv->notify_fd = inotify_init1(IN_NONBLOCK);
    if(priv->notify_fd < 0){
        ch_log_error("Could not start inotify for file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -9;
    }

    priv->watch_descr = inotify_add_watch(priv->notify_fd,filename, IN_MODIFY | IN_DELETE_SELF);
    if(priv->watch_descr < 0){
        ch_log_error("Could not begin to watch file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -10;
    }

    return EIO_ENONE;
}



//Read operations
static eio_error_t file_read_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts )
{
    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifunlikely(priv->closed){
        return EIO_ECLOSED;
    }

    ifassert(priv->reading){
        ch_log_error("Call read release before calling read acquire\n");
        return EIO_ERELEASE;
    }


    ifunlikely(priv->notify_fd && priv->eof){
        struct inotify_event notif = {0};
        const ssize_t read_result = read(priv->notify_fd, &notif, sizeof(notif));

        if(read_result <= 0){
            if(errno != EAGAIN && errno != EWOULDBLOCK){
                ch_log_error("Unexpected error reading notify \"%s\". Error=%s\n", this->name, strerror(errno));
                file_destroy(this);
                return EIO_ECLOSED;
            }
        }
        else if(read_result < (ssize_t)sizeof(notif)){
            ch_log_error("Unexpected error, notify structure too small \"%s\". Error=%s\n", this->name, strerror(errno));
            file_destroy(this);
            return EIO_ECLOSED;
        }
        else if(notif.wd != priv->watch_descr){
            ch_log_error("Unexpected error, notify watch descriptor is wrong \"%s\". Error=%s\n", this->name, strerror(errno));
            file_destroy(this);
            return EIO_ECLOSED;
        }
        else if(notif.mask == IN_MODIFY){
            //File has been modified, reset and go to start

            struct stat st;
            if(fstat(priv->fd,&st) < 0){
                ch_log_error("Cannot stat file \"%s\". Error=%s\n", this->name, strerror(errno));
                file_destroy(this);
                return -8;
            }


            //We only care about changes which affect the file size
            if(st.st_size != priv->filesize)
            {
                priv->filesize  = st.st_size;
                priv->blocksize = st.st_blksize;

                //If the file is truncated, there is nothing to read, come back later and try again?
                if(st.st_size == 0){
                    lseek(priv->fd, 0, SEEK_SET);
                    return EIO_ETRYAGAIN;
                }

                //In reset mode, a file change triggers a complete re-read
                if( priv->read_on_mod == EXACTIO_FILE_MOD_RESET){
                    lseek(priv->fd, 0, SEEK_SET);
                }

                priv->eof = false;
                this->fd = priv->fd;
            }

            return EIO_ETRYAGAIN;
        }
        else if(notif.mask == IN_DELETE_SELF)
        {

            close(priv->fd);
            close(priv->notify_fd);

            const int error = file_open(this, true);
            if(error){
                if( error == EIO_ETRYAGAIN){
                    return EIO_ETRYAGAIN;
                }
                else{
                    return EIO_EEOF;
                }
            }
        }
        else{
            return EIO_ETRYAGAIN;
        }
    }

    const ssize_t read_result = read(priv->fd, priv->read_buff, priv->read_buff_size);
    ifunlikely(read_result == 0){
        priv->eof = true;
        if(priv->notify_fd){
            this->fd = priv->notify_fd;
        }
        return EIO_EEOF;
    }
    ifunlikely(read_result < 0){
        if(errno == EAGAIN || errno == EWOULDBLOCK){
          return EIO_ETRYAGAIN;
        }

        ch_log_error("Unexpected error reading file \"%s\". Error=%s\n", this->name, strerror(errno));
        file_destroy(this);
        return EIO_ECLOSED;
    }

    //All good! Successful read!
    priv->reading = true;
    *buffer = priv->read_buff;
    *len    = read_result;
    eio_nowns(ts);

    return EIO_ENONE;
}

static eio_error_t file_read_release(eio_stream_t* this, int64_t* ts)
{
    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(!priv->reading){
        ch_log_error("Call read acquire before calling read release\n");
        return EIO_ERELEASE;
    }

    priv->reading = false;

    eio_nowns(ts);
    //Nothing to do here;
    return EIO_ENONE;
}


static inline eio_error_t file_read_sw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}

static inline eio_error_t file_read_hw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}


//Write operations
static eio_error_t file_write_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts)
{
    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    ifunlikely(priv->closed){
        return EIO_ECLOSED;
    }

    ifassert(priv->writing){
        ch_log_error("Call write release before calling write acquire\n");
        return EIO_ERELEASE;
    }

    ifassert(!buffer || !len)
    {
        ch_log_fatal("Buffer (%p) or length (%p) pointer is null\n", buffer, len);
    }

    /* Did the user supply a buffer? */
    const bool user_buff = (*buffer && *len);

    ifassert(!user_buff && *len > priv->write_buff_size){
        ch_log_fatal("Error length (%li) is too long for buffer (%li). Data corruption is likely\n",
                *len,
                priv->write_buff_size);
        return EIO_ETOOBIG;
    }

    iflikely(user_buff){
        //User has supplied a buffer and a length, so just give it back to them
        priv->usr_write_buff = *buffer;
        priv->usr_write_buff_size = *len;

    }
    else{
        *len = priv->write_buff_size;
        *buffer = priv->write_buff;
    }

    priv->writing = true;
    eio_nowns(ts);

    return EIO_ENONE;
}


static eio_error_t file_write_release(eio_stream_t* this, int64_t len, int64_t* ts)
{
    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    ifassert(!priv->writing){
        ch_log_fatal("Call write release before calling write acquire\n");
        return EIO_ERELEASE;
    }

    ifassert(!priv->usr_write_buff && len > priv->write_buff_size){
        ch_log_fatal("Error length (%li) is too long for buffer (%li). Data corruption is likely\n",
                len,
                priv->write_buff_size);
        return EIO_ETOOBIG;
    }

    ifassert(priv->usr_write_buff && len > priv->usr_write_buff_size){
        ch_log_fatal("Error length (%li) is too big for user buffer size (%li). Data corruption is likely\n",
                len,
                priv->usr_write_buff_size);
        return EIO_ETOOBIG;
    }


    if(len == 0){
        priv->writing = false;
        eio_nowns(ts);
        return EIO_ENONE;
    }

    /* Is the file too big? Make a new one! */
    ifunlikely(priv->write_max_file_size > 0 &&
               priv->total_bytes_written >= priv->write_max_file_size)
    {

        ch_log_debug1("Flushing file and starting again write_max_file_size=%li, total_bytes_written=%li\n", priv->write_max_file_size, priv->total_bytes_written );
        //Rename the file with a number extension eg "myfile.17"
        priv->write_file_num++;
        const int bufferlen = snprintf(NULL,0,"%s.%lu", this->name, priv->write_file_num);
        char* newfilename = calloc(1,bufferlen+1);
        sprintf(newfilename,"%s.%lu", this->name, priv->write_file_num);

        //Close the old file, open a new one
        close(priv->fd);
        priv->fd = open(newfilename, O_RDWR | O_CREAT | O_TRUNC, (mode_t)(0666));
        if(priv->fd < 0){
            ch_log_error("Could not open file \"%s\". Error=%s\n", this->name, strerror(errno));
            file_destroy(this);
            return -7;
        }

        //reset everything!
        priv->total_bytes_written = 0;
    }

    //If the user has supplied their own buffer, use it
    const char* buff = priv->usr_write_buff ? priv->usr_write_buff : priv->write_buff;
    priv->usr_write_buff = NULL;


    ssize_t bytes_written = 0;
    while(bytes_written < len){
        ch_log_debug2("Trying to write %liB at offset %li = %p\n", len -bytes_written, bytes_written, buff + bytes_written);
        const ssize_t result = write(priv->fd,buff + bytes_written,len-bytes_written);
        ifunlikely(result > 0 && result < len){
            ch_log_error("Only wrote %li / %li\n", result, len);
        }
        ifunlikely(result < 0){
            ch_log_error("Unexpected error writing to file \"%s\". Error=%s\n", this->name, strerror(errno));
            file_destroy(this);
            return EIO_ECLOSED;
        }
        bytes_written += result;
        priv->total_bytes_written += result;
    }

    priv->writing = false;
    eio_nowns(ts);
    return EIO_ENONE;
}


static inline eio_error_t file_write_sw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}

static inline eio_error_t file_write_hw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}


static eio_error_t file_time_to_tsps(eio_stream_t* this, void* time, timespecps_t* tsps)
{
    (void)this;
    (void)time;
    (void)tsps;


    return EIO_ENOTIMPL;
}


static eio_error_t file_get_id(eio_stream_t* this, int64_t* id_major, int64_t* id_minor)
{
    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    (void)priv;
    (void)id_major;
    (void)id_minor;

    return EIO_ENOTIMPL;
}



/*
 * Arguments
 * [0] filename
 * [1] read buffer size
 * [2] write buffer size
 * [3] reset on modify
 */
static eio_error_t file_construct(eio_stream_t* this, file_args_t* args)
{
    const char* filename            = args->filename;
    const uint64_t read_buff_size   = args->read_buff_size;
    const bool read_on_mod          = args->read_on_mod;

    const uint64_t write_buff_size     = ((args->write_buff_size + getpagesize() - 1) / getpagesize() ) * getpagesize();
    const bool write_directio          = args->write_directio;
    const int64_t write_max_file_size  = args->write_max_file_size;

    //Make a local copy of the filename in case the supplied name goes away
    const char* name = args->filename;
    const int64_t name_len = strnlen(name, 1024);
    this->name = calloc(name_len + 1, 1);
    memcpy(this->name, name, name_len);

    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    priv->read_buff_size        = read_buff_size;
    priv->write_buff_size       = write_buff_size;
    priv->write_directio        = write_directio;
    priv->write_max_file_size   = write_max_file_size;

    priv->read_buff = aligned_alloc(getpagesize(), priv->read_buff_size);
    if(!priv->read_buff){
        ch_log_error("Could allocate read buffer for file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -3;
    }

    /* When using delegated writes, we don't need a local buffer, so make
     * allocation of the write buffer optional */
    if( priv->write_buff_size){
        priv->write_buff = aligned_alloc(getpagesize(), priv->write_buff_size);
        ch_log_debug1("Allocated write buffer=%p size=%li\n", priv->write_buff, priv->write_buff_size);
        if(!priv->write_buff){
            ch_log_error("Could allocate write buffer for file \"%s\". Error=%s\n", filename, strerror(errno));
            file_destroy(this);
            return -5;
        }
    }


    priv->read_on_mod = read_on_mod;
    return file_open(this, false);

}


NEW_IOSTREAM_DEFINE(file, file_args_t, file_priv_t)
