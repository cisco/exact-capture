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

    char* usr_write_buff;
    int64_t usr_write_buff_size;


    int64_t filesize;
    int64_t blocksize;

    exactio_file_mod_t on_mod; //0 ignore, 1 reset, 2, tail
    int notify_fd;
    int watch_descr;

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
    }

    if(priv->filename){
        free(priv->filename);
    }

    if(priv->fd){
        close(priv->fd);
    }

    priv->closed = true;

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
                ch_log_error("Unexpected error reading notify \"%s\". Error=%s\n", priv->filename, strerror(errno));
                file_destroy(this);
                return EIO_ECLOSED;
            }
        }
        else if(read_result < (ssize_t)sizeof(notif)){
            ch_log_error("Unexpected error, notify structure too small \"%s\". Error=%s\n", priv->filename, strerror(errno));
            file_destroy(this);
            return EIO_ECLOSED;
        }
        else if(notif.wd != priv->watch_descr){
            ch_log_error("Unexpected error, notify watch descriptor is wrong \"%s\". Error=%s\n", priv->filename, strerror(errno));
            file_destroy(this);
            return EIO_ECLOSED;
        }
        else if(notif.mask == IN_MODIFY){
            //File has been modified, reset and go to start

            struct stat st;
            if(fstat(priv->fd,&st) < 0){
                ch_log_error("Cannot stat file \"%s\". Error=%s\n", priv->filename, strerror(errno));
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
                if( priv->on_mod == EXACTIO_FILE_MOD_RESET){
                    lseek(priv->fd, 0, SEEK_SET);
                }

                priv->eof = false;
                this->fd = priv->fd;
            }

            return EIO_ETRYAGAIN;
        }


        return EIO_ETRYAGAIN;
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

        ch_log_error("Unexpected error reading file \"%s\". Error=%s\n", priv->filename, strerror(errno));
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
    (void)ts;
    //eio_nowns(ts);

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
            ch_log_error("Unexpected error writing to file \"%s\". Error=%s\n", priv->filename, strerror(errno));
            file_destroy(this);
            return EIO_ECLOSED;
        }
        bytes_written += result;
    }

    priv->writing = false;
    eio_nowns(ts);
    return EIO_ENONE;
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
    const uint64_t write_buff_size  = ((args->write_buff_size + getpagesize() - 1) / getpagesize() ) * getpagesize();
    const uint64_t on_mod           = args->on_mod;

    file_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    //Make a local copy of the filename in case the supplied name goes away
    const uint16_t name_len = strlen(filename); //Safety bug here? What's a reasonable max on filename size?
    priv->filename = calloc(1, name_len);
    if(!priv->filename){
        ch_log_error("Could allocate filename buffer for file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -2;
    }
    memcpy(priv->filename, filename, name_len);


    priv->read_buff_size  = read_buff_size;
    priv->write_buff_size = write_buff_size;

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

    priv->fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, (mode_t)(0666));
    if(priv->fd < 0){
        ch_log_error("Could not open file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -7;
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

    priv->eof    = 0;
    priv->closed = false;
    priv->on_mod = on_mod;
    this->fd = priv->fd;

    if(priv->on_mod == 0){
        return 0; //Early exit, success!
    }

    //We'll be listening to notify operations, so set it up
    priv->notify_fd = inotify_init1(IN_NONBLOCK);
    if(priv->notify_fd < 0){
        ch_log_error("Could not start inotify for file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -9;
    }

    priv->watch_descr = inotify_add_watch(priv->notify_fd,filename, IN_MODIFY);
    if(priv->watch_descr < 0){
        ch_log_error("Could not begin to watch file \"%s\". Error=%s\n", filename, strerror(errno));
        file_destroy(this);
        return -10;
    }

    return 0;

}


NEW_IOSTREAM_DEFINE(file, file_args_t, file_priv_t)
