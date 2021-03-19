#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <chaste/types/types.h>
#include <chaste/utils/util.h>

#include "buff.h"
#include "data_structs/expcap.h"

buff_error_t buff_init(char* filename, int64_t max_filesize, bool conserve_fds, bool allow_duplicates, buff_t** buffo)
{
    buff_t* new_buff;
    new_buff = (buff_t*)calloc(1, sizeof(buff_t));
    if(!new_buff){
        return BUFF_EALLOC;
    }

    new_buff->data = calloc(1, BUFF_SIZE);
    if(!new_buff->data){
        return BUFF_EALLOC;
    }

    new_buff->filename = filename;
    new_buff->max_filesize = max_filesize;
    new_buff->conserve_fds = conserve_fds;
    new_buff->allow_duplicates = allow_duplicates;

    *buffo = new_buff;
    return BUFF_ENONE;
}

/* Open a new file for output, as a buff_t */
buff_error_t buff_new_file(buff_t* buff)
{
    char full_filename[MAX_FILENAME] = {0};
    buff_get_full_filename(buff, full_filename, MAX_FILENAME);

    if(buff->fd){
        close(buff->fd);
    }

    /* Check for files that already have this filename.
       If they exist, append _file_dup to the newly created file */
    if(buff->allow_duplicates){
        while(access(full_filename, F_OK) == 0 && buff->file_dup > -1){
            buff->file_dup++;
            buff_get_full_filename(buff, full_filename, MAX_FILENAME);
        }
    }

    ch_log_debug1("Opening output \"%s\"...\n",full_filename);
    buff->fd = open(full_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666 );

    if(buff->fd < 0){
        ch_log_warn("Could not open output file %s: \"%s\"",
                    full_filename, strerror(errno));
        return BUFF_EOPEN;
    }

    if(buff->conserve_fds){
        close(buff->fd);
        buff->fd = 0;
    }

    if(buff->file_header){
        BUFF_TRY(buff_write_file_header(buff));
    }

    buff->file_bytes_written = 0;
    return BUFF_ENONE;
}

buff_error_t buff_write_file_header(buff_t* buff)
{
    if(buff->read_only){
        return BUFF_EREADONLY;
    }

    if(buff->conserve_fds){
        char full_filename[MAX_FILENAME] = {0};
        buff_get_full_filename(buff, full_filename, MAX_FILENAME);
        buff->fd = open(full_filename, O_APPEND | O_WRONLY, 0666 );
        if(buff->fd < 0)
        {
            ch_log_warn("Could not open output file %s: \"%s\"\n",
                        full_filename, strerror(errno));
            return BUFF_EOPEN;
        }
    }

    ch_log_debug1("Writing file header to fd=%i\n", buff->fd);

    if(write(buff->fd,buff->file_header,buff->header_size) != buff->header_size){
        ch_log_warn("Could not write file header: %s\n", strerror(errno));
        return BUFF_EWRITE;
    }

    if(buff->conserve_fds){
        close(buff->fd);
    }
    return BUFF_ENONE;
}

buff_error_t buff_init_from_file(buff_t** buff, char* filename, size_t header_size)
{
    buff_t* new_buff = (buff_t*)calloc(1, sizeof(buff_t));
    if(!new_buff){
        ch_log_fatal("Failed to allocate memory for buff_t\n");
    }

    new_buff->read_only = true;
    new_buff->filename = filename;
    new_buff->header_size = header_size;
    new_buff->fd = open(new_buff->filename,O_RDONLY);
    if(!new_buff->fd){
        ch_log_warn("Could not open input file %s: \"%s\"", new_buff->filename, strerror(errno));
        return BUFF_EOPEN;
    }

    struct stat st = {0};
    if(stat(new_buff->filename, &st)){
        ch_log_warn("Could not stat file %s: \"%s\"\n", new_buff->filename, strerror(errno));
        return BUFF_ESTAT;
    }
    new_buff->filesize = st.st_size;
    if(new_buff->filesize < header_size){
        ch_log_warn("Cannot open file for reading, file header size is greater than total file size.\n");
        return BUFF_EBADHEADER;
    }

    new_buff->data = mmap(NULL, new_buff->filesize,
                          PROT_READ,
                          MAP_PRIVATE , //| MAP_POPULATE ,
                          new_buff->fd, 0);
    if(new_buff->data == MAP_FAILED){
        ch_log_warn("Could not map input file %s: \"%s\"\n",
                    new_buff->filename, strerror(errno));
        return BUFF_EMMAP;
    }
    new_buff->file_header = new_buff->data;

    if(madvise(new_buff->data, new_buff->filesize, MADV_SEQUENTIAL) != 0){
        ch_log_warn("Failed to advise on memory usage: %s\n", strerror(errno));
    }

    *buff = new_buff;
    return BUFF_ENONE;
}

/* Flush a buff_t to disk */
buff_error_t buff_flush_to_disk(buff_t* buff)
{
    /* open fd */
    char full_filename[MAX_FILENAME] = {0};
    buff_get_full_filename(buff, full_filename, MAX_FILENAME);

    if(buff->conserve_fds){
        buff->fd = open(full_filename, O_APPEND | O_WRONLY, 0666 );
    }
    if (buff->fd == -1){
        ch_log_warn("Failed to append to output:%s %s\n", full_filename, strerror(errno));
        return BUFF_EOPEN;
    }

    const uint64_t written = write(buff->fd, buff->data, buff->offset);
    if(written != buff->offset){
        ch_log_warn("Couldn't write all bytes: %s \n", strerror(errno));
        return BUFF_EWRITE;
    }

    buff->file_bytes_written += written;
    buff->offset = 0;

    if(buff->conserve_fds){
        close(buff->fd);
    }
    return BUFF_ENONE;
}

buff_error_t buff_copy_bytes(buff_t* buff, void* bytes, uint64_t len)
{
    int64_t remaining;

    BUFF_TRY(buff_remaining(buff, &remaining));
    if(remaining <= len){
        BUFF_TRY(buff_flush_to_disk(buff));
    }

    memcpy(buff->data + buff->offset, bytes, len);
    buff->offset += len;
    return BUFF_ENONE;
}

buff_error_t buff_remaining(buff_t* buff, int64_t* remaining)
{
    /* This should never happen... better safe than sorry. */
    ifunlikely(buff->offset > BUFF_SIZE){
        return BUFF_EOVERFLOW;
    }

    *remaining = BUFF_SIZE - buff->offset;
    return BUFF_ENONE;
}

int64_t buff_seg_remaining(buff_t* buff)
{
    return buff->max_filesize - (buff->offset + buff->file_bytes_written);
}

void buff_get_full_filename(buff_t* buff, char* full_filename, size_t len)
{
    /* Don't include the segment number in the first file written */
    if(buff->file_seg == 0){
        if(buff->file_dup == 0){
            snprintf(full_filename, len, "%s.pcap", buff->filename);
        } else {
            snprintf(full_filename, len, "%s__%i.pcap", buff->filename, buff->file_dup);
        }
    } else {
        if(buff->file_dup == 0){
            snprintf(full_filename, len, "%s_%i.pcap", buff->filename, buff->file_seg);
        } else {
            snprintf(full_filename, len, "%s_%i__%i.pcap", buff->filename, buff->file_seg, buff->file_dup);
        }
    }
}

buff_error_t buff_close(buff_t* buff){
    /* conserve_fds will mean that the fd is already closed */
    if(buff->conserve_fds){
        return BUFF_ENONE;
    }

    if(buff->read_only){
        if(munmap(buff->data, buff->filesize) != 0){
            ch_log_warn("Failed to unmap memory allocated for buff_t (%s) : %s\n", buff->filename, strerror(errno));
            return BUFF_ECLOSE;
        }
    } else{
        free(buff->data);
    }

    if(close(buff->fd) != 0){
        ch_log_warn("Failed to close buff_t (%s) : %s\n", buff->filename, strerror(errno));
        return BUFF_ECLOSE;
    }

    return BUFF_ENONE;
}
const char* buff_errlist[] = {
    "Operation succeeded",                             // BUFF_ENONE
    "Failed to allocate memory for buff_t",            // BUFF_EALLOC
    "Failed to open a file for this buff_t",           // BUFF_EOPEN
    "Failed to write to buff_t",                       // BUFF_EWRITE
    "Failed to mmap buff_t data from a file",          // BUFF_EMMAP
    "Failed to stat file associated with this buff_t", // BUFF_ESTAT
    "Failed to copy bytes to this buff_t",             // BUFF_ECOPY
    "Buffer offset is greater than the allowed size",  // BUFF_EOVERFLOW
    "Attempted to write to read-only buff_t",          // BUFF_EREADONLY
    "Failed to read file header when creating buff_t", // BUFF_EBADHEADER
    "Failed to close buff_t"                           // BUFF_ECLOSE
};

const char* buff_strerror(buff_error_t err){
    return buff_errlist[err];
}
