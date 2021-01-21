#include <stdio.h>

#include <chaste/log/log.h>
#include <chaste/types/types.h>
#include "data_structs/pcap-structures.h"

#define BUFF_SIZE (128 * 1024 * 1024) /* 128MB */
#define MAX_FILENAME 2048

#define BUFF_TRY(x)                                                          \
    do {                                                                     \
        buff_error_t err = (x);                                              \
        if (err != BUFF_ENONE) {                                             \
            ch_log_warn("%s failed at %s:%d\n", #x, __FILE__, __LINE__);     \
            ch_log_fatal("Reason: %s\n", buff_strerror(err));                \
        }                                                                    \
    } while(0)                                                               \

typedef struct {
    char* filename;
    char* file_header;
    size_t header_size;
    char* data;
    int eof;
    int fd;
    bool conserve_fds;
    uint64_t filesize;
    int64_t max_filesize;
    uint64_t offset;
    uint64_t pkt_idx;
    int file_seg;
    int file_dup;
    uint64_t file_bytes_written;
    bool read_only;
    bool allow_duplicates;
} buff_t;

typedef enum {
    BUFF_ENONE = 0,
    BUFF_EALLOC,       // Failed to allocate memory for a buff_t
    BUFF_EOPEN,        // Failed to open a file for read/write
    BUFF_EWRITE,       // Failed to write out buff_t data
    BUFF_EMMAP,        // Failed to map a buff_t from a file
    BUFF_ESTAT,        // Failed to stat a file
    BUFF_ECOPY,        // Failed to copy bytes to a buff_t
    BUFF_EOVERFLOW,    // Buffer offset is greater than the allocated buffer size.
    BUFF_EREADONLY,    // Attempting to write to a read-only buffer.
} buff_error_t;

/* Allocate and initialize a buff_t. */
buff_error_t buff_init(char* filename, int64_t max_filesize, bool conserve_fds, bool allow_duplicates, buff_t** buffo);

/* Read a file into a buff_t */
buff_error_t buff_init_from_file(buff_t** buff, char* filename);

/* Create a new pcap file header within a buff_t */
buff_error_t buff_new_file(buff_t* buff);

/* Copy bytes to buff, flushing to disk if required */
buff_error_t buff_copy_bytes(buff_t* buff, void* bytes, uint64_t len);

/* Write out the contents of a buff_t to disk */
buff_error_t buff_flush_to_disk(buff_t* wr_buff);

/* Get the amount of bytes left available in the buffer */
buff_error_t buff_remaining(buff_t* buff, int64_t* remaining);

/* Get the amount of bytes left in the current segment */
int64_t buff_seg_remaining(buff_t* buff);

/* Get full buff filename */
void buff_get_full_filename(buff_t* buff, char* full_filename, size_t len);

/* Write file header */
buff_error_t buff_write_file_header(buff_t* buff);

/* Translate an error value to a string */
const char* buff_strerror(buff_error_t err);
