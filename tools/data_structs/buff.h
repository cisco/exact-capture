#include <chaste/types/types.h>
#include "data_structs/pcap-structures.h"

#define BUFF_SIZE (128 * 1024 * 1024) /* 128MB */
#define MAX_FILENAME 2048

typedef struct {
    char* filename;
    char* data;
    pcap_pkthdr_t* pkt;
    int eof;
    int fd;
    bool usec;
    bool conserve_fds;
    uint64_t snaplen;
    uint64_t filesize;
    uint64_t max_filesize;
    uint64_t offset;
    uint64_t pkt_idx;
    int file_seg;
    uint64_t file_bytes_written;
} buff_t;

typedef enum {
    BUFF_ENONE =  0,
    BUFF_EALLOC,     // Failed to allocate memory for a buff_t
    BUFF_EOPEN,      // Failed to open a file for read/write
    BUFF_EWRITE,     // Failed to write out buff_t data
    BUFF_EMMAP,      // Failed to map a buff_t from a file
    BUFF_ESTAT,      // Failed to stat a file
    BUFF_ECOPY,      // Failed to copy bytes to a buff_t
    BUFF_EOVERFLOW,  // Buffer offset is greater than the allocated buffer size.
} buff_error_t;

/* Allocate and initialize a buff_t. Returns NULL on failure */
buff_error_t init_buff(char* filename, buff_t* buff, uint64_t snaplen, uint64_t max_filesize, bool usec);

/* Read a file into a buff_t */
buff_error_t read_file(buff_t* buff, char* filename);

/* Create a new pcap file header within a buff_t */
buff_error_t new_file(buff_t* buff);

/* Increment to next packet  */
void next_packet(buff_t* buff);

/* Copy bytes to buff, flushing to disk if required */
buff_error_t buff_copy_bytes(buff_t* buff, void* bytes, uint64_t len);

/* Write out the contents of a buff_t to disk */
buff_error_t flush_to_disk(buff_t* wr_buff);

/* Get the amount of bytes left available in buffer */
buff_error_t buff_remaining(buff_t* buff, uint64_t* remaining);

/* Translate an error value to a string */
const char* buff_strerror(buff_error_t err);
