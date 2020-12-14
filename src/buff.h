#include "data_structs/pcap-structures.h"

#define READ_BUFF_SIZE (128 * 1024 * 1024) /* 128MB */
#define WRITE_BUFF_SIZE (128 * 1024 * 1024) /* 128MB */

typedef struct {
    char* filename;
    char* data;
    pcap_pkthdr_t* pkt;
    int eof;
    int fd;
    int usec;
    uint64_t snaplen;
    uint64_t filesize;
    uint64_t max_filesize;
    uint64_t offset;
    uint64_t pkt_idx;
    int file_seg;
    uint64_t file_bytes_written;
} buff_t;

/* Allocate and initialize a buff_t. Returns NULL on failure */
int init_buff(char* filename, buff_t* buff, uint64_t snaplen, uint64_t max_filesize, int usec);
/* Read a file into a buff_t */
int read_file(buff_t* buff, char* filename);
/* Create a new pcap file header within a buff_t */
int new_file(buff_t* buff);
/* Increment to next packet  */
void next_packet(buff_t* buff);
/* Copy bytes to buff, flushing to disk if required */
int buff_copy_bytes(buff_t* buff, void* bytes, uint64_t len);
/* Write out the contents of a buff_t to disk */
int flush_to_disk(buff_t* wr_buff);
/* Get the amount of bytes left available in buffer */
uint64_t buff_remaining(buff_t* buff);
