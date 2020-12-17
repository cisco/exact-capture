#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include <chaste/types/types.h>
#include <chaste/log/log.h>

#include "buff.h"
#include "data_structs/expcap.h"

buff_error_t init_buff(char* filename, buff_t* buff, uint64_t snaplen, uint64_t max_filesize, bool usec)
{
    memset(buff, 0, sizeof(buff_t));
    buff->data = calloc(1, BUFF_SIZE);
    if(!buff->data){
        ch_log_warn("Could not allocate memory for buffer!\n");
        return BUFF_EALLOC;
    }
    buff->usec = usec;
    buff->snaplen = snaplen;
    buff->max_filesize = max_filesize;
    buff->filename = filename;
    return BUFF_ENONE;
}

/* Open a new file for output, as a buff_t */
buff_error_t new_file(buff_t* buff)
{
    char full_filename[2048] = {0};
    snprintf(full_filename, 2048, "%s_%i.pcap", buff->filename, buff->file_seg);

    ch_log_info("Opening output \"%s\"...\n",full_filename);
    buff->fd = open(full_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666 );
    if(buff->fd < 0)
    {
        ch_log_warn("Could not open output file %s: \"%s\"",
                    full_filename, strerror(errno));
        return BUFF_EOPEN;
    }

    /* TODO: Currently assumes PCAP output only, would be nice at add ERF */
    /* Generate the output file header */
    pcap_file_header_t hdr;
    hdr.magic = buff->usec ? TCPDUMP_MAGIC: NSEC_TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr.snaplen = buff->snaplen + (int)sizeof(expcap_pktftr_t);
    hdr.linktype = DLT_EN10MB;
    ch_log_info("Writing PCAP header to fd=%i\n", buff->fd);
    if(write(buff->fd,&hdr,sizeof(hdr)) != sizeof(hdr)){
        ch_log_warn("Could not write PCAP header");
        return BUFF_EWRITE;
    }
    close(buff->fd);
    return BUFF_ENONE;
}

buff_error_t read_file(buff_t* buff, char* filename)
{
    buff->filename = filename;
    buff->fd = open(buff->filename,O_RDONLY);
    if(!buff->fd){
        ch_log_warn("Could not open input file %s: \"%s\"",
                    buff->filename, strerror(errno));
        return BUFF_EOPEN;
    }

    struct stat st = {0};
    if(stat(buff->filename, &st)){
        ch_log_warn("Could not stat file %s: \"%s\"\n",
                    buff->filename, strerror(errno));
        return BUFF_ESTAT;
    }
    buff->filesize = st.st_size;
    buff->data = mmap(NULL, buff->filesize,
                            PROT_READ,
                            MAP_PRIVATE , //| MAP_POPULATE ,
                            buff->fd, 0);
    if(buff->data == MAP_FAILED){
        ch_log_warn("Could not map input file %s: \"%s\"\n",
                    buff->filename, strerror(errno));
        return BUFF_EMMAP;
    }

    buff->pkt = (pcap_pkthdr_t*)(buff->data + sizeof(pcap_file_header_t));
    return BUFF_ENONE;
}

/* Flush a buff_t to disk */
buff_error_t flush_to_disk(buff_t* buff)
{
    /* open fd */
    char full_filename[1024] = {0};
    snprintf(full_filename, 1024, "%s_%i.pcap", buff->filename, buff->file_seg);
    buff->fd = open(full_filename, O_APPEND | O_WRONLY, 0666 );
    if (buff->fd == -1){
        ch_log_warn("Failed to append to output: %s\n", strerror(errno));
        return BUFF_EOPEN;
    }

    const uint64_t written = write(buff->fd,buff->data,buff->offset);
    if(written != buff->offset){
        ch_log_warn("Couldn't write all bytes: %s \n", strerror(errno));
        return BUFF_EWRITE;
    }

    buff->file_bytes_written += written;
    buff->offset = 0;
    close(buff->fd);
    return BUFF_ENONE;
}


void next_packet(buff_t* buff)
{
    pcap_pkthdr_t* curr_pkt    = buff->pkt;
    const int64_t curr_cap_len = curr_pkt->caplen;
    pcap_pkthdr_t* next_pkt    = (pcap_pkthdr_t*)((char*)(curr_pkt+1) + curr_cap_len);

    buff->pkt = next_pkt;
    buff->pkt_idx++;

    /*Check if we've overflowed */
    const uint64_t offset = (char*)next_pkt - buff->data;
    buff->eof = offset >= buff->filesize;
    if(buff->eof){
        ch_log_warn("End of file \"%s\"\n", buff->filename);
    }
}

buff_error_t buff_copy_bytes(buff_t* buff, void* bytes, uint64_t len)
{
    uint64_t remaining;
    buff_error_t err = BUFF_ENONE;
    err = buff_remaining(buff, &remaining);
    if(err == BUFF_ENONE && remaining <= len){
        err = flush_to_disk(buff);
        if(err != BUFF_ENONE){
            ch_log_warn("Failed to copy bytes to buff: %s\n", buff_strerror(err));
            return BUFF_ECOPY;
        }
        err = new_file(buff);
        if(err != BUFF_ENONE){
            ch_log_warn("Failed to create a new file for buff: %s\n", buff_strerror(err));
            return err;
        }
    }

    memcpy(buff->data + buff->offset, bytes, len);
    buff->offset += len;
    return err;
}

buff_error_t buff_remaining(buff_t* buff, uint64_t* remaining)
{
    if(buff->max_filesize > 0){
        if(buff->offset > buff->max_filesize){
            return BUFF_EOVERFLOW;
        }
        return buff->max_filesize - buff->offset;
    }

    /* This should never happen... better safe than sorry. */
    if(buff->offset > BUFF_SIZE){
        return BUFF_EOVERFLOW;
    }

    *remaining = BUFF_SIZE - buff->offset;
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
    "Buffer offset is greater than the allowed size"   // BUFF_EOVERFLOW
};

const char* buff_strerror(buff_error_t err){
    return buff_errlist[err];
}
