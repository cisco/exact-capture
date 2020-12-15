#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "buff.h"
#include "data_structs/expcap.h"

int init_buff(char* filename, buff_t* buff, uint64_t snaplen, uint64_t max_filesize, int usec)
{
    memset(buff, 0, sizeof(buff_t));
    buff->data = calloc(1, WRITE_BUFF_SIZE);
    if(!buff->data){
        fprintf(stderr, "Could not allocate memory for buffer!\n");
        return 1;
    }
    buff->usec = usec;
    buff->snaplen = snaplen;
    buff->max_filesize = max_filesize;
    buff->filename = filename;
    return 0;
}

/* Open a new file for output, as a buff_t */
int new_file(buff_t* buff)
{
    char full_filename[2048] = {0};
    snprintf(full_filename, 2048, "%s_%i.pcap", buff->filename, buff->file_seg);

    printf("Opening output \"%s\"...\n",full_filename);
    buff->fd = open(full_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666 );
    if(buff->fd < 0)
    {
        fprintf(stderr, "Could not open output file %s: \"%s\"",
                full_filename, strerror(errno));
        return 1;
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
    printf("Writing PCAP header to fd=%i\n", buff->fd);
    if(write(buff->fd,&hdr,sizeof(hdr)) != sizeof(hdr)){
        fprintf(stderr, "Could not write PCAP header");
        return 1;
    }
    close(buff->fd);
    return 0;
}

int read_file(buff_t* buff, char* filename)
{
    buff->filename = filename;
    buff->fd = open(buff->filename,O_RDONLY);
    if(!buff->fd){
        fprintf(stderr,"Could not open input file %s: \"%s\"",
                buff->filename, strerror(errno));
        return 1;
    }

    struct stat st = {0};
    if(stat(buff->filename, &st)){
        fprintf(stderr, "Could not stat file %s: \"%s\"\n",
                buff->filename, strerror(errno));
        return 1;
    }
    buff->filesize = st.st_size;
    buff->data = mmap(NULL, buff->filesize,
                            PROT_READ,
                            MAP_PRIVATE , //| MAP_POPULATE ,
                            buff->fd, 0);
    if(buff->data == MAP_FAILED){
        fprintf(stderr, "Could not map input file %s: \"%s\"\n",
                buff->filename, strerror(errno));
        return 1;
    }
    buff->pkt = (pcap_pkthdr_t*)(buff->data + sizeof(pcap_file_header_t));
    return 0;
}

/* Flush a buff_t to disk */
int flush_to_disk(buff_t* buff)
{
    /* open fd */
    char full_filename[1024] = {0};
    snprintf(full_filename, 1024, "%s_%i.pcap", buff->filename, buff->file_seg);
    buff->fd = open(full_filename, O_APPEND | O_WRONLY, 0666 );
    if (buff->fd == -1){
        fprintf(stderr, "Failed to append to output: %s\n", strerror(errno));
        return 1;
    }

    const uint64_t written = write(buff->fd,buff->data,buff->offset);
    if(written != buff->offset){
        fprintf(stderr, "Couldn't write all bytes: %s \n", strerror(errno));
        return 1;
    }

    buff->file_bytes_written += written;
    buff->offset = 0;
    close(buff->fd);
    return 0;
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
        fprintf(stderr, "End of file \"%s\"\n", buff->filename);
    }
}

int buff_copy_bytes(buff_t* buff, void* bytes, uint64_t len)
{
    if(buff_remaining(buff) < len){
        if(flush_to_disk(buff) != 0){
            fprintf(stderr, "Failed to copy bytes to buff!\n");
            return 1;
        }
        new_file(buff);
    }

    memcpy(buff->data + buff->offset, bytes, len);
    buff->offset += len;
    return 0;
}

uint64_t buff_remaining(buff_t* buff)
{
    if(buff->max_filesize > 0){
        if(buff->offset > buff->max_filesize){
            return 0;
        }
        return buff->max_filesize - buff->offset;
    }
    /* This should never happen... better safe than sorry. */
    if(buff->offset > WRITE_BUFF_SIZE){
        return 0;
    }
    return WRITE_BUFF_SIZE - buff->offset;
}
