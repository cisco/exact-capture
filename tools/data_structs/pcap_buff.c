#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include <chaste/log/log.h>
#include <errno.h>
#include "pcap_buff.h"

buff_error_t pcap_buff_init(char* filename, int64_t snaplen, int64_t max_filesize, bool usec,
                           bool conserve_fds, bool allow_duplicates, pcap_buff_t* pcap_buffo)
{
    buff_t* buff = NULL;
    BUFF_TRY(buff_init(filename, max_filesize, conserve_fds, allow_duplicates, &buff));

    pcap_buffo->_buff = buff;
    pcap_buffo->snaplen = snaplen;
    pcap_buffo->usec = usec;

    /* Generate the output file header */
    pcap_file_header_t* hdr = (pcap_file_header_t*)malloc(sizeof(pcap_file_header_t));
    if(!hdr){
        ch_log_fatal("Failed to allocate memory for file header!\n");
    }

    buff->file_header = (char*)hdr;
    buff->header_size = sizeof(pcap_file_header_t);

    hdr->magic = usec ? TCPDUMP_MAGIC: NSEC_TCPDUMP_MAGIC;
    hdr->version_major = PCAP_VERSION_MAJOR;
    hdr->version_minor = PCAP_VERSION_MINOR;
    hdr->thiszone = 0;
    hdr->sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr->snaplen = snaplen + (int)sizeof(expcap_pktftr_t);
    hdr->linktype = DLT_EN10MB;

    BUFF_TRY(buff_new_file(buff));

    return BUFF_ENONE;
}

buff_error_t pcap_buff_from_file(pcap_buff_t* pcap_buff, char* filename, bool is_expcap)
{
    pcap_buff->expcap = is_expcap;
    BUFF_TRY(buff_init_from_file(&pcap_buff->_buff, filename, sizeof(pcap_file_header_t)));
    return BUFF_ENONE;
}

pkt_info_t pcap_buff_get_info(pcap_buff_t* pcap_buff)
{
    if(pcap_buff->hdr == NULL){
        pcap_buff->hdr = (pcap_pkthdr_t*)(pcap_buff->_buff->data + sizeof(pcap_file_header_t));
        pcap_buff->idx = 0;
    }

    pcap_buff->pkt = (char*)(pcap_buff->hdr + 1);

    /* Check if we've overflowed */
    buff_t* buff = pcap_buff->_buff;
    int64_t offset = (char*)pcap_buff->hdr - buff->data;
    buff->eof = offset >= buff->filesize;
    if(buff->eof){
        return PKT_EOF;
    }

    if(pcap_buff->hdr->len == 0){
        return PKT_PADDING;
    }

    if(pcap_buff->hdr->caplen < 64){
        return PKT_RUNT;
    }

    pcap_file_header_t* hdr = (pcap_file_header_t*)buff->file_header;
    if(pcap_buff->hdr->len > hdr->snaplen){
        return PKT_OVER_SNAPLEN;
    }

    if(pcap_buff->hdr->len > pcap_buff->hdr->caplen){
        return PKT_SNAPPED;
    }

    if(pcap_buff->expcap){
        pcap_buff->ftr = (expcap_pktftr_t*)(pcap_buff->pkt + pcap_buff->hdr->caplen - sizeof(expcap_pktftr_t));

        if(pcap_buff->ftr->foot.extra.dropped > 0){
            ch_log_warn("%li packets were droped before this one\n",
                pcap_buff->ftr->foot.extra.dropped);
        }

        if( (pcap_buff->ftr->flags & EXPCAP_FLAG_ABRT) ||
            (pcap_buff->ftr->flags & EXPCAP_FLAG_CRPT) ||
            (pcap_buff->ftr->flags & EXPCAP_FLAG_SWOVFL)){

            return PKT_ERROR;
        }
    } else {
        pcap_buff->ftr = NULL;
    }

    return PKT_OK;
}

pkt_info_t pcap_buff_next_packet(pcap_buff_t* pcap_buff)
{
    pcap_pkthdr_t* curr_hdr = pcap_buff->hdr;

    if(curr_hdr == NULL){
        pcap_buff->hdr = (pcap_pkthdr_t*)(pcap_buff->_buff->data + sizeof(pcap_file_header_t));
        pcap_buff->idx = 0;
    } else {
        const int64_t curr_cap_len = curr_hdr->caplen;
        pcap_pkthdr_t* next_hdr = (pcap_pkthdr_t*)((char*)(curr_hdr+1) + curr_cap_len);
        pcap_buff->hdr = next_hdr;
        pcap_buff->idx++;
    }

    return pcap_buff_get_info(pcap_buff);
}

bool pcap_buff_eof(pcap_buff_t* pcap_buff)
{
    buff_t* buff = pcap_buff->_buff;
    return buff->eof;
}

char* pcap_buff_get_filename(pcap_buff_t* pcap_buff)
{
    return pcap_buff->_buff->filename;
}

buff_error_t pcap_buff_flush_to_disk(pcap_buff_t* pcap_buff){
    return buff_flush_to_disk(pcap_buff->_buff);
}

buff_error_t pcap_buff_write(pcap_buff_t* pcap_buff, pcap_pkthdr_t* hdr, char* data, size_t data_len, expcap_pktftr_t* ftr)
{
    buff_t* buff = pcap_buff->_buff;
    const int64_t pcap_record_bytes = sizeof(pcap_pkthdr_t) + data_len + (ftr ? sizeof(expcap_pktftr_t) : 0);

    // there isn't enough space in the buff_t. must flush to disk.
    int64_t bytes_remaining;
    BUFF_TRY(buff_remaining(buff, &bytes_remaining));
    const bool buff_full = bytes_remaining < pcap_record_bytes;

    if(buff_full){
        BUFF_TRY(buff_flush_to_disk(buff));
    }

    if(buff->max_filesize > 0){
        /* tcpdump allows one packet to be written past the filesize limit. */
        if(buff_seg_remaining(buff) < 0){
            BUFF_TRY(buff_flush_to_disk(buff));
            buff->file_seg++;
            buff_new_file(buff);
        }
    }

    /* Flush the buffer if we need to */
    if(ftr){
        hdr->caplen += sizeof(expcap_pktftr_t);
    }

    ch_log_debug1("header bytes=%li\n", sizeof(pcap_pkthdr_t));
    ch_log_debug1("footer bytes=%li\n", sizeof(expcap_pktftr_t));
    ch_log_debug1("max pcap_record_bytes=%li\n", pcap_record_bytes);

    BUFF_TRY(buff_copy_bytes(buff, hdr, sizeof(pcap_pkthdr_t)));
    BUFF_TRY(buff_copy_bytes(buff, data, data_len));

    if(ftr){
        BUFF_TRY(buff_copy_bytes(buff, ftr, sizeof(expcap_pktftr_t)));
    }

    return BUFF_ENONE;
}

buff_error_t pcap_buff_close(pcap_buff_t* pcap_buff){
    return buff_close(pcap_buff->_buff);
}

static const char* pkt_infolist[] = {
    "Packet OK.",                                                     // PKT_OK
    "Packet is expcap padding.",                                      // PKT_PADDING
    "Packet is a runt (len < 64B).",                                  // PKT_RUNT
    "Packet contains an error.",                                      // PKT_ERROR
    "No more packets left in this buffer. ",                          // PKT_EOF
    "Packet length exceeds the pcap file's snaplen.",                 // PKT_OVER_SNAPLEN
    "Packet data length is less than the length on disk.",            // PKT_BAD_LEN
    "Packet has been snapped to less than it's length on the wire."   // PKT_SNAPPED
};

const char* pcap_buff_strinfo(pkt_info_t info){
    return pkt_infolist[info];
}
