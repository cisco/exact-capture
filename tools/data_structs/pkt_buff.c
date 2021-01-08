#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <chaste/log/log.h>
#include <errno.h>
#include "pkt_buff.h"

buff_error_t pkt_buff_init(char* filename, pkt_buff_t* pkt_buff, int64_t snaplen, int64_t max_filesize, bool usec)
{
    buff_t* buff = NULL;
    buff_error_t err = BUFF_ENONE;
    err = buff_init(filename, &buff, max_filesize);
    if(err != BUFF_ENONE){
        return err;
    }

    pkt_buff->_buff = buff;
    pkt_buff->snaplen = snaplen;
    pkt_buff->usec = usec;

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

    err = buff_new_file(buff);
    if(err != BUFF_ENONE){
        return err;
    }

    return err;
}

buff_error_t pkt_buff_from_file(pkt_buff_t* pkt_buff, char* filename)
{
    return buff_init_from_file(&pkt_buff->_buff, filename);
}

pkt_info_t pkt_buff_next_packet(pkt_buff_t* pkt_buff)
{
    pcap_pkthdr_t* curr_hdr = pkt_buff->hdr;

    if(curr_hdr == NULL){
        pkt_buff->hdr = (pcap_pkthdr_t*)(pkt_buff->_buff->data + sizeof(pcap_file_header_t));
        pkt_buff->idx = 0;
    } else {
        const int64_t curr_cap_len = curr_hdr->caplen;
        pcap_pkthdr_t* next_hdr = (pcap_pkthdr_t*)((char*)(curr_hdr+1) + curr_cap_len);
        pkt_buff->hdr = next_hdr;
        pkt_buff->idx++;
    }

    pkt_buff->pkt = (char*)(pkt_buff->hdr + 1);
    pkt_buff->ftr = (expcap_pktftr_t*)(pkt_buff->pkt + pkt_buff->hdr->caplen - sizeof(expcap_pktftr_t));

    /* Check if we've overflowed */
    buff_t* buff = pkt_buff->_buff;
    uint64_t offset = (char*)pkt_buff->hdr - buff->data;
    buff->eof = offset >= buff->filesize;
    if(buff->eof){
        return PKT_EOF;
    }

    if(pkt_buff->hdr->len == 0){
        return PKT_PADDING;
    }

    if(pkt_buff->hdr->caplen < 64){
        return PKT_RUNT;
    }

    if(pkt_buff->ftr->foot.extra.dropped > 0){
        ch_log_warn("%li packets were droped before this one\n",
                    pkt_buff->ftr->foot.extra.dropped);
    }

    if( (pkt_buff->ftr->flags & EXPCAP_FLAG_ABRT) ||
        (pkt_buff->ftr->flags & EXPCAP_FLAG_CRPT) ||
        (pkt_buff->ftr->flags & EXPCAP_FLAG_SWOVFL)){

        return PKT_ERROR;
    }

    return PKT_OK;
}

bool pkt_buff_eof(pkt_buff_t* pkt_buff)
{
    buff_t* buff = pkt_buff->_buff;
    return buff->eof;
}

char* pkt_buff_get_filename(pkt_buff_t* pkt_buff)
{
    return pkt_buff->_buff->filename;
}

buff_error_t pkt_buff_flush_to_disk(pkt_buff_t* pkt_buff){
    return buff_flush_to_disk(pkt_buff->_buff);
}


buff_error_t pkt_buff_write(pkt_buff_t* pkt_buff, pcap_pkthdr_t* hdr, char* data, size_t data_len, expcap_pktftr_t* ftr)
{
    buff_error_t err = BUFF_ENONE;
    buff_t* buff = pkt_buff->_buff;

    /* Flush the buffer if we need to */
    uint64_t bytes_remaining;
    err = buff_remaining(buff, &bytes_remaining);
    if(err != BUFF_ENONE){
        ch_log_fatal("Buffer is in invalid state: %s\n", buff_strerror(err));
    }

    const int64_t pcap_record_bytes = sizeof(pcap_pkthdr_t) + data_len + (ftr ? sizeof(expcap_pktftr_t) : 0);
    const bool file_full = bytes_remaining < pcap_record_bytes;
    if(file_full)
    {
        if(buff_flush_to_disk(buff) != 0){
            ch_log_fatal("Failed to flush buffer to disk\n");
        }

        ch_log_info("File is full. Closing\n");
        err = buff_new_file(buff);
        if(err != BUFF_ENONE){
            ch_log_fatal("Failed to create new file: %s, %s\n", buff->filename, buff_strerror(err));
        }
    }

    if(ftr){
        hdr->caplen += sizeof(expcap_pktftr_t);
    }

    ch_log_debug1("header bytes=%li\n", sizeof(pcap_pkthdr_t));
    ch_log_debug1("packet_bytes=%li\n", packet_copy_bytes);
    ch_log_debug1("footer bytes=%li\n", sizeof(expcap_pktftr_t));
    ch_log_debug1("max pcap_record_bytes=%li\n", pcap_record_bytes);

    buff_copy_bytes(buff, hdr, sizeof(pcap_pkthdr_t));
    buff_copy_bytes(buff, data, data_len);

    if(ftr){
        buff_copy_bytes(buff, ftr, sizeof(expcap_pktftr_t));
    }

    return err;
}
