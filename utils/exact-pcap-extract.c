/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     1 March 2018
 *  Author:      Matthew P. Grosvenor
 *  Description: A tool for exacting pcaps form expcap files. It can also be
 *               used to filter expcaps, removing dummy packets and including
 *               only packets from a given device and port.
 *
 */


#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <math.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/timing/timestamp.h>
#include <chaste/utils/util.h>

#include "src/data_structs/pcap-structures.h"
#include "src/data_structs/expcap.h"
#include "src/data_structs/fusion_hpt.h"

USE_CH_LOGGER_DEFAULT; //(CH_LOG_LVL_DEBUG3, true, CH_LOG_OUT_STDERR, NULL);
USE_CH_OPTIONS;

bool lstop = 0;

static struct
{
    CH_VECTOR(cstr)* reads;
    char* write;
    ch_word max_file;
    ch_word max_count;
    char* format;
    ch_word usec;
    ch_word snaplen;
    ch_word port;
    ch_word device;
    ch_bool all;
    ch_bool skip_runts;
    ch_word hpt_device;
    ch_word hpt_port;
} options;

enum out_format_type {
    EXTR_OPT_FORM_UNKNOWN,
    EXTR_OPT_FORM_PCAP,
    EXTR_OPT_FORM_EXPCAP
};

typedef struct {
    char* cmdline;
    enum out_format_type type;
} out_format_t;


#define OUT_FORMATS_COUNT 5
out_format_t out_formats[5] = {
        {"pcap",  EXTR_OPT_FORM_PCAP},
        {"PCAP",  EXTR_OPT_FORM_PCAP},
        {"expcap",EXTR_OPT_FORM_EXPCAP},
        {"exPCAP",EXTR_OPT_FORM_EXPCAP},
        {"EXPCAP",EXTR_OPT_FORM_EXPCAP}
};


/*
 * Signal handler tells all threads to stop, but if you can force exit by
 * sending a second signal
 */
void signal_handler (int signum)
{
    ch_log_warn("Caught signal %li, shutting down\n", signum);
    if (lstop == 1)
    {
        ch_log_fatal("Hard exit\n");
    }
    lstop = 1;
}


typedef struct {
    char* filename;
    char* data;
    pcap_pkthdr_t* pkt;
    bool eof;
    int fd;
    uint64_t filesize;
    uint64_t offset;
    uint64_t pkt_idx;
} buff_t;



/* Return packet with earliest timestamp */
int64_t min_packet_ts(int64_t buff_idx_lhs, int64_t buff_idx_rhs, buff_t* buffs)
{
    ch_log_debug1("checking minimum pcaksts on %li vs %li at %p\n", buff_idx_lhs, buff_idx_rhs, buffs);

    pcap_pkthdr_t* lhs_hdr = buffs[buff_idx_lhs].pkt;
    pcap_pkthdr_t* rhs_hdr = buffs[buff_idx_rhs].pkt;
    //ch_log_info("lhs_hdr=%p, rhs_hdr=%p\n", lhs_hdr, rhs_hdr);


#ifndef NDEBUG
    const int64_t lhs_caplen = lhs_hdr->caplen;
    const int64_t rhs_caplen = rhs_hdr->caplen;
    ch_log_debug1("lhr_caplen=%li, rhs_caplen=%li\n", lhs_caplen, rhs_caplen);
#endif

    expcap_pktftr_t* lhs_ftr = (expcap_pktftr_t*)((char*)lhs_hdr + sizeof(pcap_pkthdr_t) + lhs_hdr->caplen - sizeof(expcap_pktftr_t));
    expcap_pktftr_t* rhs_ftr = (expcap_pktftr_t*)((char*)rhs_hdr + sizeof(pcap_pkthdr_t) + rhs_hdr->caplen - sizeof(expcap_pktftr_t));

    ch_log_debug1("lhs ts = %lu.%lu vs rhs ts =%lu.%lu\n",
                  (uint64_t)lhs_ftr->ts_secs, (uint64_t)lhs_ftr->ts_psecs,
                  (uint64_t)rhs_ftr->ts_secs, (uint64_t)rhs_ftr->ts_psecs);

    if(lhs_ftr->ts_secs < rhs_ftr->ts_secs)
    {
        return buff_idx_lhs;
    }

    if(lhs_ftr->ts_secs > rhs_ftr->ts_secs)
    {
        return buff_idx_rhs;
    }

    /* Here the seconds components are the same */
    if(lhs_ftr->ts_psecs < rhs_ftr->ts_psecs)
    {
        return buff_idx_lhs;
    }

    if(lhs_ftr->ts_psecs > rhs_ftr->ts_psecs)
    {
        return buff_idx_rhs;
    }

    return buff_idx_lhs;

}

/* Open a new file for output, as a buff_t */
void new_file(buff_t* wr_buff, int file_num)
{
    char full_filename[1024] = {0};
    snprintf(full_filename, 1024, "%s_%i.pcap", wr_buff->filename, file_num);

    ch_log_info("Opening output \"%s\"...\n",full_filename );
    wr_buff->fd = open(full_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666 );
    if(wr_buff->fd < 0)
    {
        ch_log_fatal("Could not open output file %s: \"%s\"",
                     full_filename, strerror(errno));
    }

    /* TODO: Currently assumes PCAP output only, would be nice at add ERF */
    /* Generate the output file header */
    pcap_file_header_t hdr;
    hdr.magic = options.usec ? TCPDUMP_MAGIC: NSEC_TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr.snaplen = options.snaplen + (ch_word)sizeof(expcap_pktftr_t);
    hdr.linktype = DLT_EN10MB;
    ch_log_info("Writing PCAP header to fd=%i\n", wr_buff->fd);
    if(write(wr_buff->fd,&hdr,sizeof(hdr)) != sizeof(hdr))
    {
        ch_log_fatal("Could not write PCAP header");
        /*TDOD: handle this failure more gracefully */
    }

}

void flush_to_disk(buff_t* wr_buff, int64_t* file_bytes_written, int64_t packets_written)
{
    (void)packets_written;
    (void)file_bytes_written;

    //ch_log_info("Flushing %liB to fd=%i total=(%liMB) packets=%li\n", wr_buff->offset, wr_buff->fd, *file_bytes_written / 1024/ 1024, packets_written);
    /* Not enough space in the buffer, time to flush it */
    const uint64_t written = write(wr_buff->fd,wr_buff->data,wr_buff->offset);
    if(written < wr_buff->offset)
    {
        ch_log_fatal("Couldn't write all bytes, fix this some time\n");
    }

    wr_buff->offset = 0;

}


void next_packet(buff_t* buff)
{
    pcap_pkthdr_t* curr_pkt    = buff->pkt;
    const int64_t curr_cap_len = curr_pkt->caplen;
    ch_log_debug1("Skipping %li bytes ahead\n", curr_cap_len);
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

#define READ_BUFF_SIZE (128 * 1024 * 1024) /* 128MB */
#define WRITE_BUFF_SIZE (128 * 1024 * 1024) /* 128MB */





/**
 * Main loop sets up threads and listens for stats / configuration messages.
 */
int main (int argc, char** argv)
{
    signal (SIGHUP, signal_handler);
    signal (SIGINT, signal_handler);
    signal (SIGPIPE, signal_handler);
    signal (SIGALRM, signal_handler);
    signal (SIGTERM, signal_handler);


//    ch_opt_name("Exact Extract");
//    ch_opt_short_description("Extracts PCAP and exPCAP files out of exact cap ecap files.");

    ch_opt_addSU (CH_OPTION_UNLIMTED, 'i', "input",    "exact-capture expcap files to extract from", &options.reads);
    ch_opt_addsu (CH_OPTION_REQUIRED, 'w', "write",    "Destination to write output to", &options.write);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'p', "port",     "Port number to extract", &options.port,-1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'd', "device",   "Device number to extract", &options.device,-1);
    ch_opt_addbi (CH_OPTION_FLAG,     'a', "all",      "Output packets from all ports/devices", &options.all, false);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'f', "format",   "Output format. Valid values are [pcap, expcap]", &options.format, "expcap");
    ch_opt_addii (CH_OPTION_OPTIONAL, 'c', "count",    "Maxium number of packets to output (<=0 means no max)", &options.max_count, 0);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'M', "maxfile",  "Maximum file size in MB (<=0 means no max)", &options.max_file, 0); //128M
    ch_opt_addii (CH_OPTION_OPTIONAL, 'u', "usecpcap", "PCAP output in microseconds", &options.usec, false);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'S', "snaplen",  "Maximum packet length", &options.snaplen, 1518);
    ch_opt_addbi (CH_OPTION_FLAG,     'r', "skip-runts", "Skip runt packets", &options.skip_runts, false);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'D', "hpt-device", "Fusion HPT device-tagged packets to extract", &options.hpt_device, -1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 't', "hpt-port", "Fusion HPT port-tagged packets to extract", &options.hpt_port, -1);
    ch_opt_parse (argc, argv);

    options.max_file *= 1024 * 1024; /* Convert max file size from MB to B */

    ch_log_settings.log_level = CH_LOG_LVL_DEBUG1;


    if(!options.all && (options.port == -1 || options.device == -1))
    {
        ch_log_fatal("Must supply a port and device number (--dev /--port) or use --all\n");
    }

    if(options.reads->count == 0)
    {
        ch_log_fatal("Please supply input files\n");
    }

    ch_log_debug1("Starting packet extractor...\n");

    /* Parse the format type */
    enum out_format_type format = EXTR_OPT_FORM_UNKNOWN;
    for(int i = 0; i < OUT_FORMATS_COUNT; i++ )
        if(strncmp(options.format, out_formats[i].cmdline, strlen(out_formats[i].cmdline))== 0 )
        {
            format = out_formats[i].type;
        }

    if(format == EXTR_OPT_FORM_UNKNOWN)
    {
        ch_log_fatal("Unknown output format type %s\n", options.format );
    }

    buff_t wr_buff = {0};
    wr_buff.data = calloc(1, WRITE_BUFF_SIZE);
    if(!wr_buff.data)
    {
        ch_log_fatal("Could not allocate memory for write buffer\n");
    }
    wr_buff.filename = options.write;


    /* Allocate N read buffers where */
    const int64_t rd_buffs_count = options.reads->count;
    buff_t* rd_buffs = (buff_t*)calloc(rd_buffs_count, sizeof(buff_t));
    if(!rd_buffs)
    {
        ch_log_fatal("Could not allocate memory for read buffers table\n");
    }
    for(int i = 0; i < rd_buffs_count; i++)
    {
        rd_buffs[i].filename = options.reads->first[i];
        ch_log_debug1("Opening input %s...\n",rd_buffs[i].filename );
        rd_buffs[i].fd = open(rd_buffs[i].filename,O_RDONLY);
        if(!rd_buffs[i].fd)
        {
            ch_log_fatal("Could not open input file %s: \"%s\"",
                         rd_buffs[i].filename, strerror(errno));
        }

        struct stat st = {0};
        if(stat(rd_buffs[i].filename, &st))
        {
            ch_log_fatal("Could not stat file %s: \"%s\"\n",
                         rd_buffs[i].filename, strerror(errno));
        }
        rd_buffs[i].filesize = st.st_size;


        rd_buffs[i].data = mmap(NULL, rd_buffs[i].filesize,
                                  PROT_READ,
                                  MAP_PRIVATE , //| MAP_POPULATE ,
                                  rd_buffs[i].fd, 0);
        ch_log_debug1("File mapped at %p\n", rd_buffs[i].data);
        if(rd_buffs[i].data == MAP_FAILED)
        {
            ch_log_fatal("Could not map input file %s: \"%s\"\n",
                             rd_buffs[i].filename, strerror(errno));
        }

    }

    ch_log_info("starting main loop with %li buffers\n", rd_buffs_count);


    /* At this point we have read buffers ready for reading data and a write
     * buffer for outputting and file handles ready to go. Fun starts now*/


    /* Skip over the PCAP headers in each file */
    for(int i = 0; i < rd_buffs_count; i++)
    {
        rd_buffs[i].pkt = (pcap_pkthdr_t*)(rd_buffs[i].data + sizeof(pcap_file_header_t));
    }


    /* Process the merge */
    ch_log_info("Beginning merge\n");
    int64_t file_bytes_written = 0;
    int64_t file_seg = 0;
    new_file(&wr_buff, file_seg);

    int64_t packets_total   = 0;
    int64_t dropped_padding = 0;
    int64_t dropped_runts   = 0;
    int64_t dropped_errors  = 0;
    int64_t dropped_errors_abrt   = 0;
    int64_t dropped_errors_crpt   = 0;
    int64_t dropped_errors_swofl  = 0;

    i64 count = 0;
    for(int i = 0; !lstop ; i++)
    {
begin_loop:
        ch_log_debug1("\n%i ######\n", i );

        /* Check all the FD in case we've read everything  */
        ch_log_debug1("Checking for EOF\n");
        bool all_eof = true;
        for(int i = 0; i < rd_buffs_count; i++)
        {
           all_eof &= rd_buffs[i].eof;
        }
        if(all_eof)
        {
            ch_log_info("All files empty, exiting now\n");
            break;
        }


        ch_log_debug1("Looking for minimum timestamp index on %i buffers\n",
                      rd_buffs_count);
        /* Find the read buffer with the earliest timestamp */
        int64_t min_idx          = 0;


        for(int buff_idx = 0; buff_idx < rd_buffs_count; buff_idx++ )
        {
            if(rd_buffs[buff_idx].eof){
                if(min_idx == buff_idx){
                    min_idx = buff_idx+1;
                }
                continue;
            }

            pcap_pkthdr_t* pkt_hdr = rd_buffs[buff_idx].pkt;
#ifndef NDEBUG
            int64_t pkt_idx  = rd_buffs[buff_idx].pkt_idx;
#endif
            if(pkt_hdr->len == 0){
                /* Skip over this packet, it's a dummy so we don't want it*/
                ch_log_debug1("Skipping over packet %i (buffer %i) because len=0\n",pkt_idx , buff_idx);
                dropped_padding++;
                next_packet(&rd_buffs[buff_idx]);
                if(rd_buffs[buff_idx].eof){
                    goto begin_loop;
                }
                buff_idx--;
                continue;
            }

            expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)((char*)(pkt_hdr + 1)
                    + pkt_hdr->caplen - sizeof(expcap_pktftr_t));

            const uint64_t offset = (char*)pkt_ftr - rd_buffs[buff_idx].data;
            if(offset > rd_buffs[buff_idx].filesize){
                ch_log_warn("End of file \"%s\"\n", rd_buffs[buff_idx].filename);
                rd_buffs[buff_idx].eof = 1;
                goto begin_loop;
            }



            if(!options.all && (pkt_ftr->port_id != options.port || pkt_ftr->dev_id != options.device)){
                ch_log_debug1("Skipping over packet %i (buffer %i) because port %li != %lu or %li != %lu\n",
                              pkt_idx, buff_idx, (uint64_t)pkt_ftr->port_id, options.port,
                              (uint64_t)pkt_ftr->dev_id, options.device);
                next_packet(&rd_buffs[buff_idx]);
                if(rd_buffs[buff_idx].eof){
                    goto begin_loop;
                }
                buff_idx--;
                continue;
            }

            if(pkt_hdr->caplen < 64){
                ch_log_debug1("Skipping over runt frame %i (buffer %i) \n",
                              pkt_idx, buff_idx);
                dropped_runts++;
                if(options.skip_runts)
                {
                    next_packet(&rd_buffs[buff_idx]);
                    if(rd_buffs[buff_idx].eof)
                    {
                        goto begin_loop;
                    }
                    buff_idx--;

                    continue;
                }
            }


            if(pkt_ftr->foot.extra.dropped > 0){
                ch_log_warn("%li packets were droped before this one\n",
                            pkt_ftr->foot.extra.dropped);
            }

            if( (pkt_ftr->flags & EXPCAP_FLAG_ABRT) ||
                (pkt_ftr->flags & EXPCAP_FLAG_CRPT) ||
                (pkt_ftr->flags & EXPCAP_FLAG_SWOVFL)){

                if(pkt_ftr->flags & EXPCAP_FLAG_ABRT)
                    dropped_errors_abrt++;

                if(pkt_ftr->flags & EXPCAP_FLAG_CRPT)
                    dropped_errors_crpt++;

                if(pkt_ftr->flags & EXPCAP_FLAG_SWOVFL)
                    dropped_errors_swofl++;


                dropped_errors++;
                ch_log_debug1("Skipping over damaged packet %i (buffer %i) because flags = 0x%02x\n",
                              pkt_idx, buff_idx, pkt_ftr->flags);
                next_packet(&rd_buffs[buff_idx]);
                if(rd_buffs[buff_idx].eof){
                    goto begin_loop;
                }
                buff_idx--;
                continue;
            }


            min_idx = min_packet_ts(min_idx, buff_idx, rd_buffs);
            ch_log_debug1("Minimum timestamp index is %i \n", min_idx);
        }


        pcap_pkthdr_t* pkt_hdr = rd_buffs[min_idx].pkt;
        const int64_t packet_len = (ch_word)pkt_hdr->caplen - (ch_word)sizeof(expcap_pktftr_t);

        /* TODO add more comprehensive filtering in here */
        char* pkt_data = (char *)(pkt_hdr + 1);

        fusion_hpt_trailer_t* hpt_trailer = (fusion_hpt_trailer_t *)((pkt_data + packet_len) - sizeof(fusion_hpt_trailer_t));

        const bool extract_hpt = options.hpt_device > -1 || options.hpt_port > -1;
        if(extract_hpt){
            if((options.hpt_device > -1 && options.hpt_device != hpt_trailer->device_id) ||
               (options.hpt_port > -1 && options.hpt_port !=  hpt_trailer->port)) {
                goto next_packet;
            }
        }

        /* HPT trailers will be stripped in the final capture, original FCS is kept */
        const int64_t packet_copy_bytes = MIN(options.snaplen, packet_len - ((extract_hpt) ? sizeof(fusion_hpt_trailer_t) - 4 : 0));
        const int64_t pcap_record_bytes = sizeof(pcap_pkthdr_t) + packet_copy_bytes + sizeof(expcap_pktftr_t);

        ch_log_debug1("header bytes=%li\n", sizeof(pcap_pkthdr_t));
        ch_log_debug1("packet_bytes=%li\n", packet_copy_bytes);
        ch_log_debug1("footer bytes=%li\n", sizeof(expcap_pktftr_t));
        ch_log_debug1("max pcap_record_bytes=%li\n", pcap_record_bytes);

        ch_log_debug1("Buffer offset=%li, write_buff_size=%li, delta=%li\n",
                      wr_buff.offset, WRITE_BUFF_SIZE,
                      WRITE_BUFF_SIZE - wr_buff.offset);

        /* Flush the buffer if we need to */
        const bool file_full = options.max_file > 0 &&
                 (file_bytes_written + pcap_record_bytes) > options.max_file ;

        if(file_full || wr_buff.offset + pcap_record_bytes > WRITE_BUFF_SIZE)
        {
            flush_to_disk(&wr_buff, &file_bytes_written, packets_total);

            if(file_full){
                    ch_log_info("File is full. Closing\n");
                    close(wr_buff.fd);
                    file_seg++;
                    file_bytes_written = 0;
                    new_file(&wr_buff, file_seg);
            }
        }


        /* Copy the packet header, and upto snap len packet data bytes */
        const int64_t copy_bytes =  sizeof(pcap_pkthdr_t) + packet_copy_bytes;
        ch_log_debug1("Copying %li bytes from buffer %li at index=%li into buffer at offset=%li\n", copy_bytes, min_idx, rd_buffs[min_idx].pkt_idx, wr_buff.offset);
        memcpy(wr_buff.data + wr_buff.offset, pkt_hdr, copy_bytes);
        packets_total++;

        /* Update the packet header in case snaplen is less than the original capture */
        pcap_pkthdr_t* wr_pkt_hdr = (pcap_pkthdr_t*)(wr_buff.data + wr_buff.offset);
        /* Update the wire length as HPT trailer may be stripped */
        wr_pkt_hdr->len = packet_copy_bytes;
        wr_pkt_hdr->caplen = packet_copy_bytes;

        double hpt_frac = 0;
        uint64_t hpt_psecs = 0;
        uint64_t hpt_secs = 0;
        if (extract_hpt) {
            hpt_frac = ldexp((double)be40toh(hpt_trailer->frac_seconds), -40);
            hpt_psecs = hpt_frac * 1000 * 1000 * 1000 * 1000;
            hpt_secs = be32toh(hpt_trailer->seconds_since_epoch);
        }

        /* Extract the timestamp from the footer */
        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)((char*)(pkt_hdr + 1)
                + pkt_hdr->caplen - sizeof(expcap_pktftr_t));
        const uint64_t secs          = (extract_hpt) ? hpt_secs : pkt_ftr->ts_secs;
        const uint64_t psecs         = (extract_hpt) ? hpt_psecs : pkt_ftr->ts_psecs;
        const uint64_t psecs_mod1000 = psecs % 1000;
        const uint64_t psecs_floor   = psecs - psecs_mod1000;
        const uint64_t psecs_rounded = psecs_mod1000 >= 500 ? psecs_floor + 1000 : psecs_floor ;
        const uint64_t nsecs         = psecs_rounded / 1000;

        wr_pkt_hdr->ts.ns.ts_sec  = secs;
        wr_pkt_hdr->ts.ns.ts_nsec = nsecs;

        wr_buff.offset += copy_bytes;
        file_bytes_written += copy_bytes;

        /* Include the footer (if we want it) */
        if(format == EXTR_OPT_FORM_EXPCAP)
        {
            expcap_pktftr_t wr_pkt_ftr = *pkt_ftr;
            wr_pkt_ftr.ts_secs = secs;
            wr_pkt_ftr.ts_psecs = psecs;
            memcpy(wr_buff.data + wr_buff.offset, &wr_pkt_ftr, sizeof(expcap_pktftr_t));
            wr_buff.offset     += sizeof(expcap_pktftr_t);
            file_bytes_written += sizeof(expcap_pktftr_t);
            wr_pkt_hdr->caplen += sizeof(expcap_pktftr_t);
        }

        count++;
        if(options.max_count && count >= options.max_count){
            break;
        }

    next_packet:
       /* Increment packet pointer to look at the next packet */
       next_packet(&rd_buffs[min_idx]);
    }

    ch_log_info("Finished writing %li packets total (Runts=%li, Errors=%li (%li, %li, %li), Padding=%li). Closing\n", packets_total, dropped_runts, dropped_errors, dropped_errors_abrt, dropped_errors_crpt, dropped_errors_swofl, dropped_padding);
    flush_to_disk(&wr_buff, &file_bytes_written, packets_total);
    close(wr_buff.fd);



    return 0;
}
