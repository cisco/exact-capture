/*
 * Copyright (c) 2018 All rights reserved.
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
#include <inttypes.h>
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
#include <byteswap.h>
#include <math.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/data_structs/hash_map/hash_map.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/timing/timestamp.h>
#include <chaste/utils/util.h>

#include "src/data_structs/pcap-structures.h"
#include "src/data_structs/expcap.h"
#include "src/data_structs/fusion_hpt.h"
#include "src/data_structs/vlan_ethhdr.h"
#include "src/buff.h"

USE_CH_LOGGER_DEFAULT; //(CH_LOG_LVL_DEBUG3, true, CH_LOG_OUT_STDERR, NULL);
USE_CH_OPTIONS;

bool lstop = 0;

static struct
{
    CH_VECTOR(cstr)* reads;
    char* write;
    char* write_dir;
    ch_word max_file;
    ch_word max_count;
    char* format;
    ch_word usec;
    ch_word snaplen;
    ch_word port;
    ch_word device;
    ch_bool all;
    ch_bool skip_runts;
    ch_bool hpt_trailer;
    ch_bool vlan_filter;
    ch_bool hpt_filter;
    ch_bool expcap_filter;
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

int get_key_from_vlan(char* pbuf, pcap_pkthdr_t* hdr, uint16_t* key)
{
    if(hdr->len < sizeof(vlan_ethhdr_t)){
        ch_log_error("Packet is too small %"PRIu64"to extract VLAN hdr\n", hdr->len);
        return 1;
    }

    vlan_ethhdr_t* vlan_hdr = (vlan_ethhdr_t*)pbuf;
    if(vlan_hdr->h_vlan_proto == 0x0081){
        uint16_t vlan_id = bswap_16(vlan_hdr->h_vlan_TCI) & 0x0FFF;
        *key = vlan_id;
    } else {
        *key = 0;
    }
    return 0;
}

int get_key_from_hpt(char* pbuf, pcap_pkthdr_t* hdr, uint16_t* key)
{
    if(hdr->len < sizeof(fusion_hpt_trailer_t)){
        ch_log_error("Packet is too small %"PRIu64"to extract HPT trailer\n", hdr->len);
        return 1;
    }

    uint64_t trailer_offset = (hdr->len - sizeof(fusion_hpt_trailer_t));
    fusion_hpt_trailer_t* trailer = (fusion_hpt_trailer_t*)(pbuf + trailer_offset);
    uint8_t device = trailer->device_id;
    uint8_t port = trailer->port;
    *key = (uint16_t)device << 8 | (uint16_t)port;
    return 0;
}

int get_key_from_expcap(char* pbuf, pcap_pkthdr_t* hdr, uint16_t* key)
{
    if(hdr->caplen < sizeof(expcap_pktftr_t)){
        ch_log_error("Packet is too small %"PRIu64"to extract expcap trailer\n", hdr->caplen);
        return 1;
    }

    uint64_t trailer_offset = (hdr->caplen - sizeof(expcap_pktftr_t));
    expcap_pktftr_t* trailer = (expcap_pktftr_t*)(pbuf + trailer_offset);
    uint8_t device = trailer->dev_id;
    uint8_t port = trailer->port_id;
    *key = (uint16_t)device << 8 | (uint16_t)port;
    return 0;
}

int format_vlan_key(uint16_t key, char* format_str)
{
    if(key > 0){
        snprintf(format_str, 1024, "_vlan-%u", key);
    } else {
        format_str[0] = '\0';
    }
    return 0;
}

int format_hpt_key(uint16_t key, char* format_str)
{
    uint8_t device = (uint8_t)(key >> 8);
    uint8_t port = (uint8_t)key;
    snprintf(format_str, 1024, "_device-%u_port-%u", device, port);
    return 0;
}
buff_t* test;
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
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'W', "write-dir", "Write output to a directory", &options.write_dir, NULL);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'p', "port",     "Port number to extract", &options.port,-1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'd', "device",   "Device number to extract", &options.device,-1);
    ch_opt_addbi (CH_OPTION_FLAG,     'a', "all",      "Output packets from all ports/devices", &options.all, false);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'f', "format",   "Output format. Valid values are [pcap, expcap]", &options.format, "expcap");
    ch_opt_addii (CH_OPTION_OPTIONAL, 'c', "count",    "Maxium number of packets to output (<=0 means no max)", &options.max_count, 0);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'M', "maxfile",  "Maximum file size in MB (<=0 means no max)", &options.max_file, 0); //128M
    ch_opt_addii (CH_OPTION_OPTIONAL, 'u', "usecpcap", "PCAP output in microseconds", &options.usec, false);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'S', "snaplen",  "Maximum packet length", &options.snaplen, 1518);
    ch_opt_addbi (CH_OPTION_FLAG,     'r', "skip-runts", "Skip runt packets", &options.skip_runts, false);
    ch_opt_addbi (CH_OPTION_FLAG,     't', "hpt-trailer", "Extract timestamps from Fusion HPT trailers", &options.hpt_trailer, false);
    ch_opt_addbi (CH_OPTION_FLAG,     'v', "vlan-filter", "Write to a new pcap for each VLAN tag in the input.", &options.vlan_filter, false);
    ch_opt_addbi (CH_OPTION_FLAG,     'T', "HPT-filter", "Write to a new pcap based on Fusion HPT port/device.", &options.hpt_filter, false);
    ch_opt_addbi (CH_OPTION_FLAG,     'P', "port-filter", "Write to a new pcap based on the expcap port/device.", &options.expcap_filter, false);

    ch_opt_parse (argc, argv);

    options.max_file *= 1024 * 1024; /* Convert max file size from MB to B */

    ch_log_settings.log_level = CH_LOG_LVL_DEBUG1;

    if(!options.write && !options.write_dir){
        ch_log_fatal("Must supply an output (-w file or -W directory)\n");
    }

    if(options.write_dir){
        if(!options.vlan_filter && !options.hpt_filter && !options.expcap_filter){
            ch_log_fatal("Must specify a filtering option to use with -W.\n", options.write_dir, strerror(errno));
        }
        if(mkdir(options.write_dir, 0755) != 0){
            ch_log_fatal("Failed to create directory %s : %s\n", options.write_dir, strerror(errno));
        }
    }

    if(!options.all && (options.port == -1 || options.device == -1)){
        ch_log_fatal("Must supply a port and device number (--dev /--port) or use --all\n");
    }

    if(options.reads->count == 0){
        ch_log_fatal("Please supply input files\n");
    }

    int (*get_key)(char*, pcap_pkthdr_t*, uint16_t*) = NULL;
    int (*format_key)(uint16_t, char*) = NULL;
    if(options.vlan_filter){
        get_key = &get_key_from_vlan;
        format_key = &format_vlan_key;
    } else if (options.hpt_filter) {
        get_key = &get_key_from_hpt;
        format_key = &format_hpt_key;
    } else if (options.expcap_filter) {
        get_key = &get_key_from_expcap;
        format_key = format_hpt_key;
    }

    ch_log_debug1("Starting packet extractor...\n");

    /* Parse the format type */
    enum out_format_type format = EXTR_OPT_FORM_UNKNOWN;
    for(int i = 0; i < OUT_FORMATS_COUNT; i++ ){
        if(strncmp(options.format, out_formats[i].cmdline, strlen(out_formats[i].cmdline))== 0 ){
            format = out_formats[i].type;
        }
    }

    if(format == EXTR_OPT_FORM_UNKNOWN){
        ch_log_fatal("Unknown output format type %s\n", options.format );
    }

    buff_t* wr_buff = NULL;
    buff_t* buff = NULL;
    uint16_t key;
    ch_hash_map* hmap = ch_hash_map_new(65536, sizeof(buff_t), NULL);


    /* Allocate N read buffers where */
    const int64_t rd_buffs_count = options.reads->count;
    buff_t* rd_buffs = (buff_t*)calloc(rd_buffs_count, sizeof(buff_t));
    if(!rd_buffs){
        ch_log_fatal("Could not allocate memory for read buffers table\n");
    }
    for(int i = 0; i < rd_buffs_count; i++){
        if(read_file(&rd_buffs[i], options.reads->first[i]) != 0){
            ch_log_fatal("Failed to read %s into buff_t!\n", options.reads->first[i]);
        }
    }

    ch_log_info("starting main loop with %li buffers\n", rd_buffs_count);

    /* At this point we have read buffers ready for reading data and a write
     * buffer for outputting and file handles ready to go. Fun starts now */

    /* Skip over the PCAP headers in each file */
    for(int i = 0; i < rd_buffs_count; i++){
        rd_buffs[i].pkt = (pcap_pkthdr_t*)(rd_buffs[i].data + sizeof(pcap_file_header_t));
    }

    /* Process the merge */
    ch_log_info("Beginning merge\n");
    int64_t packets_total   = 0;
    int64_t dropped_padding = 0;
    int64_t dropped_runts   = 0;
    int64_t dropped_errors  = 0;

    i64 count = 0;
    for(int i = 0; !lstop ; i++)
    {
begin_loop:
        ch_log_debug1("\n%i ######\n", i );

        /* Check all the FD in case we've read everything  */
        ch_log_debug1("Checking for EOF\n");
        bool all_eof = true;
        for(int i = 0; i < rd_buffs_count; i++){
           all_eof &= rd_buffs[i].eof;
        }
        if(all_eof){
            ch_log_info("All files empty, exiting now\n");
            break;
        }


        ch_log_debug1("Looking for minimum timestamp index on %i buffers\n",
                      rd_buffs_count);
        /* Find the read buffer with the earliest timestamp */
        int64_t min_idx          = 0;


        for(int buff_idx = 0; buff_idx < rd_buffs_count; buff_idx++ ){
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
        char* pkt_data = (char *)(pkt_hdr + 1);

        if(get_key){
            if(get_key(pkt_data, pkt_hdr, &key) != 0){
                ch_log_fatal("Failed to extract key from packet!\n");
            }
        } else {
            key = 0;
        }

        ch_hash_map_it hmit = hash_map_get_first(hmap, &key, sizeof(uint16_t));
        if(hmit.key){
            wr_buff = hmit.value;
        } else {
            buff = (buff_t*)malloc(sizeof(buff_t));
            if(!buff){
                ch_log_fatal("Could not allocate memory new buff\n");
            }
            if(options.write_dir){
                char format_str[1024];
                buff->filename = (char*)malloc(1024);
                if(!buff->filename){
                    ch_log_fatal("Could not allocate memory for filename\n");
                }
                format_key(key, format_str);
                snprintf(buff->filename, 1024, "%s/%s%s", options.write_dir, options.write, format_str);
            } else {
                buff->filename = options.write;
            }
            if(init_buff(buff->filename, buff, options.snaplen, options.max_file, options.usec) != 0){
                ch_log_fatal("Failed to initialize write buffer!\n");
            }
            new_file(buff);
            hash_map_push(hmap, &key, sizeof(uint16_t), buff);
            wr_buff = buff;
            test = buff;
        }

        pcap_pkthdr_t* wr_pkt_hdr = (pcap_pkthdr_t*)(wr_buff->data + wr_buff->offset);
        const int64_t pkt_len = (ch_word)pkt_hdr->len;
        const uint64_t trailer_size = options.hpt_trailer ? sizeof(fusion_hpt_trailer_t) : 0;

        uint64_t hpt_secs = 0;
        uint64_t hpt_psecs = 0;
        if(options.hpt_trailer){
            double hpt_frac = 0;
            fusion_hpt_trailer_t* hpt_trailer = (fusion_hpt_trailer_t*)(pkt_data + pkt_len - trailer_size);
            hpt_frac = ldexp((double)be40toh(hpt_trailer->frac_seconds), -40);
            hpt_psecs = hpt_frac * 1000 * 1000 * 1000 * 1000;
            hpt_secs = bswap_32(hpt_trailer->seconds_since_epoch);
        }

        const int64_t packet_copy_bytes = MIN(options.snaplen, pkt_len - trailer_size + 4);
        const int64_t pcap_record_bytes = sizeof(pcap_pkthdr_t) + packet_copy_bytes + sizeof(expcap_pktftr_t);

        ch_log_debug1("header bytes=%li\n", sizeof(pcap_pkthdr_t));
        ch_log_debug1("packet_bytes=%li\n", packet_copy_bytes);
        ch_log_debug1("footer bytes=%li\n", sizeof(expcap_pktftr_t));
        ch_log_debug1("max pcap_record_bytes=%li\n", pcap_record_bytes);
        ch_log_debug1("Buffer offset=%li, write_buff_size=%li, delta=%li\n",
                      wr_buff->offset, WRITE_BUFF_SIZE,
                      WRITE_BUFF_SIZE - wr_buff->offset);

        if(buff_remaining(wr_buff) < pcap_record_bytes)
        {
            if(flush_to_disk(wr_buff) != 0){
                ch_log_fatal("Failed to flush buffer to disk\n");
            }

            ch_log_info("File is full. Closing\n");
            wr_buff->file_seg++;
            if(new_file(wr_buff) != 0){
                ch_log_fatal("Failed to create new file: %s\n", wr_buff->filename);
            }
        }

        /* Copy the packet header, and upto snap len packet data bytes */
        const int64_t copy_bytes = sizeof(pcap_pkthdr_t) + packet_copy_bytes;
        ch_log_debug1("Copying %li bytes from buffer %li at index=%li into buffer at offset=%li\n", copy_bytes, min_idx, rd_buffs[min_idx].pkt_idx, wr_buff->offset);

        if(buff_copy_bytes(wr_buff, pkt_hdr, copy_bytes) != 0){
            ch_log_fatal("Failed to copy packet data to wr_buff\n");
        }


        /* Update the packet header in case snaplen is less than the original capture */
        wr_pkt_hdr->len = packet_copy_bytes;
        wr_pkt_hdr->caplen = packet_copy_bytes;
        packets_total++;

        /* Extract the timestamp from the footer */
        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)((char*)(pkt_hdr + 1)
                + pkt_hdr->caplen - sizeof(expcap_pktftr_t));
        const uint64_t secs          = options.hpt_trailer ? hpt_secs : pkt_ftr->ts_secs;
        const uint64_t psecs         = options.hpt_trailer ? hpt_psecs : pkt_ftr->ts_psecs;
        const uint64_t psecs_mod1000 = psecs % 1000;
        const uint64_t psecs_floor   = psecs - psecs_mod1000;
        const uint64_t psecs_rounded = psecs_mod1000 >= 500 ? psecs_floor + 1000 : psecs_floor ;
        const uint64_t nsecs         = psecs_rounded / 1000;

        wr_pkt_hdr->ts.ns.ts_sec  = secs;
        wr_pkt_hdr->ts.ns.ts_nsec = nsecs;

        /* Include the footer (if we want it) */
        if(format == EXTR_OPT_FORM_EXPCAP){
            if(buff_copy_bytes(wr_buff, pkt_ftr, sizeof(expcap_pktftr_t)) != 0){
                ch_log_fatal("Failed to copy packet footer to wr_buff\n");
            }
            expcap_pktftr_t* wr_pkt_ftr = (expcap_pktftr_t*)(wr_buff->data + wr_buff->offset);
            wr_pkt_ftr->ts_secs = secs;
            wr_pkt_ftr->ts_psecs = psecs;
            wr_pkt_hdr->caplen += sizeof(expcap_pktftr_t);
        }

        count++;
        wr_buff->usec = 1;
        if(options.max_count && count >= options.max_count){
            break;
        }

       /* Increment packet pointer to look at the next packet */
       next_packet(&rd_buffs[min_idx]);
    }

    ch_log_info("Finished writing %li packets total (Runts=%li, Errors=%li, Padding=%li). Closing\n", packets_total, dropped_runts, dropped_errors, dropped_padding);
    ch_hash_map_it hmit = hash_map_first(hmap);
    while(hmit.value){
        wr_buff = (buff_t*)hmit.value;
        flush_to_disk(wr_buff);
        hash_map_next(hmap, &hmit);
    }

    return 0;
}
