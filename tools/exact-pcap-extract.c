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
#include <sys/resource.h>
#include <inttypes.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/data_structs/hash_map/hash_map.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/timing/timestamp.h>
#include <chaste/utils/util.h>

#include "../src/data_structs/pcap-structures.h"
#include "../src/data_structs/expcap.h"
#include "data_structs/fusion_hpt.h"
#include "data_structs/vlan_ethhdr.h"
#include "data_structs/pcap_buff.h"

#define BUFF_HMAP_SIZE 1024
#define MAX_FD_LIMIT 8192

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
    ch_bool allow_duplicates;
    ch_bool hpt_trailer;
    char* steer_type;
    ch_bool verbose;
} options;

enum out_format_type {
    EXTR_OPT_FORM_UNKNOWN,
    EXTR_OPT_FORM_PCAP,
    EXTR_OPT_FORM_EXPCAP
};

enum steer_type {
    STEER_NONE,
    STEER_FUSION_HPT,
    STEER_VLAN,
    STEER_EXPCAP
};

typedef struct {
    char* cmdline;
    enum out_format_type type;
} out_format_t;

typedef struct {
    char* cmdline;
    enum steer_type type;
} steer_t;

#define OUT_FORMATS_COUNT 5
out_format_t out_formats[OUT_FORMATS_COUNT] = {
        {"pcap",  EXTR_OPT_FORM_PCAP},
        {"PCAP",  EXTR_OPT_FORM_PCAP},
        {"expcap",EXTR_OPT_FORM_EXPCAP},
        {"exPCAP",EXTR_OPT_FORM_EXPCAP},
        {"EXPCAP",EXTR_OPT_FORM_EXPCAP}
};

#define STEER_RULES_COUNT 7
steer_t steer_rules[STEER_RULES_COUNT] = {
    {"hpt",   STEER_FUSION_HPT},
    {"HPT",   STEER_FUSION_HPT},
    {"vlan",  STEER_VLAN},
    {"VLAN",  STEER_VLAN},
    {"expcap",STEER_EXPCAP},
    {"exPCAP",STEER_EXPCAP},
    {"EXPCAP",STEER_EXPCAP}
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
int64_t min_packet_ts(int64_t buff_idx_lhs, int64_t buff_idx_rhs, pcap_buff_t* buffs)
{
    ch_log_debug1("checking minimum packet ts on %li vs %li at %p\n", buff_idx_lhs, buff_idx_rhs, buffs);

#ifndef NDEBUG
    pcap_pkthdr_t* lhs_hdr = buffs[buff_idx_lhs].hdr;
    pcap_pkthdr_t* rhs_hdr = buffs[buff_idx_rhs].hdr;
    const int64_t lhs_caplen = lhs_hdr->caplen;
    const int64_t rhs_caplen = rhs_hdr->caplen;
    ch_log_debug1("lhr_caplen=%li, rhs_caplen=%li\n", lhs_caplen, rhs_caplen);
#endif

    expcap_pktftr_t* lhs_ftr = buffs[buff_idx_lhs].ftr;
    expcap_pktftr_t* rhs_ftr = buffs[buff_idx_rhs].ftr;

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

static inline int get_key_from_vlan(pcap_buff_t* buff, uint16_t* key)
{
    if(buff->hdr->len < sizeof(vlan_ethhdr_t)){
        ch_log_error("Packet is too small %"PRIu64"to extract VLAN hdr\n", buff->hdr->len);
        return 1;
    }

    vlan_ethhdr_t* vlan_hdr = (vlan_ethhdr_t*)buff->pkt;
    if(vlan_hdr->h_vlan_proto == 0x0081){
        uint16_t vlan_id = bswap_16(vlan_hdr->h_vlan_TCI) & 0x0FFF;
        *key = vlan_id;
    } else {
        *key = 0;
    }
    return 0;
}

static inline int get_key_from_hpt(pcap_buff_t* buff, uint16_t* key)
{
    if(buff->hdr->len < sizeof(fusion_hpt_trailer_t)){
        ch_log_error("Packet is too small %"PRIu64"to extract HPT trailer\n", buff->hdr->len);
        return 1;
    }

    uint64_t trailer_offset = (buff->hdr->len - sizeof(fusion_hpt_trailer_t));
    fusion_hpt_trailer_t* trailer = (fusion_hpt_trailer_t*)(buff->pkt + trailer_offset);
    uint8_t device = trailer->device_id;
    uint8_t port = trailer->port;
    *key = (uint16_t)device << 8 | (uint16_t)port;
    return 0;
}

static inline int get_key_from_expcap(pcap_buff_t* buff, uint16_t* key)
{
    if(buff->hdr->caplen < sizeof(expcap_pktftr_t)){
        ch_log_error("Packet is too small %"PRIu64"to extract expcap trailer\n", buff->hdr->caplen);
        return 1;
    }

    uint64_t trailer_offset = (buff->hdr->caplen - sizeof(expcap_pktftr_t));
    expcap_pktftr_t* trailer = (expcap_pktftr_t*)(buff->pkt + trailer_offset);
    uint8_t device = trailer->dev_id;
    uint8_t port = trailer->port_id;
    *key = (uint16_t)device << 8 | (uint16_t)port;
    return 0;
}

static inline void format_vlan_key(uint16_t key, char* output_str, size_t len)
{
    if(key > 0){
        snprintf(output_str, len, "_vlan_%u", key);
    } else {
        output_str[0] = '\0';
    }
}

static inline void format_hpt_key(uint16_t key, char* output_str, size_t len)
{
    uint8_t device = (uint8_t)(key >> 8);
    uint8_t port = (uint8_t)key;
    snprintf(output_str, len, "_device_%u_port_%u", device, port);
}

static inline uint16_t get_steer_key(enum steer_type rule, pcap_buff_t* buff)
{
    int status = 0;
    uint16_t key = 0;

    switch(rule){
    case STEER_FUSION_HPT:
        status = get_key_from_hpt(buff, &key);
        break;
    case STEER_VLAN:
        status = get_key_from_vlan(buff, &key);
        break;
    case STEER_EXPCAP:
        status = get_key_from_expcap(buff, &key);
        break;
    case STEER_NONE:
        break;
    }
    if(status != 0){
        ch_log_fatal("Failed to extract a steering rule from packet data!\n");
    }

    return key;
}

/* Based on a steering key, format a string used for steered file names. */
static inline char* format_steer_key(enum steer_type rule, uint16_t key)
{
    char* format_str = NULL;

    switch(rule){
    case STEER_EXPCAP: // Fall through - same formatting is used for HPT and expcap steering
    case STEER_FUSION_HPT:
        format_str = (char*)malloc(MAX_FILENAME);
        if(!format_str){
            ch_log_fatal("Could not allocate memory for formatted filename\n");
        }
        format_hpt_key(key, format_str, MAX_FILENAME);
        break;
    case STEER_VLAN:
        format_str = (char*)malloc(MAX_FILENAME);
        if(!format_str){
            ch_log_fatal("Could not allocate memory for formatted filename\n");
        }
        format_vlan_key(key, format_str, MAX_FILENAME);
        break;
    case STEER_NONE:
        format_str = "";
    }
    if(!format_str){
        ch_log_fatal("Failed to format string from key!\n");
    }

    return format_str;
}

static pcap_buff_t* init_wr_buff(char* filename, bool conserve_fds)
{
    pcap_buff_t* buff = (pcap_buff_t*)malloc(sizeof(pcap_buff_t));
    char* full_filename = NULL;

    if(!buff){
        ch_log_fatal("Could not allocate memory for new pcap_buff_t\n");
    }

    if(options.write_dir){
        full_filename = (char*)malloc(MAX_FILENAME);
        if(!full_filename){
            ch_log_fatal("Could not allocate memory for new pcap_buff_t filename\n");
        }
        snprintf(full_filename, MAX_FILENAME, "%s/%s%s", options.write_dir, options.write, filename);

    } else {
        full_filename = options.write;
    }

    buff_error_t err = pcap_buff_init(full_filename, options.snaplen, options.max_file, options.usec, conserve_fds,
                                      options.allow_duplicates, buff);
    if(err != BUFF_ENONE){
        ch_log_fatal("Failed to create a new write buffer: %s\n", buff_strerror(err));
    }
    return buff;
}

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
    ch_opt_addbi (CH_OPTION_FLAG,     'D', "allow-duplicates", "Allow duplicate filenames to be used", &options.allow_duplicates, false);
    ch_opt_addbi (CH_OPTION_FLAG,     't', "hpt-trailer", "Extract timestamps from Fusion HPT trailers", &options.hpt_trailer, false);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 's', "steer",    "Steer packets to different files depending on packet contents. Valid values are [hpt, vlan, expcap]", &options.steer_type, NULL);
    ch_opt_addbi (CH_OPTION_FLAG,     'v', "verbose",  "Printout verbose output.", &options.verbose, false);

    ch_opt_parse (argc, argv);

    options.max_file *= 1000 * 1000; /* Per tcpdump, max filesize is in 1,000,000B, not 1,048,576B */

    ch_log_settings.log_level = CH_LOG_LVL_DEBUG1;

    if(!options.write && !options.write_dir){
        ch_log_fatal("Must supply an output (-w file or -W directory)\n");
    }

    bool conserve_fds = false;
    struct rlimit rlim;
    if(options.write_dir){
        if(!options.steer_type){
            ch_log_fatal("Must specify a steering option to use with -W.\n", options.write_dir, strerror(errno));
        }

        if(mkdir(options.write_dir, 0755) != 0){
            if(errno == EEXIST){
                ch_log_info("Using existing directory %s : %s\n", options.write_dir);
            } else {
                ch_log_fatal("Failed to make new directory %s : %s\n", options.write_dir, strerror(errno));
            }
        }

        /* Try to raise the max file descriptor limit. */
        rlim.rlim_cur = MAX_FD_LIMIT;
        rlim.rlim_max = MAX_FD_LIMIT;
        if(setrlimit(RLIMIT_NOFILE, &rlim) != 0){
            ch_log_warn("Could not raise the limit on concurrently open files.\n"
                        "Allowing exact-pcap-extract to raise its limit on open files can lead to an improvement in performance.\n"
                        "See the exact-capture utility documentation for more information.\n", strerror(errno));
            conserve_fds = true;
        }
    }

    if(!options.all && (options.port == -1 || options.device == -1)){
        ch_log_fatal("Must supply a port and device number (--dev /--port) or use --all\n");
    }

    if(options.reads->count == 0){
        ch_log_fatal("Please supply input files\n");
    }

    ch_log_debug1("Starting packet extractor...\n");

    /* Parse the format type */
    enum out_format_type format = EXTR_OPT_FORM_UNKNOWN;
    for(int i = 0; i < OUT_FORMATS_COUNT; i++){
        if(strncmp(options.format, out_formats[i].cmdline, strlen(out_formats[i].cmdline)) == 0){
            format = out_formats[i].type;
        }
    }

    if(format == EXTR_OPT_FORM_UNKNOWN){
        ch_log_fatal("Unknown output format type %s\n", options.format);
    }

    /* Parse steering options */
    enum steer_type steer_rule = STEER_NONE;
    if(options.steer_type){
        for(int i = 0; i < STEER_RULES_COUNT; i++){
            if(strncmp(options.steer_type, steer_rules[i].cmdline, strlen(steer_rules[i].cmdline)) == 0){
                steer_rule = steer_rules[i].type;
            }
        }

        if(steer_rule == STEER_NONE){
            ch_log_fatal("Unknown steer rule %s\n", options.steer_type);
        }
    }

    pcap_buff_t* wr_buff;
    buff_error_t buff_err = BUFF_ENONE;
    uint16_t key;
    ch_hash_map* hmap = ch_hash_map_new(BUFF_HMAP_SIZE, sizeof(pcap_buff_t), NULL);

    /* Allocate N read buffers where */
    const int64_t rd_buffs_count = options.reads->count;
    pcap_buff_t* rd_buffs = (pcap_buff_t*)calloc(rd_buffs_count, sizeof(pcap_buff_t));
    if(!rd_buffs){
        ch_log_fatal("Could not allocate memory for read buffers table\n");
    }
    for(int i = 0; i < rd_buffs_count; i++){
        buff_err = pcap_buff_from_file(&rd_buffs[i], options.reads->first[i]);
        if(buff_err != BUFF_ENONE){
            ch_log_fatal("Failed to read %s into a pcap_buff_t: %s\n", options.reads->first[i], buff_strerror(buff_err));
        }
    }

    ch_log_info("starting main loop with %li buffers\n", rd_buffs_count);
  
    /* At this point we have read buffers ready for reading data and a write
     * buffer for outputting and file handles ready to go. Fun starts now.
     * Skip over the PCAP headers in each file */
    /* Process the merge */
    ch_log_info("Beginning merge\n");
    if(buff_err != BUFF_ENONE){
        ch_log_fatal("Failed to create new file for writer buff: %s\n", buff_strerror(buff_err));
    }

    int64_t packets_total   = 0;
    int64_t dropped_padding = 0;
    int64_t dropped_runts   = 0;
    int64_t dropped_errors  = 0;
    pkt_info_t pkt_info;
    i64 count = 0;
    for(int i = 0; !lstop ; i++)
    {
begin_loop:
        ch_log_debug1("\n%i ######\n", i );

        /* Check all the FD in case we've read everything  */
        ch_log_debug1("Checking for EOF\n");
        bool all_eof = true;
        for(int i = 0; i < rd_buffs_count; i++){
            all_eof &= pcap_buff_eof(&rd_buffs[i]);
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
            if(pcap_buff_eof(&rd_buffs[buff_idx])){
                if(min_idx == buff_idx){
                    min_idx = buff_idx+1;
                }
                continue;
            }

            pkt_info = pcap_buff_get_info(&rd_buffs[buff_idx]);
            const char* cur_filename = pcap_buff_get_filename(&rd_buffs[buff_idx]);
            const uint64_t pkt_idx = rd_buffs[buff_idx].idx;

            switch(pkt_info){
            case PKT_PADDING:
                ch_log_debug1("Skipping over packet %i (buffer %i) because len=0\n", pkt_idx, buff_idx);
                dropped_padding++;
                buff_idx--;
                pcap_buff_next_packet(&rd_buffs[buff_idx]);
                continue;
            case PKT_RUNT:
                if(options.skip_runts){
                    ch_log_debug1("Skipping over runt frame %i (buffer %i) \n", pkt_idx, buff_idx);
                    dropped_runts++;
                    buff_idx--;
                    pcap_buff_next_packet(&rd_buffs[buff_idx]);
                    continue;
                }
                break;
            case PKT_ERROR:
                ch_log_debug1("Skipping over damaged packet %i (buffer %i) because flags = 0x%02x\n",
                              pkt_idx, buff_idx, rd_buffs[buff_idx].ftr->flags);
                dropped_errors++;
                buff_idx--;
                pcap_buff_next_packet(&rd_buffs[buff_idx]);
                continue;
            case PKT_EOF:
                ch_log_debug1("End of file \"%s\"\n", cur_filename);
                goto begin_loop;
                break;
            case PKT_OVER_SNAPLEN:
                 ch_log_fatal("Packet with index %d (%s) does not comply with snaplen: %d (data len is %d)\n",
                              pkt_idx, cur_filename, rd_buffs[buff_idx].snaplen, rd_buffs[buff_idx].hdr->len);
            case PKT_SNAPPED: // Fall through
                if(options.verbose){
                    ch_log_warn("Packet has been snapped shorter (%d) than it's wire length (%d) [%s].\n",
                                rd_buffs[buff_idx].hdr->caplen, rd_buffs[buff_idx].hdr->len, cur_filename);
                }
            case PKT_OK:
                break;
            }

            min_idx = min_packet_ts(min_idx, buff_idx, rd_buffs);
            ch_log_debug1("Minimum timestamp index is %i \n", min_idx);
        }

        const pcap_pkthdr_t* pkt_hdr = rd_buffs[min_idx].hdr;
        const int64_t pkt_len = pkt_hdr->len;
        const char* pkt_data = rd_buffs[min_idx].pkt;
        const int64_t trailer_size = options.hpt_trailer ? sizeof(fusion_hpt_trailer_t) : 0;
        pcap_pkthdr_t wr_pkt_hdr;
        int64_t packet_copy_bytes = MIN(options.snaplen, (ch_word)pkt_hdr->caplen - (ch_word)sizeof(expcap_pktftr_t) - trailer_size);
#ifndef NDEBUG
        const int64_t pcap_record_bytes = sizeof(pcap_pkthdr_t) + packet_copy_bytes + sizeof(expcap_pktftr_t);
#endif

        key = get_steer_key(steer_rule, &rd_buffs[min_idx]);

        ch_hash_map_it hmit = hash_map_get_first(hmap, &key, sizeof(uint16_t));
        if(hmit.key){
            wr_buff = hmit.value;
        } else {
            char* format_str = format_steer_key(steer_rule, key);
            wr_buff = init_wr_buff(format_str, conserve_fds);
            hash_map_push(hmap, &key, sizeof(uint16_t), wr_buff);
        }

        uint64_t hpt_secs = 0;
        uint64_t hpt_psecs = 0;
        if(options.hpt_trailer){
            double hpt_frac = 0;
            fusion_hpt_trailer_t* hpt_trailer = (fusion_hpt_trailer_t*)(pkt_data + pkt_len - trailer_size);
            hpt_frac = ldexp((double)be40toh(hpt_trailer->frac_seconds), -40);
            hpt_psecs = hpt_frac * 1000 * 1000 * 1000 * 1000;
            hpt_secs = bswap_32(hpt_trailer->seconds_since_epoch);
        }

#ifndef NDEBUG
        const int64_t pcap_record_bytes = sizeof(pcap_pkthdr_t) + packet_copy_bytes + sizeof(expcap_pktftr_t);
#endif

        /* Extract the timestamp from the footer */
        expcap_pktftr_t* pkt_ftr = rd_buffs[min_idx].ftr;
        const uint64_t secs          = options.hpt_trailer ? hpt_secs : pkt_ftr->ts_secs;
        const uint64_t psecs         = options.hpt_trailer ? hpt_psecs : pkt_ftr->ts_psecs;
        const uint64_t psecs_mod1000 = psecs % 1000;
        const uint64_t psecs_floor   = psecs - psecs_mod1000;
        const uint64_t psecs_rounded = psecs_mod1000 >= 500 ? psecs_floor + 1000 : psecs_floor ;
        const uint64_t nsecs         = psecs_rounded / 1000;

        /* Update the packet header in case snaplen is less than the original capture */
        wr_pkt_hdr.len = pkt_len - trailer_size;
        wr_pkt_hdr.caplen = packet_copy_bytes;
        wr_pkt_hdr.ts.ns.ts_sec  = secs;
        wr_pkt_hdr.ts.ns.ts_nsec = nsecs;

        expcap_pktftr_t wr_pkt_ftr;
        /* Include the footer (if we want it) */
        if(format == EXTR_OPT_FORM_EXPCAP){
            wr_pkt_ftr = *pkt_ftr;
            wr_pkt_ftr.ts_secs = secs;
            wr_pkt_ftr.ts_psecs = psecs;
        }

        /* Copy the packet header, and upto snap len packet data bytes */
        ch_log_debug1("Copying %li bytes from buffer %li at index=%li into buffer at offset=%li\n", pcap_record_bytes, min_idx, rd_buffs[min_idx].pkt_idx, wr_buff.offset);

        buff_err = pcap_buff_write(wr_buff, &wr_pkt_hdr, rd_buffs[min_idx].pkt, packet_copy_bytes, &wr_pkt_ftr);

        if(buff_err != BUFF_ENONE){
            ch_log_fatal("Failed to write packet data: %s\n", buff_strerror(buff_err));
        }

        packets_total++;
        count++;
        pcap_buff_next_packet(&rd_buffs[min_idx]);
        if(options.max_count && count >= options.max_count){
            break;
        }
    }

    ch_log_info("Finished writing %li packets total (Runts=%li, Errors=%li, Padding=%li). Closing\n", packets_total, dropped_runts, dropped_errors, dropped_padding);

    ch_hash_map_it hmit = hash_map_first(hmap);
    buff_error_t err;
    while(hmit.value){
        wr_buff = (pcap_buff_t*)hmit.value;
        err = pcap_buff_flush_to_disk(wr_buff);
        if(err != BUFF_ENONE){
            ch_log_fatal("Failed to flush buffer to disk: %s\n", buff_strerror(buff_err));
        }
        hash_map_next(hmap, &hmit);
    }
  
    return 0;
}
