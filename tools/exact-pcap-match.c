/*
 * Copyright (c) 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     28 March 2018
 *  Author:      Matthew P. Grosvenor
 *  Description: A tool for exacting peforming packet matching on a pair of
 *               pcap or expcap files. The output is a text file containing the
 *               computed latency in nanoseconds and potentially picoseconds.
 *
 */


#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/data_structs/hash_map/hash_map.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/utils/util.h>

#include "../src/data_structs/pcap-structures.h"
#include "../src/data_structs/expcap.h"
#include "data_structs/pcap_buff.h"

USE_CH_LOGGER_DEFAULT;
USE_CH_OPTIONS;

struct
{
    char* input;
    char* ref;
    char* csv;
    char* inp_missed;
    char* ref_missed;
    char* inp_miss_pcap;
    char* ref_miss_pcap;
    char* format;
    ch_word num;
    ch_word offset_ref;
    ch_word offset_inp;
    ch_word max_ref;
    ch_word max_inp;
    bool verbose;
    ch_word max_dupes;
} options;

typedef struct
{
    pcap_pkthdr_t pkt_hdr;
    expcap_pktftr_t pkt_ftr;
    bool matched_once;
} value_t;

static volatile bool stop = false;
void signal_handler (int signum)
{
    ch_log_warn("Caught signal %li, shutting down\n", signum);
    if (stop == 1)
    {
        ch_log_fatal("Hard exit\n");
    }
    stop = 1;
}

void dprint_packet (int fd, bool expcap, pcap_pkthdr_t* pkt_hdr,
                    expcap_pktftr_t* pkt_ftr, char* packet, bool nl,
                    bool content)
{
    char fmtd[4096] = { 0 };

    if (expcap)
    {
        dprintf (fd, "%i,%li.%012li,", pkt_ftr->port_id,
                 (int64_t) pkt_ftr->ts_secs, (int64_t) pkt_ftr->ts_psecs);
    }

    if (content && options.num != 0)
    {
        int n = 0;

        if (options.num < 0)
        {
            options.num = INT64_MAX;
        }
        n += snprintf (fmtd + n, 4096 - n, ",");
        for (int64_t i = 0; i < MIN((int64_t )pkt_hdr->len, options.num); i++)
        {
            n += snprintf (fmtd + n, 4096 - n, "%02x",
                           *((uint8_t*) packet + i));
        }
    }
    dprintf (fd, "%i.%09i,%i%s", pkt_hdr->ts.ns.ts_sec, pkt_hdr->ts.ns.ts_nsec,
             pkt_hdr->caplen, fmtd);

    if (nl)
    {
        dprintf (fd, "\n");
    }
}

int snprint_packet (char* out, int max, bool expcap, pcap_pkthdr_t* pkt_hdr,
                    expcap_pktftr_t* pkt_ftr, char* packet, bool nl,
                    bool content)
{

    int n = 0;
    if (expcap)
    {
        n += snprintf (out + n, max - n, "%i,%li.%012li,", pkt_ftr->port_id,
                       (int64_t) pkt_ftr->ts_secs, (int64_t) pkt_ftr->ts_psecs);
    }

    n += snprintf (out + n, max - n, "%i.%09i,%i", pkt_hdr->ts.ns.ts_sec,
                   pkt_hdr->ts.ns.ts_nsec, pkt_hdr->caplen);

    if (content && options.num != 0)
    {
        n += snprintf (out + n, max - n, ",");
        if (options.num < 0)
        {
            options.num = INT64_MAX;
        }

        for (int64_t i = 0; i < MIN((int64_t )pkt_hdr->len, options.num); i++)
        {
            n += snprintf (out + n, max - n, "%02x", *((uint8_t*) packet + i));
        }
    }

    if (nl)
    {
        n += snprintf (out + n, max - n, "\n");
    }

    return n;
}

int main (int argc, char** argv)
{
    signal (SIGHUP, signal_handler);
    signal (SIGINT, signal_handler);
    signal (SIGPIPE, signal_handler);
    signal (SIGALRM, signal_handler);
    signal (SIGTERM, signal_handler);

    ch_opt_addsu (CH_OPTION_REQUIRED, 'r', "reference", "ref PCAP file to read", &options.ref);
    ch_opt_addsu (CH_OPTION_REQUIRED, 'i', "input", "cmp PCAP file to read", &options.input);
    ch_opt_addsu (CH_OPTION_REQUIRED, 'c', "csv", "Output CSV", &options.csv);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'R', "ref-miss", "Reference misses", &options.ref_missed, NULL);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'I', "inp-miss", "Input misses", &options.inp_missed, NULL);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'e', "ref-miss-pcap", "Reference misses capture", &options.ref_miss_pcap, NULL);
    ch_opt_addsi (CH_OPTION_OPTIONAL, 'p', "inp-miss-pcap", "Input misses capture", &options.inp_miss_pcap, NULL);
    ch_opt_addsu (CH_OPTION_REQUIRED, 'f', "format", "Input format [pcap | expcap]", &options.format);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'O', "offset-ref", "Offset into the reference file to start ", &options.offset_ref, 0);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'o', "offset-inp", "Offset into the input file to start ", &options.offset_inp, 0);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'M', "max-ref", "Max items in the reference file to match  (<0 means all)", &options.max_ref, -1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'm', "max-inp", "Max items in input file to match (<0 means all)", &options.max_inp, -1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'n', "num-chars", "Number of bytes from matched packets to output (<0 means all)", &options.num, 64);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'd', "max-dupes", "Maximum number of duplicate matches allowed for a single packet (default is 0).", &options.max_dupes, 0);
    ch_opt_addbi (CH_OPTION_FLAG, 'v', "verbose", "Printout verbose output", &options.verbose, false);
    ch_opt_parse (argc, argv);
    ch_log_info("Starting PCAP Matcher\n");

    ch_log_settings.log_level = CH_LOG_LVL_DEBUG1;

    int fd_out = open (options.csv, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_out < 0){
        ch_log_fatal("Could not open output csv %s (%s)\n", options.csv,
                     strerror(errno));
    }

    int fd_inp_miss = -1;
    if (options.inp_missed){
        fd_inp_miss = open (options.inp_missed, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd_inp_miss < 0){
            ch_log_fatal("Could not open input missed file %s (%s)\n",
                         options.csv, strerror(errno));
        }
    }

    int fd_ref_miss = -1;
    if (options.ref_missed){
        fd_ref_miss = open (options.ref_missed, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd_ref_miss < 0){
            ch_log_fatal("Could not open reference missed file %s (%s)\n",
                         options.csv, strerror(errno));
        }
    }

    bool expcap = false;
    if (strncmp (options.format, "pcap", strlen ("pcap")) == 0){
        expcap = false;
    }
    else if (strncmp (options.format, "expcap", strlen ("expcap")) == 0){
        expcap = true;
    }
    else{
        ch_log_fatal(
                "Unkown format type =\"%s\". Must be \"pcap\" or \"expcap\"\n",
                options.format);
    }

    if (options.max_ref < 0){
        options.max_ref = INT64_MAX;
    }

    if (options.max_inp < 0){
        options.max_inp = INT64_MAX;
    }

    ch_hash_map* hmap = ch_hash_map_new (128 * 1024 * 1024, sizeof(value_t),
                                         NULL);

    /* Load up the reference file into the hashmap*/
    pcap_buff_t ref_buff = {0};
    ch_log_info("Loading reference file %s...\n", options.ref);
    if(pcap_buff_from_file(&ref_buff, options.ref, expcap) != BUFF_ENONE){
        ch_log_fatal("Failed to create new pcap buff from file: %s\n", options.ref);
    }

    pcap_buff_t* ref_miss_buff;
    if(options.ref_miss_pcap){
	ref_miss_buff = malloc(sizeof(pcap_buff_t));
	if(!ref_miss_buff){
            ch_log_fatal("Could not allocate memory for reference miss buff_t.\n");
	}

        /* Create a new pcap buff for reference misses.
           It's created without options, since we want a copy of packets as they
           exist in the ref pcap. */
        buff_error_t err = pcap_buff_init(options.ref_miss_pcap, 0, 0, 0, 0, 0, ref_miss_buff);
        if(err != BUFF_ENONE){
            ch_log_fatal("Failed to create a new write buffer for ref miss pcap: %s\n", buff_strerror(err));
	}
    }

    int64_t pkt_num = 0;
    int64_t loaded = 0;
    for (pkt_num = 0; !stop && pkt_num < options.max_ref + options.offset_ref; pkt_num++){
        if (pkt_num && pkt_num % (1000 * 1000) == 0){
            ch_log_info("Loaded %li,000,000 packets\n", pkt_num / 1000 / 1000);
        }

        pkt_info_t pkt_info;
        pkt_info = pcap_buff_next_packet(&ref_buff);
        pcap_pkthdr_t* ref_hdr = ref_buff.hdr;
        switch(pkt_info){
        case PKT_EOF:
            goto ref_pcap_loaded;
        case PKT_OVER_SNAPLEN:
            ch_log_fatal("Packet with index %d does not comply with snaplen: %d (data len is %d)\n", pkt_num, ref_buff.snaplen, ref_buff.hdr->len);
            break;
        case PKT_SNAPPED:
            if(options.verbose){
                ch_log_warn("Packet has been snapped shorter (%d) than it's wire length (%d).\n", ref_hdr->caplen, ref_hdr->len);
            }
            break;
        case PKT_PADDING:
            ch_log_fatal("File %s still contains expcap padding. Use exact-pcap-extract to remove padding packets from this capture\n", options.ref);
            break;
        case PKT_OK: // Fall through
        case PKT_RUNT:
        case PKT_ERROR:
            break;
        }

        if (pkt_num < options.offset_ref){
            //Skip over packets in the reference file
            continue;
        }

        if (options.verbose){
            dprintf (STDOUT_FILENO, "ref,");
            dprint_packet (STDOUT_FILENO, expcap, ref_hdr, ref_buff.ftr, ref_buff.pkt, true, true);
        }

        value_t val;
        bzero (&val, sizeof(val));
        val.pkt_hdr = *ref_hdr;
        if (expcap){
            val.pkt_ftr = *ref_buff.ftr;
        }

        const int64_t caplen = expcap ? ref_hdr->caplen - sizeof(expcap_pktftr_t) : ref_hdr->caplen;

        /*Use the whole packet as the key, and the header as the value */
        hash_map_push (hmap, ref_buff.pkt, caplen, &val);

        loaded++;
    }

ref_pcap_loaded:

    ch_log_info("Loaded %li entries from reference file %s...\n", pkt_num,
                options.ref);

    ch_log_info("Loading input file %s...\n", options.input);
    pcap_buff_t inp_buff = {0};
    if(pcap_buff_from_file(&inp_buff, options.input, expcap) != BUFF_ENONE){
        ch_log_fatal("Failed to create new pcap buff from file: %s\n", options.input);
    }

    pcap_buff_t* inp_miss_buff;
    if(options.inp_miss_pcap){
        inp_miss_buff = malloc(sizeof(pcap_buff_t));
        if(!inp_miss_buff){
            ch_log_fatal("Could not allocate memory for input miss buff_t.\n");
        }

        /* Create a new pcap buff for reference misses.
           It's created without options, since we want a copy of packets as they
           exist in the ref pcap. */
        buff_error_t err = pcap_buff_init(options.inp_miss_pcap, 0, 0, 0, 0, 0, inp_miss_buff);
        if(err != BUFF_ENONE){
            ch_log_fatal("Failed to create a new write buffer for ref miss pcap: %s\n", buff_strerror(err));
        }
    }

    int64_t total_matched = 0;
    int64_t total_lost = 0;
    for (pkt_num = 0; !stop && pkt_num < options.max_inp + options.offset_ref;
            pkt_num++){
        if (pkt_num && pkt_num % (1000 * 1000) == 0){
            ch_log_info("Processed %li,000,000 packets\n", pkt_num / 1000 / 1000);
        }

        pkt_info_t pkt_info;
        pkt_info = pcap_buff_next_packet(&inp_buff);
        pcap_pkthdr_t *inp_hdr = inp_buff.hdr;

        switch(pkt_info){
        case PKT_EOF:
            goto find_input_misses;
        case PKT_OVER_SNAPLEN:
            ch_log_fatal("Packet with index %d does not comply with snaplen: %d (data len is %d)\n", pkt_num, inp_buff.snaplen, inp_buff.hdr->len);
            break;
        case PKT_SNAPPED:
            if (options.verbose){
                ch_log_warn("Packet has been snapped shorter (%d) than it's wire length (%d).\n", inp_hdr->len, inp_hdr->caplen);
            }
            break;
        case PKT_PADDING:
            ch_log_fatal("File %s still contains expcap padding. Use exact-pcap-extract to remove padding packets from this capture\n", options.input);
            break;
        case PKT_OK: // Fall through
        case PKT_RUNT:
        case PKT_ERROR:
            break;
        }

        if (pkt_num < options.offset_inp){
            continue;
        }

        if (options.verbose && pkt_num){
            dprintf (STDOUT_FILENO, "inp,");
            dprint_packet (STDOUT_FILENO, expcap, inp_hdr, inp_buff.ftr, inp_buff.pkt, true, true);
        }

        /* Look for this packet in the hash map */
        const int64_t caplen = expcap ? inp_hdr->caplen - sizeof(expcap_pktftr_t) : inp_hdr->caplen;
        ch_hash_map_it hmit = hash_map_get_first (hmap, inp_buff.pkt, caplen);
        if(hmit.key)
        {
            ch_word num_matches = 0;
            value_t* val = (value_t*) hmit.value;
            while(val->matched_once && num_matches < options.max_dupes)
            {
                hmit = hash_map_get_next(hmit);
                val = (value_t*) hmit.value;
                num_matches++;
            }
        }

        value_t* val = (value_t*) hmit.value;
        if (!hmit.key || val->matched_once)
        {
            total_lost++;
            if (fd_inp_miss > 0){
                dprint_packet (fd_inp_miss, expcap, inp_hdr, inp_buff.ftr, inp_buff.pkt, true, true);
            }
        if (options.inp_miss_pcap){
                pcap_buff_write(inp_miss_buff, inp_hdr, inp_buff.pkt, inp_hdr->caplen, NULL);
            }
            continue;
        }

        total_matched++;
        char* ref_pkt = (char*) hmit.key;
        pcap_pkthdr_t* ref_hdr = &val->pkt_hdr;
        expcap_pktftr_t* ref_ftr = &val->pkt_ftr;

        val->matched_once = true;

        int64_t lat_ns = INT64_MAX;
        int64_t lat_ps = INT64_MAX;
        int64_t matching_keys = 0;

#define OSTRMAX 4096
        char matches[OSTRMAX] = { 0 };
        int n = 0;
        n += snprint_packet (matches + n, OSTRMAX - n, expcap, inp_hdr, inp_buff.ftr, inp_buff.pkt, false, true);
        n += snprintf (matches + n, OSTRMAX - n, ",-->,");
        for (; hmit.key && hmit.value && n < OSTRMAX;
                hmit = hash_map_get_next (hmit)){

            matching_keys++;

            int64_t secs_delta = (int64_t) ref_hdr->ts.ns.ts_sec
                    - (int64_t) inp_hdr->ts.ns.ts_sec;
            int64_t necs_delta = (int64_t) ref_hdr->ts.ns.ts_nsec
                    - (int64_t) inp_hdr->ts.ns.ts_nsec;
            int64_t delta_ns = secs_delta * (1000 * 1000 * 1000ULL)
                    + necs_delta;

            int64_t delta_ps = 0;

            if (expcap){
                int64_t secs_delta = (int64_t) ref_ftr->ts_secs
                        - (int64_t) inp_buff.ftr->ts_secs;
                int64_t psecs_delta = (int64_t) ref_ftr->ts_psecs
                        - (int64_t) inp_buff.ftr->ts_psecs;
                delta_ps = secs_delta * (1000 * 1000 * 1000 * 1000ULL)
                        + psecs_delta;
            }

            const uint64_t new_min_lat_ns = MIN(llabs (lat_ns),
                                                llabs (delta_ns));
            if ((uint64_t) llabs (lat_ns) != new_min_lat_ns){
                lat_ns = delta_ns;
                lat_ps = delta_ps;
            }

            n += snprint_packet (matches + n, OSTRMAX - n, expcap, ref_hdr, ref_ftr, ref_pkt, false, false);
            n += snprintf (matches + n, OSTRMAX - n, ",");
        }

        if (expcap){
            dprintf (fd_out, "%li,%li,%li,%s\n", lat_ns, lat_ps, matching_keys,
                     matches);
        }
        else{
            dprintf (fd_out, "%li,%li,%s\n", lat_ns, matching_keys, matches);
        }

    }

find_input_misses:

    ch_log_info("Finding all elements missing in input\n");
    ch_hash_map_it hmit = hash_map_first (hmap);
    int64_t missing_input = 0;
    while (hmit.key){
        value_t* val = (value_t*) hmit.value;
        if (!val->matched_once){
            missing_input++;
            if (fd_ref_miss > 0){
                dprint_packet (fd_ref_miss, expcap, &val->pkt_hdr, &val->pkt_ftr, hmit.key, true, true);
            }

            if(options.ref_miss_pcap){
                pcap_buff_write(ref_miss_buff, &val->pkt_hdr, hmit.key, val->pkt_hdr.caplen, NULL);
	    }
        }

        hash_map_next (hmap, &hmit);
    }

    ch_log_info("%-12li packets loaded from input file.\n", loaded);
    ch_log_info("%-12li packets from input file found in reference file.\n", total_matched);
    ch_log_info("%-12li packets from input file never found in reference file\n", total_lost);
    ch_log_info("%-12li packets in reference were never matched with input\n\n", missing_input);

    pcap_buff_close(&ref_buff);
    pcap_buff_close(&inp_buff);

    if(fd_inp_miss > 0){
        close (fd_inp_miss);
    }
    if(fd_ref_miss > 0){
        close (fd_ref_miss);
    }
    if(options.inp_miss_pcap){
        pcap_buff_close(inp_miss_buff);
    }
    if(options.ref_miss_pcap){
        pcap_buff_close(ref_miss_buff);
    }

    ch_log_info("PCAP matcher, finished\n");
    return 0;
}
