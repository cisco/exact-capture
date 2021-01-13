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

#include "data_structs/pthread_vec.h"
#include "data_structs/eiostream_vec.h"
#include "data_structs/pcap-structures.h"

#include "data_structs/expcap.h"

USE_CH_LOGGER_DEFAULT;
USE_CH_OPTIONS;

struct
{
    char* input;
    char* ref;
    char* csv;
    char* inp_missed;
    char* ref_missed;
    char* format;
    ch_word num;
    ch_word offset_ref;
    ch_word offset_inp;
    ch_word max_ref;
    ch_word max_inp;
    bool verbose;
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

int read_expect (int fd, void* buff, ssize_t len, int64_t* offset, bool debug)
{
    ssize_t total_bytes = 0;

    do
    {
        if (debug)
        {
            ch_log_debug1("Trying to read %liB on fd=%li\n", len, fd);
        };
        ssize_t bytes = read (fd, (char*) buff + total_bytes,
                              len - total_bytes);
        if (bytes == 0)
        {
            ch_log_error("Reached end of file\n");
            return 1;
        }
        total_bytes += bytes;

    }
    while (total_bytes < len);

    *offset += total_bytes;

    return 0;
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
    ch_word result = -1;
    int64_t offset = 0;

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
    ch_opt_addsu (CH_OPTION_REQUIRED, 'f', "format", "Input format [pcap | expcap]", &options.format);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'O', "offset-ref", "Offset into the reference file to start ", &options.offset_ref, 0);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'o', "offset-inp", "Offset into the input file to start ", &options.offset_inp, 0);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'M', "max-ref", "Max items in the reference file to match  (<0 means all)", &options.max_ref, -1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'm', "max-inp", "Max items in input file to match (<0 means all)", &options.max_inp, -1);
    ch_opt_addii (CH_OPTION_OPTIONAL, 'n', "num-chars", "Number of bytes from matched packets to output (<0 means all)", &options.num, 64);
    ch_opt_addbi (CH_OPTION_FLAG, 'v', "verbose", "Printout verbose output", &options.verbose, false);
    ch_opt_parse (argc, argv);
    ch_log_info("Starting PCAP Matcher\n");

    ch_log_settings.log_level = CH_LOG_LVL_DEBUG1;

    int fd_ref = open (options.ref, O_RDONLY);
    if (fd_ref < 0)
    {
        ch_log_fatal("Could not open reference PCAP %s (%s)\n", options.ref,
                     strerror(errno));
    }

    int fd_inp = open (options.input, O_RDONLY);
    if (fd_inp < 0)
    {
        ch_log_fatal("Could not open input PCAP %s (%s)\n", options.input,
                     strerror(errno));
    }

    int fd_out = open (options.csv, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_out < 0)
    {
        ch_log_fatal("Could not open output csv %s (%s)\n", options.csv,
                     strerror(errno));
    }

    int fd_inp_miss = -1;
    if (options.inp_missed)
    {
        fd_inp_miss = open (options.inp_missed, O_WRONLY | O_CREAT | O_TRUNC,
                            0666);
        if (fd_inp_miss < 0)
        {
            ch_log_fatal("Could not open input missed file %s (%s)\n",
                         options.csv, strerror(errno));
        }
    }

    int fd_ref_miss = -1;
    if (options.ref_missed)
    {
        fd_ref_miss = open (options.ref_missed, O_WRONLY | O_CREAT | O_TRUNC,
                            0666);
        if (fd_ref_miss < 0)
        {
            ch_log_fatal("Could not open reference missed file %s (%s)\n",
                         options.csv, strerror(errno));
        }
    }

    bool expcap = false;
    if (strncmp (options.format, "pcap", strlen ("pcap")) == 0)
    {
        expcap = false;
    }
    else if (strncmp (options.format, "expcap", strlen ("expcap")) == 0)
    {
        expcap = true;
    }
    else
    {
        ch_log_fatal(
                "Unkown format type =\"%s\". Must be \"pcap\" or \"expcap\"\n",
                options.format);
    }

    if (options.max_ref < 0)
    {
        options.max_ref = INT64_MAX;
    }

    if (options.max_inp < 0)
    {
        options.max_inp = INT64_MAX;
    }

    pcap_file_header_t fhdr_ref;
    if (read_expect (fd_ref, &fhdr_ref, sizeof(pcap_file_header_t), &offset,
                     false))
    {
        ch_log_fatal(
                "Could not read enough bytes from %s at offset %li, (%li required)\n",
                options.input, offset, sizeof(pcap_file_header_t));
    }

    char* magic_str =
            fhdr_ref.magic == NSEC_TCPDUMP_MAGIC ?
                    "Nansec TCP Dump" : "UNKNOWN";
    magic_str = fhdr_ref.magic == TCPDUMP_MAGIC ? "TCP Dump" : magic_str;
    if (options.verbose)
    {
        printf ("Magic    0x%08x (%i) (%s)\n", fhdr_ref.magic, fhdr_ref.magic, magic_str);
        printf ("Ver Maj  0x%04x (%i)\n", fhdr_ref.version_major, fhdr_ref.version_major);
        printf ("Ver Min  0x%04x (%i)\n", fhdr_ref.version_minor, fhdr_ref.version_minor);
        printf ("Thiszone 0x%08x (%i)\n", fhdr_ref.thiszone, fhdr_ref.thiszone);
        printf ("SigFigs  0x%08x (%i)\n", fhdr_ref.sigfigs, fhdr_ref.sigfigs);
        printf ("Snap Len 0x%08x (%i)\n", fhdr_ref.snaplen, fhdr_ref.snaplen);
        printf ("Link typ 0x%08x (%i)\n", fhdr_ref.linktype, fhdr_ref.linktype);
    }

    ch_hash_map* hmap = ch_hash_map_new (128 * 1024 * 1024, sizeof(value_t),
                                         NULL);

    ch_log_info("Loading reference file %s...\n", options.ref);

    /* Load up the reference file into the hashmap*/
    int64_t pkt_num = 0;
    int64_t loaded = 0;
    for (pkt_num = 0; !stop && pkt_num < options.max_ref + options.offset_ref;
            pkt_num++)
    {
        if (pkt_num && pkt_num % (1000 * 1000) == 0)
        {
            ch_log_info("Loaded %li,000,000 packets\n", pkt_num / 1000 / 1000);
        }

        pcap_pkthdr_t pkt_hdr;
        if (read_expect (fd_ref, &pkt_hdr, sizeof(pkt_hdr), &offset, false))
        {
            ch_log_error(
                    "Could not read enough bytes from %s at offset %li, (%li required)\n",
                    options.input, offset, sizeof(pkt_hdr));
            break;
        }

        if (pkt_hdr.caplen > fhdr_ref.snaplen || pkt_hdr.caplen < 64)
        {
            ch_log_error(
                    "Error, packet length (%li) out of range [64,%li] %u offset=%li\n",
                    pkt_hdr.caplen, fhdr_ref.snaplen, offset);
        }

        if (options.verbose && pkt_num >= options.offset_ref
                && (pkt_hdr.len + sizeof(expcap_pktftr_t) < pkt_hdr.caplen))
        {
            ch_log_warn("Warning: packet len %li < capture len %li\n",
                        pkt_hdr.len, pkt_hdr.caplen);
        }

        char pbuf[1024 * 64] = { 0 };
        if (read_expect (fd_ref, &pbuf, pkt_hdr.caplen, &offset, false))
        {
            break;
        }

        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*) (pbuf + pkt_hdr.caplen
                - sizeof(expcap_pktftr_t));

        if (pkt_num < options.offset_ref)
        {
            //Skip over packets in the reference file
            continue;
        }

        if (options.verbose)
        {
            dprintf (STDOUT_FILENO, "ref,");
            dprint_packet (STDOUT_FILENO, expcap, &pkt_hdr, pkt_ftr, pbuf, true,
                           true);
        }

        value_t val;
        bzero (&val, sizeof(val));
        val.pkt_hdr = pkt_hdr;
        if (expcap)
        {
            val.pkt_ftr = *pkt_ftr;
        }

        const int64_t caplen =
                expcap ?
                        pkt_hdr.caplen - sizeof(expcap_pktftr_t) :
                        pkt_hdr.caplen;

        /*Use the whole packet as the key, and the header as the value */
        hash_map_push (hmap, pbuf, caplen, &val);

        loaded++;

    }
    ch_log_info("Loaded %li entries from reference file %s...\n", pkt_num,
                options.input);

    ch_log_info("Loading input file %s...\n", options.input);

    pcap_file_header_t fhdr_inp;
    if (read_expect (fd_inp, &fhdr_inp, sizeof(fhdr_inp), &offset, true))
    {
        ch_log_fatal(
                "Could not read enough bytes from %s at offset %li, (%li required)\n",
                options.input, offset, sizeof(pcap_file_header_t));
    }

    char* magic_str_inp =
            fhdr_inp.magic == NSEC_TCPDUMP_MAGIC ?
                    "Nansec TCP Dump" : "UNKNOWN";
    magic_str = fhdr_inp.magic == TCPDUMP_MAGIC ? "TCP Dump" : magic_str_inp;
    if (options.verbose)
    {
        printf ("Magic    0x%08x (%i) (%s)\n", fhdr_inp.magic, fhdr_inp.magic, magic_str);
        printf ("Ver Maj  0x%04x (%i)\n", fhdr_inp.version_major,fhdr_inp.version_major);
        printf ("Ver Min  0x%04x (%i)\n", fhdr_inp.version_minor, fhdr_inp.version_minor);
        printf ("Thiszone 0x%08x (%i)\n", fhdr_inp.thiszone, fhdr_inp.thiszone);
        printf ("SigFigs  0x%08x (%i)\n", fhdr_inp.sigfigs, fhdr_inp.sigfigs);
        printf ("Snap Len 0x%08x (%i)\n", fhdr_inp.snaplen, fhdr_inp.snaplen);
        printf ("Link typ 0x%08x (%i)\n", fhdr_inp.linktype, fhdr_inp.linktype);
    }

    offset = 0;
    int64_t total_matched = 0;
    int64_t total_lost = 0;
    for (pkt_num = 0; !stop && pkt_num < options.max_inp + options.offset_ref;
            pkt_num++)
    {

        if (pkt_num && pkt_num % (1000 * 1000) == 0)
        {
            ch_log_info("Processed %li,000,000 packets\n",
                        pkt_num / 1000 / 1000);
        }

        pcap_pkthdr_t pkt_hdr;
        if (read_expect (fd_inp, &pkt_hdr, sizeof(pkt_hdr), &offset, true))
        {
            ch_log_error(
                    "Could not read enough bytes from %s at offset %li, (%li required)\n",
                    options.input, offset, sizeof(pkt_hdr));
            ch_log_error("Ending now\n");
            break;
        }

        if (pkt_hdr.caplen > fhdr_ref.snaplen || pkt_hdr.caplen < 64)
        {
            ch_log_error(
                    "Error, packet length (%li) out of range [64,%li] %u offset=%li\n",
                    pkt_hdr.caplen, fhdr_inp.snaplen, offset);
        }

        if (options.verbose && pkt_num >= options.offset_inp
                && (pkt_hdr.len + sizeof(expcap_pktftr_t) < pkt_hdr.caplen))
        {
            ch_log_warn("Warning: packet len %li < capture len %li\n",
                        pkt_hdr.len, pkt_hdr.caplen);
        }

        char pbuf[1024 * 64] = { 0 };
        if (read_expect (fd_inp, &pbuf, pkt_hdr.caplen, &offset, true))
        {
            break;
        }

        if (pkt_num < options.offset_inp)
        {
            continue;
        }

        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*) (pbuf + pkt_hdr.caplen
                - sizeof(expcap_pktftr_t));

        if (options.verbose && pkt_num)
        {
            dprintf (STDOUT_FILENO, "inp,");
            dprint_packet (STDOUT_FILENO, expcap, &pkt_hdr, pkt_ftr, pbuf, true,
                           true);
        }

        /* Look for this packet in the hash map */

        const int64_t caplen =
                expcap ?
                        pkt_hdr.caplen - sizeof(expcap_pktftr_t) :
                        pkt_hdr.caplen;
        ch_hash_map_it hmit = hash_map_get_first (hmap, pbuf, caplen);
        if (!hmit.key)
        {
            total_lost++;
            if (fd_inp_miss > 0)
                dprint_packet (fd_inp_miss, expcap, &pkt_hdr, pkt_ftr, pbuf,
                               true, true);
            continue;
        }

        total_matched++;
        value_t* val = (value_t*) hmit.value;
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
        n += snprint_packet (matches + n, OSTRMAX - n, expcap, &pkt_hdr,
                             pkt_ftr, pbuf, false, true);
        n += snprintf (matches + n, OSTRMAX - n, ",-->,");
        for (; hmit.key && hmit.value && n < OSTRMAX;
                hmit = hash_map_get_next (hmit))
        {

            matching_keys++;

            int64_t secs_delta = (int64_t) ref_hdr->ts.ns.ts_sec
                    - (int64_t) pkt_hdr.ts.ns.ts_sec;
            int64_t necs_delta = (int64_t) ref_hdr->ts.ns.ts_nsec
                    - (int64_t) pkt_hdr.ts.ns.ts_nsec;
            int64_t delta_ns = secs_delta * (1000 * 1000 * 1000ULL)
                    + necs_delta;

            int64_t delta_ps = 0;

            if (expcap)
            {
                int64_t secs_delta = (int64_t) ref_ftr->ts_secs
                        - (int64_t) pkt_ftr->ts_secs;
                int64_t psecs_delta = (int64_t) ref_ftr->ts_psecs
                        - (int64_t) pkt_ftr->ts_psecs;
                delta_ps = secs_delta * (1000 * 1000 * 1000 * 1000ULL)
                        + psecs_delta;
            }

            const uint64_t new_min_lat_ns = MIN(llabs (lat_ns),
                                                llabs (delta_ns));
            if ((uint64_t) llabs (lat_ns) != new_min_lat_ns)
            {
                lat_ns = delta_ns;
                lat_ps = delta_ps;
            }

            n += snprint_packet (matches + n, OSTRMAX - n, expcap, ref_hdr,
                                 ref_ftr, ref_pkt, false, false);
            n += snprintf (matches + n, OSTRMAX - n, ",");

        }

        if (expcap)
        {
            dprintf (fd_out, "%li,%li,%li,%s\n", lat_ns, lat_ps, matching_keys,
                     matches);
        }
        else
        {
            dprintf (fd_out, "%li,%li,%s\n", lat_ns, matching_keys, matches);
        }

    }

    ch_log_info("Finding all elements missing in input\n");
    ch_hash_map_it hmit = hash_map_first (hmap);
    int64_t missing_input = 0;
    while (hmit.key)
    {
        value_t* val = (value_t*) hmit.value;
        if (!val->matched_once)
        {
            missing_input++;
            if (fd_ref_miss > 0)
                dprint_packet (fd_ref_miss, expcap, &val->pkt_hdr,
                               &val->pkt_ftr, hmit.key, true, true);
        }

        hash_map_next (hmap, &hmit);
    }

    ch_log_info("%-12li packets loaded from input file.\n", loaded);
    ch_log_info("%-12li packets from input file found in reference file.\n", total_matched);
    ch_log_info("%-12li packets from input file never found in reference file\n", total_lost);
    ch_log_info("%-12li packets in reference were never matched with input\n\n", missing_input);

    close (fd_ref);
    close (fd_out);
    if (fd_inp_miss > 0) close (fd_inp_miss);
    if (fd_ref_miss > 0) close (fd_ref_miss);

    ch_log_info("PCAP matcher, finished\n");
    return result;

}
