/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     28 Jul 2017
 *  Author:      Matthew P. Grosvenor
 *  Description: A tool for parsing pcaps and expcaps and outputting in ASCII
 *               for debugging and inspection.
 *
 */


#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>

#include "data_structs/pthread_vec.h"
#include "data_structs/eiostream_vec.h"
#include "data_structs/pcap-structures.h"

#include "data_structs/expcap.h"


USE_CH_LOGGER_DEFAULT;
USE_CH_OPTIONS;


struct {
    char*  input;
    char* csv;
    bool verbose;
    char* format;
    ch_word offset;
    ch_word timens;
    ch_word max;
    ch_word num;
} options;


static volatile bool stop = false;
void signal_handler(int signum)
{
    ch_log_warn("Caught signal %li, shutting down\n", signum);
    if(stop == 1){
        ch_log_fatal("Hard exit\n");
    }
    stop = 1;
}




void dprint_packet(int fd, bool expcap, pcap_pkthdr_t* pkt_hdr, char* packet,
                   int total_out, int64_t timedelta_ns)
{
    char fmtd[4096] = {0};
    char out[4096] = {0};
    int off = 0;

    if(options.num != 0){
        int n = 0;

        if(options.num < 0){
            options.num = INT64_MAX;
        }

        for(int64_t i = 0; i < MIN((int64_t)pkt_hdr->caplen,options.num); i++){
            n += sprintf(fmtd + n, "%02x", *((uint8_t*)packet +i));
        }
    }
    off += sprintf(out + off, "%04i,%lins,%i.%09i,%i,%i,",
            total_out, timedelta_ns,
            pkt_hdr->ts.ns.ts_sec, pkt_hdr->ts.ns.ts_nsec,
            pkt_hdr->caplen, pkt_hdr->len);


    if(expcap && packet){
        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)((char*)(packet)
                + pkt_hdr->caplen - sizeof(expcap_pktftr_t));

        off += sprintf(out + off, "%i,%i,%li.%012li,",
                pkt_ftr->dev_id,
                pkt_ftr->port_id,
                (int64_t)pkt_ftr->ts_secs, (int64_t)pkt_ftr->ts_psecs);
    }

    off += sprintf(out + off, "%s",fmtd);

    dprintf(fd, "%s\n", out);

}



int read_packet(char* data, int64_t* offset, int64_t snaplen, pcap_pkthdr_t** pkt_hdro, char** pbufo )
{

    pcap_pkthdr_t* pkt_hdr = (pcap_pkthdr_t*)(data + *offset);
    *offset += sizeof(pcap_pkthdr_t);

    bool error = false;
    snaplen = 4096;
    if(pkt_hdr->caplen > snaplen){
        ch_log_error("Error, packet length out of range [0,%li] %u at offset=%li\n", snaplen, pkt_hdr->len, offset);
        error = true;
    }

    if(options.verbose && (pkt_hdr->len != 0 && pkt_hdr->len + sizeof(expcap_pktftr_t) < pkt_hdr->caplen)){
        ch_log_warn("Warning: packet len %li < capture len %li\n", pkt_hdr->len, pkt_hdr->caplen);
    }


    if(error){
        char* pbuf = data + *offset;
        hexdump(pkt_hdr, sizeof(pkt_hdr));
        hexdump(pbuf, 4096);
        exit(0);
    }

    char* pbuf = data + *offset;
    *offset += pkt_hdr->caplen;

    *pbufo = pbuf;
    *pkt_hdro = pkt_hdr;

    return 0;

}



int main(int argc, char** argv)
{
    ch_word result = -1;
    int64_t offset = 0;

    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGTERM, signal_handler);

    ch_opt_addsu(CH_OPTION_REQUIRED,'i',"input","PCAP file to read", &options.input);
    ch_opt_addsi(CH_OPTION_OPTIONAL,'c',"csv","CSV output file to write to ", &options.csv, NULL);
    ch_opt_addbi(CH_OPTION_FLAG,'v',"verbose","Printout verbose output", &options.verbose, false);
    ch_opt_addsu(CH_OPTION_REQUIRED,'f',"format","Input format [pcap | expcap]", &options.format);
    ch_opt_addii(CH_OPTION_OPTIONAL,'o',"offset","Offset into the file to start ", &options.offset, 0);
    ch_opt_addii(CH_OPTION_OPTIONAL,'t',"time","Time into the file to start ", &options.timens, 0);
    ch_opt_addii(CH_OPTION_OPTIONAL,'m',"max","Max packets to output (<0 means all)", &options.max, -1);
    ch_opt_addii(CH_OPTION_OPTIONAL,'n',"num-chars","Number of characters to output (<=0 means all)", &options.num, 64);

    ch_opt_parse(argc,argv);

    ch_log_settings.log_level = CH_LOG_LVL_INFO;

    if(!options.verbose && !options.csv){
        ch_log_fatal("Must choose an output type. Use either --verbose or --csv\n");
    }

    bool expcap = false;
    if(strncmp(options.format, "pcap", strlen("pcap")) == 0){
        expcap = false;
    }
    else if(strncmp(options.format, "expcap", strlen("expcap")) == 0){
        expcap = true;
    }
    else{
        ch_log_fatal("Unknown format type =\"%s\". Must be \"pcap\" or \"expcap\"\n", options.format);
    }

    if(options.max < 0){
        options.max = INT64_MAX;
    }

    ch_log_info("Starting PCAP parser...\n");

    int fd = open(options.input,O_RDONLY);
    if(fd < 0){
        ch_log_fatal("Could not open PCAP %s (%s)\n", options.input, strerror(errno));
    }

    struct stat st = {0};
    if(stat(options.input, &st))
    {
        ch_log_fatal("Could not stat file %s: \"%s\"\n", options.input, strerror(errno));
    }
    const ssize_t filesize = st.st_size;


    char* data = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE , fd, 0);
    if(data == MAP_FAILED)
    {
        ch_log_fatal("Could not map input file %s: \"%s\"\n", options.input, strerror(errno));
    }

    pcap_file_header_t* fhdr = (pcap_file_header_t*)(data + offset);
    offset += sizeof(pcap_file_header_t);
    char* magic_str = fhdr->magic == NSEC_TCPDUMP_MAGIC ? "Nansec TCP Dump" :  "UNKNOWN";
    magic_str = fhdr->magic == TCPDUMP_MAGIC ? "TCP Dump" :  magic_str;
    if(options.verbose){
        printf("Magic    0x%08x (%i) (%s)\n", fhdr->magic, fhdr->magic, magic_str);
        printf("Ver Maj  0x%04x     (%i)\n", fhdr->version_major, fhdr->version_major);
        printf("Ver Min  0x%04x     (%i)\n", fhdr->version_minor, fhdr->version_minor);
        printf("Thiszone 0x%08x (%i)\n", fhdr->thiszone, fhdr->thiszone);
        printf("SigFigs  0x%08x (%i)\n", fhdr->sigfigs, fhdr->sigfigs);
        printf("Snap Len 0x%08x (%i)\n", fhdr->snaplen, fhdr->snaplen);
        printf("Link typ 0x%08x (%i)\n", fhdr->linktype, fhdr->linktype);
    }

    pcap_pkthdr_t* pkt_hdr = NULL;
    char* pbuf = NULL;
    if(read_packet(data, &offset, fhdr->snaplen, &pkt_hdr, &pbuf)){
        exit(0);
    }

    int csv_fd = -1;
    if(options.csv){
        csv_fd = open(options.csv,O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(csv_fd < 0){
            ch_log_fatal("Could not open in missed file %s (%s)\n", options.csv, strerror(errno));
        }
    }

    int64_t timenowns = 0;
    int64_t timeprevns = 0;
    int64_t total_out = 0;
    for(int pkt_num = 0; (!stop) && (pkt_num < options.offset + options.max) && offset < filesize; pkt_num++,
    timeprevns = timenowns ){
        if(pkt_num && pkt_num % (1000 * 1000) == 0){
            ch_log_info("Loaded %li,000,000 packets\n", pkt_num/1000/1000);
        }


        if(read_packet(data, &offset, fhdr->snaplen, &pkt_hdr, &pbuf)){
            break;
        }
        timenowns = pkt_hdr->ts.ns.ts_sec * 1000ULL * 1000 * 1000 + pkt_hdr->ts.ns.ts_nsec;

        if(timeprevns == 0){
            timeprevns = timenowns;
        }

        const int64_t time_delta = timenowns - timeprevns;


        if(pkt_num < options.offset || timenowns < options.timens){
            continue;
        }

        if(options.verbose){
            dprint_packet(STDOUT_FILENO, expcap, pkt_hdr, pbuf, total_out, time_delta );
        }

        if(csv_fd > 0){
            dprint_packet(csv_fd, expcap, pkt_hdr, pbuf, total_out, time_delta);
        }

        total_out++;
    }

    munmap(data, filesize);
    close(fd);
    if(csv_fd) close(csv_fd);

    ch_log_info("Output %li packets\n", total_out);
    ch_log_info("PCAP parser, finished\n");
    return result;

}
