/*
 * Copyright (c) 2017, 2018 All rights reserved.
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

#include <chaste/types/types.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/utils/util.h>

#include "data_structs/pcap_buff.h"
#include "data_structs/expcap.h"


USE_CH_LOGGER_DEFAULT;
USE_CH_OPTIONS;


struct {
    char*  input;
    char* csv;
    bool verbose;
    char* format;
    ch_word offset;
    ch_word max;
    ch_word num;
    bool write_header;
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
                   bool nl, bool content, int total_out, int64_t timedelta_ns)
{
    char fmtd[4096] = {0};

    if(content && options.num != 0){
        int n = 0;

        if(options.num < 0){
            options.num = INT64_MAX;
        }

        for(int64_t i = 0; i < MIN((int64_t)pkt_hdr->caplen,options.num); i++){
            n += snprintf(fmtd + n, 4096 -n, "%02x", *((uint8_t*)packet +i));
        }
    }
    dprintf(fd, "%04i,%lins,%i.%09i,%i,%i,",
            total_out, timedelta_ns,
            pkt_hdr->ts.ns.ts_sec, pkt_hdr->ts.ns.ts_nsec,
            pkt_hdr->caplen, pkt_hdr->len);


    if(expcap && packet){
        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)((char*)(packet)
                + pkt_hdr->caplen - sizeof(expcap_pktftr_t));

        dprintf(fd, "%i,%i,%li.%012li,",
                pkt_ftr->dev_id,
                pkt_ftr->port_id,
                (int64_t)pkt_ftr->ts_secs, (int64_t)pkt_ftr->ts_psecs);
    }
    
    dprintf(fd, "%s",fmtd);

    if(nl){
        dprintf(fd, "\n");
    }
}

int main(int argc, char** argv)
{
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
    ch_opt_addii(CH_OPTION_OPTIONAL,'m',"max","Max packets to output (<0 means all)", &options.max, -1);
    ch_opt_addii(CH_OPTION_OPTIONAL,'n',"num-chars","Number of characters to output (<=0 means all)", &options.num, 64);
    ch_opt_addbi(CH_OPTION_FLAG,'w',"write-header","Write out a header row", &options.write_header, false);

    ch_opt_parse(argc,argv);

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
    pcap_buff_t buff = {0};
    if(pcap_buff_from_file(&buff, options.input) != BUFF_ENONE){
        ch_log_fatal("Failed to create a new pcap buff from file: %s\n", options.input);
    }

    int csv_fd = -1;
    if(options.csv){
        csv_fd = open(options.csv,O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(csv_fd < 0){
            ch_log_fatal("Could not open in missed file %s (%s)\n", options.csv, strerror(errno));
        }

        if(options.write_header){
            dprintf(csv_fd,"packet_num,delta_ns,seconds.nanos,capture_length,packet_length");
            if(expcap){
                dprintf(csv_fd,",device_id,port_id,seconds.picos");
            }

            dprintf(csv_fd,"\n");
        }
    }

    int64_t timenowns = 0;
    int64_t timeprevns = 0;
    int64_t total_out = 0;
    pkt_info_t info;
    for(int pkt_num = 0; !stop && pkt_num < options.offset + options.max; pkt_num++,
            timeprevns = timenowns ){
        if(pkt_num && pkt_num % (1000 * 1000) == 0){
            ch_log_info("Loaded %li,000,000 packets\n", pkt_num/1000/1000);
        }

        info = pcap_buff_next_packet(&buff);
        if(info == PKT_EOF){
            break;
        }

        pcap_pkthdr_t hdr = *buff.hdr;
        timenowns = hdr.ts.ns.ts_sec * 1000ULL * 1000 * 1000 + hdr.ts.ns.ts_nsec;

        if(timeprevns == 0){
            timeprevns = timenowns;
        }

        const int64_t time_delta = timenowns - timeprevns;

        if(pkt_num < options.offset){
            continue;
        }

        if(options.verbose){
            dprint_packet(STDOUT_FILENO, expcap, &hdr, buff.pkt, true, true, total_out, time_delta);
        }

        if(csv_fd > 0){
            dprint_packet(csv_fd, expcap, &hdr, buff.pkt, true, true, total_out, time_delta);
        }

        total_out++;
    }


    if(csv_fd){
        close(csv_fd);
    }

    ch_log_info("Output %li packets\n", total_out);
    ch_log_info("PCAP parser, finished\n");
    return 0;

}
