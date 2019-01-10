/*
 * Copyright (c) 2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     9 January 2019
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  This file collects together statistics keeping and calculating functions
 *  for the rest of exact-capture
 */

#include "exact-capture-stats.h"

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

#include "exactio/exactio_exanic.h"
#include "exactio/exactio_bring.h"
#include "exactio/exactio_file.h"

#include "exact-capture-listener.h"
#include "exact-capture-writer.h"

#include "exact-capture-stats-math.h"

#include "exact-capture.h"
#include "utils.h"




//
//
//
//static void print_wstats(wstats_t wstats_delta,wparams_t wparams,
//                         bring_stats_hw_t* bstats_deltas, int64_t bstats_count,
//                         int tid, int64_t delta_ns )
//{
//
//    if(!wparams.disk_ostream->name)
//    {
//        //This writer has been cleaned up
//        return;
//    }
//
//    const double w_rate_mpps  = ((double) wstats_delta.packets ) / (delta_ns / 1000.0);
//
//    const double w_pcrate_gbs = ((double) wstats_delta.pcbytes * 8) / delta_ns;
//    const double w_plrate_gbs = ((double) wstats_delta.plbytes * 8) / delta_ns;
//    const double w_drate_gbs  = ((double) wstats_delta.dbytes  * 8) / delta_ns;
//
//
//
//    const int dst_str_len = strlen(wparams.disk_ostream->name);
//    char file_pretty[dst_str_len+1];
//    bzero(file_pretty, dst_str_len+1);
//    strncpy(file_pretty,wparams.disk_ostream->name, dst_str_len);
//
//    char* pretty = file_pretty;
//    if(dst_str_len > 17){
//        pretty = file_pretty + dst_str_len - 17;
//        file_pretty[0] = '.';
//        file_pretty[1] = '.';
//        file_pretty[2] = '.';
//    }
//
//
//    if(stats->more_verbose_lvl == 1 )
//    {
//        ch_log_info("Writer:%02i %-17s -- %.2fGbps %.2fMpps %.2fMB %li Pkts\n",
//                    tid,
//                    pretty,
//                    w_pcrate_gbs, w_rate_mpps,
//                    wstats_delta.pcbytes / 1024.0 / 1024.0,
//                    wstats_delta.packets);
//    }
//    else if(stats->more_verbose_lvl == 2)
//    {
//
//        const int MAX_CHARS = 1024;
//        char page_faults_str[MAX_CHARS];
//        int offset = 0;
//        offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "[");
//        for(int wid = 0; wid < bstats_count; wid++)
//        {
//            offset += snprintf(page_faults_str + offset,MAX_CHARS - offset, "%li.%li ", bstats_deltas[wid].majflt, bstats_deltas[wid].minflt );
//        }
//        offset--; //Remove trailing space.
//        offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "] ");
//
//
//        ch_log_info("Writer:%02i %-17s -- %.2fGbps %.2fMpps (%.2fGbps wire %.2fGbps disk) %.2fMB (%.2fMB %.2fMB) %li Pkts %.3fM Spins Faults:%s\n",
//                    tid,
//                    pretty,
//                    w_pcrate_gbs, w_rate_mpps, w_plrate_gbs, w_drate_gbs,
//                    wstats_delta.pcbytes / 1024.0 / 1024.0,
//                    wstats_delta.plbytes / 1024.0 / 1024.0,
//                    wstats_delta.dbytes / 1024.0 / 1024.0,
//                    wstats_delta.packets,
//                    wstats_delta.spins / 1000.0 / 1000.0,
//                    page_faults_str);
//
//    }
//}
//
//static void print_lstats_totals(listen_stats_t ldelta_total,
//                         nic_stats_hw_t pdelta_total,
//                         int64_t delta_ns)
//{
//    const double sw_rx_rate_gbs  = ((double) ldelta_total.bytes_rx * 8)
//            / delta_ns;
//    const double sw_rx_rate_mpps = ((double) ldelta_total.packets_rx ) /
//            (delta_ns / 1000.0);
//    const double hw_rx_rate_mpps = ((double) pdelta_total.rx_count ) /
//            (delta_ns / 1000.0);
//    int64_t maybe_lost     = pdelta_total.rx_count - ldelta_total.packets_rx;
//    /* Can't have lost -ve lost packets*/
//    maybe_lost = maybe_lost < 0 ? 0 : maybe_lost;
//
//    if(stats->more_verbose_lvl == 0)
//    {
//        ch_log_info("%-27s -- %.2fGbps %.2fMpps %.2fMB %li Pkts %lierrs %lidrp %liswofl\n",
//           "Total - All Listeners",
//           sw_rx_rate_gbs,
//           sw_rx_rate_mpps,
//
//           ldelta_total.bytes_rx / 1024.0 / 1024.0,
//           ldelta_total.packets_rx,
//           ldelta_total.errors, ldelta_total.dropped, ldelta_total.swofl);
//    }
//    if(stats->more_verbose_lvl == 2 )
//    {
//        ch_log_info("%-27s -- %.2fGbps %.2fMpps (HW:%.2fiMpps) %.2fMB %li Pkts (HW:%i Pkts) [lost?:%li] (%.3fM Spins1 %.3fM SpinsP ) %lierrs %lidrp %liswofl %lihwofl\n",
//           "Total - All Listeners",
//           sw_rx_rate_gbs,
//           sw_rx_rate_mpps,
//           hw_rx_rate_mpps,
//
//           ldelta_total.bytes_rx / 1024.0 / 1024.0,
//           ldelta_total.packets_rx,
//           pdelta_total.rx_count,
//
//           maybe_lost,
//           ldelta_total.spins1_rx / 1000.0 / 1000.0,
//           ldelta_total.spinsP_rx / 1000.0 / 1000.0,
//           ldelta_total.errors, ldelta_total.dropped, ldelta_total.swofl,
//           ldelta_total.hwofl);
//    }
//
//}
//
//
//static void print_wstats_totals(wstats_t wdelta_total, int64_t delta_ns )
//{
//    const double w_rate_mpps = ((double) wdelta_total.packets ) /
//            (delta_ns / 1000.0);
//
//    const double w_pcrate_gbs = ((double) wdelta_total.pcbytes * 8) / delta_ns;
//    const double w_plrate_gbs = ((double) wdelta_total.plbytes * 8) / delta_ns;
//    const double w_drate_gbs  = ((double) wdelta_total.dbytes  * 8) / delta_ns;
//
//    if(stats->more_verbose_lvl == 0 )
//    {
//        ch_log_info("%-27s -- %.2fGbps %.2fMpps %.2fMB %li Pkts\n",
//                "Total - All Writers",
//                w_pcrate_gbs, w_rate_mpps,
//                wdelta_total.pcbytes / 1024.0 / 1024.0,
//                wdelta_total.packets);
//    }
//    else if(stats->more_verbose_lvl == 2)
//    {
//        ch_log_info("%-27s -- %.2fGbps %.2fMpps (%.2fGbps wire %.2fMGbps disk) %.2fMB (%.2fMB %.2fMB) %li Pkts %.3fM Spins\n",
//                    "Total - All Writers",
//                    w_pcrate_gbs, w_rate_mpps,
//                    w_plrate_gbs, w_drate_gbs,
//                    wdelta_total.pcbytes / 1024.0 / 1024.0,
//                    wdelta_total.plbytes / 1024.0 / 1024.0,
//                    wdelta_total.dbytes / 1024.0 / 1024.0,
//                    wdelta_total.packets,
//                    wdelta_total.spins / 1000.0 / 1000.0);
//
//    }
//}
//
//
//
//
//static void print_stats_basic_totals(listen_stats_t ldelta_total, wstats_t wdelta_total,
//                              nic_stats_hw_t pdelta_total, int64_t delta_ns,
//                              int64_t hw_delta_ns)
//{
//    const double sw_rx_rate_mpps = ((double) ldelta_total.packets_rx ) /
//            (delta_ns / 1000.0);
//    const double sw_rx_rate_gbps = ((double) ldelta_total.bytes_rx * 8 )
//            / delta_ns;
//
//    const double hw_rx_rate_mpps = ((double) pdelta_total.rx_count ) /
//            (hw_delta_ns / 1000.0);
//
//    const double w_rate_mpps = ((double) wdelta_total.packets ) /
//            (delta_ns / 1000.0);
//    const double w_pcrate_gbs = ((double) wdelta_total.pcbytes * 8) / delta_ns;
//
//    int64_t maybe_lost_hwsw     = pdelta_total.rx_count - ldelta_total.packets_rx;
//    /* Can't have lost -ve lost packets*/
//    maybe_lost_hwsw = maybe_lost_hwsw < 0 ? 0 : maybe_lost_hwsw;
//
//    const double maybe_lost_hwsw_mpps = ((double) maybe_lost_hwsw) / delta_ns / 1000;
//
//    int64_t lost_rxwr_packets = ldelta_total.packets_rx - wdelta_total.packets;
//    /* Can't have lost -ve lost packets*/
//    lost_rxwr_packets = lost_rxwr_packets < 0 ? 0 : lost_rxwr_packets;
//    const double lost_rxwr_mpps = ((double) lost_rxwr_packets) / delta_ns / 1000;
//
//    int64_t lost_rxwr_bytes = ldelta_total.bytes_rx - wdelta_total.pcbytes;
//    /* Can't have lost -ve lost bytes*/
//    lost_rxwr_bytes = lost_rxwr_bytes < 0 ? 0 : lost_rxwr_bytes;
//    const double lost_rxwr_gbps = ((double) lost_rxwr_bytes * 8) / delta_ns;
//
//    const double dropped_rate_mpps = ((double) ldelta_total.dropped ) /
//            (delta_ns / 1000.0);
//    const double overflow_rate_ps = ((double) ldelta_total.swofl )
//            / (delta_ns / 1000.0 / 1000.0 / 1000.0);
//
//
//    const int col1_digits = max_digitsll(pdelta_total.rx_count,
//                                        ldelta_total.packets_rx,
//                                        ldelta_total.bytes_rx / 1024 / 1024,
//                                        wdelta_total.packets,
//                                        wdelta_total.pcbytes / 1024 / 1024,
//                                        maybe_lost_hwsw,
//                                        lost_rxwr_packets,
//                                        lost_rxwr_bytes / 1024 / 1024,
//                                        ldelta_total.dropped,
//                                        ldelta_total.swofl);
//
//
//    const int col2_digits = 3 + max_digitsf (hw_rx_rate_mpps, sw_rx_rate_mpps,
//                                         sw_rx_rate_gbps, w_rate_mpps,
//                                         w_pcrate_gbs, maybe_lost_hwsw_mpps,
//                                         lost_rxwr_mpps, lost_rxwr_gbps,
//                                         dropped_rate_mpps, overflow_rate_ps);
//
//    fprintf(stderr,"Exact Capture finished\n");
//    if(stats->more_verbose_lvl == 2)
//        fprintf(stderr,"%15s:%*u packets ( %*.3f MP/s )\n",
//                "HW Received",
//                col1_digits,
//                pdelta_total.rx_count,
//                col2_digits,
//                hw_rx_rate_mpps);
//    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
//                "SW Received",
//                col1_digits,
//                ldelta_total.packets_rx,
//                col2_digits,
//                sw_rx_rate_mpps);
//    fprintf(stderr,"%15s %*li MB      ( %*.3f Gb/s )\n",
//                "",
//                col1_digits,
//                ldelta_total.bytes_rx / 1024 / 1024,
//                col2_digits,
//                sw_rx_rate_gbps);
//    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
//                "SW Wrote",
//                col1_digits,
//                wdelta_total.packets,
//                col2_digits,
//                w_rate_mpps);
//    fprintf(stderr,"%15s %*li MB      ( %*.3f Gb/s )\n",
//                "",
//                col1_digits,
//                wdelta_total.pcbytes / 1024 / 1024,
//                col2_digits,
//                w_pcrate_gbs);
//    if(stats->more_verbose_lvl == 2)
//        fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
//                "Lost HW/SW (?)",
//                col1_digits,
//                maybe_lost_hwsw ,
//                col2_digits,
//                maybe_lost_hwsw_mpps);
//    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
//                "Lost RX/WR",
//                col1_digits,
//                lost_rxwr_packets ,
//                col2_digits,
//                lost_rxwr_mpps);
//    fprintf(stderr,"%15s %*li MB      ( %*.3f Gb/s )\n",
//                "",
//                col1_digits,
//                lost_rxwr_bytes / 1024 / 1024,
//                col2_digits,
//                lost_rxwr_gbps);
//    fprintf(stderr,"%15s:%*li packets ( %*.3f MP/s )\n",
//                "Dropped",
//                col1_digits,
//                ldelta_total.dropped ,
//                col2_digits,
//                dropped_rate_mpps);
//    fprintf(stderr,"%15s:%*li times   ( %*.3f /s   )\n",
//                "SW Overflows",
//                col1_digits,
//                ldelta_total.swofl ,
//                col2_digits,
//                overflow_rate_ps);
//
//
//    /* TODO - There must be a better way to do this... */
//    if(stats->log_file)
//    {
//        ch_log_info("Exact Capture finished\n");
//        if(stats->more_verbose_lvl == 2)
//            ch_log_info("%15s:%*u packets ( %*.3f MP/s )\n",
//                    "HW Received",
//                    col1_digits,
//                    pdelta_total.rx_count,
//                    col2_digits,
//                    hw_rx_rate_mpps);
//        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
//                    "SW Received",
//                    col1_digits,
//                    ldelta_total.packets_rx,
//                    col2_digits,
//                    sw_rx_rate_mpps);
//        ch_log_info("%15s %*li MB      ( %*.3f Gb/s )\n",
//                    "",
//                    col1_digits,
//                    ldelta_total.bytes_rx / 1024 / 1024,
//                    col2_digits,
//                    sw_rx_rate_gbps);
//        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
//                    "SW Wrote",
//                    col1_digits,
//                    wdelta_total.packets,
//                    col2_digits,
//                    w_rate_mpps);
//        ch_log_info("%15s %*li MB      ( %*.3f Gb/s )\n",
//                    "",
//                    col1_digits,
//                    wdelta_total.pcbytes / 1024 / 1024,
//                    col2_digits,
//                    w_pcrate_gbs);
//        if(stats->more_verbose_lvl == 2 )
//            ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
//                    "Lost HW/SW (?)",
//                    col1_digits,
//                    maybe_lost_hwsw ,
//                    col2_digits,
//                    maybe_lost_hwsw_mpps);
//        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
//                    "Lost RX/WR",
//                    col1_digits,
//                    lost_rxwr_packets ,
//                    col2_digits,
//                    lost_rxwr_mpps);
//        ch_log_info("%15s %*li MB      ( %*.3f Gb/s )\n",
//                    "",
//                    col1_digits,
//                    lost_rxwr_bytes / 1024 / 1024,
//                    col2_digits,
//                    lost_rxwr_gbps);
//        ch_log_info("%15s:%*li packets ( %*.3f MP/s )\n",
//                    "Dropped",
//                    col1_digits,
//                    ldelta_total.dropped ,
//                    col2_digits,
//                    dropped_rate_mpps);
//        ch_log_info("%15s:%*li times   ( %*.3f /s   )\n",
//                    "SW Overflows",
//                    col1_digits,
//                    ldelta_total.swofl ,
//                    col2_digits,
//                    overflow_rate_ps);
//
//    }
//
//
//}
//
//
//
//void estats_get_start(exact_stats_t* stats)
//{
//    const int64_t now_ns    = time_now_ns();
//    stats->time_start_ns    = now_ns;
//
//    for (int tid = 0; tid < stats->lcount; tid++)
//    {
//        eio_rd_hw_stats(stats->lparams_list[tid].nic_istream, &stats->pstats_start[tid]);
//        stats->pstats_prev[tid] = stats->pstats_start[tid];
//
//        const int64_t rings_count = stats->lparams_list[tid].rings_count;
//        for(int ring = 0; ring < rings_count; ring++){
//            eio_wr_hw_stats(stats->lparams_list[tid].rings[ring], &stats->bring_wr_start[tid * rings_count + ring]);
//            stats->bring_wr_prev[tid * rings_count + ring] = stats->bring_wr_start[tid * rings_count + ring];
//        }
//    }
//
//
//    for (int wid = 0; wid < stats->wcount; wid++)
//    {
//        const int64_t rings_count = stats->wparams_list[wid].rings_count;
//        for(int ring = 0; ring < rings_count; ring++){
//            eio_rd_hw_stats(stats->wparams_list[wid].rings[ring], &stats->bring_rd_start[wid * rings_count + ring]);
//            stats->bring_rd_prev[wid * rings_count + ring] = stats->bring_rd_start[wid * rings_count + ring];
//        }
//    }
//}
//
//void estats_get_run(exact_stats_t* stats)
//{
//    /* Collect data as close together as possible before starting processing */
//    for (int tid = 0; tid < stats->lcount; tid++)
//    {
//        eio_rd_hw_stats(stats->lparams_list[tid].nic_istream, &stats->pstats_now[tid]);
//        stats->listen_now[tid] = stats->listen_all[tid];
//
//        const int64_t rings_count = stats->lparams_list[tid].rings_count;
//        for(int ring = 0; ring < rings_count; ring++){
//             eio_wr_hw_stats(stats->lparams_list[tid].rings[ring],  &stats->bstats_wr_now[tid * rings_count + ring]);
//         }
//    }
//    for (int tid = 0; tid < stats->wcount; tid++)
//    {
//        stats->wstats_now[tid] = stats->wstats[tid];
//
//        const int64_t rings_count = stats->wparams_list[tid].rings_count;
//        for(int ring = 0; ring < rings_count; ring++){
//            eio_rd_hw_stats(stats->wparams_list[tid].rings[ring], &stats->bring_rd_now[tid * rings_count + ring]);
//            stats->bring_rd_prev[tid * rings_count + ring] =
//                    stats->bring_rd_now[tid * rings_count + ring];
//        }
//    }
//
//    stats->time_prev_ns = stats->time_now_ns;
//    stats->time_now_ns  = time_now_ns();
//
//}
//
//
//
//
//void estats_get_final(exact_stats_t* stats)
//{
//
//    for (int tid = 0; tid < listeners_count ; tid++)
//    {
//        eio_rd_hw_stats(lparams_list[tid].nic_istream,&pstats_stop[tid]);
//        const int64_t rings_count = lparams_list[tid].rings_count;
//        for(int ring = 0; ring < rings_count; ring++){
//            eio_wr_hw_stats(lparams_list[tid].rings[ring],
//                            &bstats_wr_stop[tid * rings_count + ring]);
//        }
//
//    }
//
//
//    now_ns = time_now_ns();
//    delta_ns = now_ns - start_ns;
//    const int64_t hw_delta_ns = hw_stop_ns - start_ns;
//
//
//    /* Start processing the listener thread stats */
//    ldelta_total = lempty;
//    pdelta_total = pempty;
//    bdelta_total = bempty;
//    for (int tid = 0; tid < lthreads->count; tid++)
//    {
//
//        listen_now[tid] = lstats_all[tid];
//        listen_stats_t lstats_delta = lthread_stats_sub(&listen_now[tid], &listen_start[tid]);
//        ldelta_total = listener_stats_add(&ldelta_total, &lstats_delta);
//
//        nic_stats_hw_t pstats_delta = nic_stats_hw_sub(&pstats_stop[tid], &pstats_start[tid]);
//        pdelta_total = nic_stats_hw_add(&pdelta_total, &pstats_delta);
//
//        bring_stats_hw_t bstats_deltas[MAX_WTHREADS] = {0};
//        bring_stats_hw_t bstats_totals[MAX_WTHREADS] = {0};
//        const ch_word  wthreads_count = wthreads->count;
//        for(int wid = 0; wid < wthreads_count; wid++)
//        {
//            const int bstats_idx = tid* wthreads_count + wid;
//            bstats_deltas[wid] = bring_stats_hw_sub(&bstats_wr_stop[bstats_idx],&bring_wr_start[bstats_idx]);
//            bstats_totals[wid] = bring_stats_hw_add(&bstats_totals[wid],&bstats_deltas[wid]);
//            bdelta_total       = bring_stats_hw_add(&bdelta_total, &bstats_deltas[wid]);
//        }
//
//
//        if(!stats->more_verbose_lvl)
//            continue;
//
//        print_lstats(lstats_delta, lparams_list[tid], pstats_delta, bstats_deltas, wthreads_count, tid,  delta_ns);
//
//    }
//
//    if(stats->verbose)
//        print_lstats_totals(ldelta_total,pdelta_total, delta_ns);
//
//
//    /* Process the writer thread stats */
//    wdelta_total = wempty;
//    for (int tid = 0; tid < wthreads->count; tid++)
//    {
//        wstats_t wstats_delta = wstats[tid];
//        wdelta_total = wstats_add(&wdelta_total, &wstats_delta);
//
//        if(!stats->more_verbose_lvl)
//            continue;
//
//
//        bring_stats_hw_t bstats_deltas[MAX_WTHREADS] = {0};
//        bring_stats_hw_t bstats_totals[MAX_WTHREADS] = {0};
//        const ch_word  wthreads_count = wthreads->count;
//        for(int wid = 0; wid < wthreads_count; wid++)
//        {
//            const int bstats_idx = tid* wthreads_count + wid;
//            bstats_deltas[wid] = bring_stats_hw_sub(&bring_rd_now[bstats_idx],&bring_rd_prev[bstats_idx]);
//            bstats_totals[wid] = bring_stats_hw_add(&bstats_totals[wid],&bstats_deltas[wid]);
//            bdelta_total       = bring_stats_hw_add(&bdelta_total, &bstats_deltas[wid]);
//            bring_rd_prev[bstats_idx] = bring_rd_now[bstats_idx];
//        }
//
//        print_wstats(wstats_delta, wparams_list[tid], bstats_deltas,
//                     wthreads_count, tid, delta_ns);
//
//    }
//
//
//    if(stats->verbose)
//        print_wstats_totals(wdelta_total, delta_ns);
//
//
//    print_stats_basic_totals(ldelta_total, wdelta_total, pdelta_total,delta_ns,
//                             hw_delta_ns);
//}
//
//
//void print_stats()
//{
//    /* Start processing the listener thread stats */
//    ldelta_total = lempty;
//    pdelta_total = pempty;
//    for (int tid = 0; tid < lthreads->count;
//            listen_prev[tid] = listen_now[tid],
//            pstats_prev[tid] = pstats_now[tid],
//            tid++)
//    {
//        listen_stats_t lstats_delta = lthread_stats_sub(
//                &listen_now[tid],
//                &listen_prev[tid]);
//
//        ldelta_total = listener_stats_add(&ldelta_total, &lstats_delta);
//
//        nic_stats_hw_t pstats_delta = nic_stats_hw_sub(
//                &pstats_now[tid],
//                &pstats_prev[tid]);
//
//        pdelta_total = nic_stats_hw_add(&pdelta_total, &pstats_delta );
//
//        bring_stats_hw_t bstats_deltas[MAX_WTHREADS] = {0};
//        bring_stats_hw_t bstats_totals[MAX_WTHREADS] = {0};
//        const ch_word  wthreads_count = wthreads->count;
//        for(int wid = 0; wid < wthreads_count; wid++)
//        {
//            const int bstats_idx = tid* wthreads_count + wid;
//            bstats_deltas[wid] = bring_stats_hw_sub(&bstats_wr_now[bstats_idx],&bring_wr_prev[bstats_idx]);
//            bstats_totals[wid] = bring_stats_hw_add(&bstats_totals[wid],&bstats_deltas[wid]);
//            bdelta_total       = bring_stats_hw_add(&bdelta_total, &bstats_deltas[wid]);
//            bring_wr_prev[bstats_idx] = bstats_wr_now[bstats_idx];
//        }
//
//
//        if(!stats->more_verbose_lvl)
//            continue;
//
//        print_lstats(lstats_delta, lparams_list[tid], pstats_delta,
//                     bstats_deltas, wthreads_count, tid, delta_ns);
//
//    }
//
//    if(stats->verbose)
//    {
//        print_lstats_totals(ldelta_total,pdelta_total, delta_ns);
//    }
//
//    /* Process the writer thread stats */
//    wdelta_total = wempty;
//    for (int tid = 0;
//            (stats->more_verbose_lvl || stats->verbose) && tid < wthreads->count;
//            wstats_prev[tid] = wstats_now[tid], tid++)
//    {
//        wstats_t wstats_delta = file_stats_sw_sub(&wstats_now[tid], &wstats_prev[tid]);
//        wdelta_total = wstats_add(&wdelta_total, &wstats_delta);
//
//        bring_stats_hw_t bstats_deltas[MAX_WTHREADS] = {0};
//        bring_stats_hw_t bstats_totals[MAX_WTHREADS] = {0};
//        const ch_word  wthreads_count = wthreads->count;
//        for(int wid = 0; wid < wthreads_count; wid++)
//        {
//            const int bstats_idx = tid* wthreads_count + wid;
//            bstats_deltas[wid] = bring_stats_hw_sub(&bring_rd_now[bstats_idx],&bring_rd_prev[bstats_idx]);
//            bstats_totals[wid] = bring_stats_hw_add(&bstats_totals[wid],&bstats_deltas[wid]);
//            bdelta_total       = bring_stats_hw_add(&bdelta_total, &bstats_deltas[wid]);
//            bring_rd_prev[bstats_idx] = bring_rd_now[bstats_idx];
//        }
//
//
//        if(!stats->more_verbose_lvl)
//            continue;
//
//        print_wstats(wstats_delta, wparams_list[tid], bstats_deltas,
//                     wthreads_count, tid, delta_ns);
//
//    }
//
//    if(stats->verbose)
//    {
//        print_wstats_totals(wdelta_total, delta_ns);
//    }
//
//    if(!stats->no_overflow_warn && (ldelta_total.swofl || ldelta_total.hwofl)){
//        ch_log_warn("Warning: Overflow(s) occurred (SW:%li, HW:%li). Many packets lost!\n",
//                ldelta_total.swofl, ldelta_total.hwofl);
//    }
//}
//
//
//
//static void print_lstats_totals(exact_stats_t stats, exact_stats_sample_t delta)
//{
//
//    const double sw_rx_rate_gbs  = ((double) ldelta_total.bytes_rx * 8)
//            / delta_ns;
//    const double sw_rx_rate_mpps = ((double) ldelta_total.packets_rx ) /
//            (delta_ns / 1000.0);
//    const double hw_rx_rate_mpps = ((double) pdelta_total.rx_count ) /
//            (delta_ns / 1000.0);
//    int64_t maybe_lost     = pdelta_total.rx_count - ldelta_total.packets_rx;
//    /* Can't have lost -ve lost packets*/
//    maybe_lost = maybe_lost < 0 ? 0 : maybe_lost;
//
//    if(stats->more_verbose_lvl == 0)
//    {
//        ch_log_info("%-27s -- %.2fGbps %.2fMpps %.2fMB %li Pkts %lierrs %lidrp %liswofl\n",
//           "Total - All Listeners",
//           sw_rx_rate_gbs,
//           sw_rx_rate_mpps,
//
//           ldelta_total.bytes_rx / 1024.0 / 1024.0,
//           ldelta_total.packets_rx,
//           ldelta_total.errors, ldelta_total.dropped, ldelta_total.swofl);
//    }
//    if(stats->more_verbose_lvl == 2 )
//    {
//        ch_log_info("%-27s -- %.2fGbps %.2fMpps (HW:%.2fiMpps) %.2fMB %li Pkts (HW:%i Pkts) [lost?:%li] (%.3fM Spins1 %.3fM SpinsP ) %lierrs %lidrp %liswofl %lihwofl\n",
//           "Total - All Listeners",
//           sw_rx_rate_gbs,
//           sw_rx_rate_mpps,
//           hw_rx_rate_mpps,
//
//           ldelta_total.bytes_rx / 1024.0 / 1024.0,
//           ldelta_total.packets_rx,
//           pdelta_total.rx_count,
//
//           maybe_lost,
//           ldelta_total.spins1_rx / 1000.0 / 1000.0,
//           ldelta_total.spinsP_rx / 1000.0 / 1000.0,
//           ldelta_total.errors, ldelta_total.dropped, ldelta_total.swofl,
//           ldelta_total.hwofl);
//    }
//
//}


static void format_bring_stats(exact_stats_t* stats,
                               bring_stats_hw_t* bring_hw,
                               bring_stats_sw_t* bring_sw,
                               int64_t delta_ns,
                               char* bring_hw_str,
                               char* bring_sw_str,
                               int out_str_len)
{

    int hw_str_off = 0;
    int sw_str_off = 0;

    bring_stats_hw_t bring_hw_totals = {0};
    bring_stats_sw_t bring_sw_totals = {0};

    hw_str_off += snprintf(bring_hw_str + hw_str_off, out_str_len - hw_str_off, "[");
    for(int w = 0; w < stats->wcount; w++)
    {
        const double bring_sw_aq_rate_gbps = ((double)bring_sw[w].aq_bytes * 8) / delta_ns;
        const double bring_sw_rl_rate_gbps = ((double)bring_sw[w].rl_bytes * 8) / delta_ns;

        hw_str_off += snprintf(bring_hw_str + hw_str_off,out_str_len - hw_str_off,
                               "%li.%li ",
                               bring_hw[w].majflt,
                               bring_hw[w].minflt );
        sw_str_off += snprintf(bring_sw_str + sw_str_off,out_str_len - sw_str_off,
                               "%li hits /%li miss Aq:%.2fGbps Rl:%.2fGbps,",
                               bring_sw[w].aq_hit,
                               bring_sw[w].aq_miss,
                               bring_sw_aq_rate_gbps,
                               bring_sw_rl_rate_gbps );

        bring_hw_totals = bring_stats_hw_add(&bring_hw_totals,&bring_hw[w]);
        bring_sw_totals = bring_stats_sw_add(&bring_sw_totals,&bring_sw[w]);

    }

    hw_str_off--; //Remove trailing space.
    hw_str_off += snprintf(bring_hw_str + hw_str_off, out_str_len - hw_str_off,
                           "] (%li.%liflts)",
                           bring_hw_totals.majflt,
                           bring_hw_totals.minflt);

    const double bring_sw_aq_total_rate_gbps = ((double)bring_sw_totals.aq_bytes * 8) / delta_ns;
    const double bring_sw_rl_total_rate_gbps = ((double)bring_sw_totals.rl_bytes * 8) / delta_ns;

    sw_str_off--; //Remove trailing comma
    sw_str_off += snprintf(bring_sw_str + hw_str_off, out_str_len - hw_str_off,
                           "] (%li hits / %li miss Aq:%.2fGbps Rl:%.2fGbps)",
                           bring_sw_totals.aq_hit,
                           bring_sw_totals.aq_miss,
                           bring_sw_aq_total_rate_gbps,
                           bring_sw_rl_total_rate_gbps );

}



static void estats_wprint(exact_stats_t* stats,
                          bring_stats_hw_t* bring_hw,
                          bring_stats_sw_t* bring_sw,
                          file_stats_sw_rdwr_t* file_sw,
                          int64_t delta_ns,
                          int64_t tid)
{

    const char* name = file_sw->name;

        const double w_rate_mops  = ((double) file_sw->count ) / (delta_ns / 1000.0);
        const double w_rate_gbs  = ((double) file_sw->bytes  * 8) / delta_ns;

        if(stats->more_verbose_lvl == 1 )
        {
            ch_log_info("Writer:%02i %-17s -- %.2fGbps %.2fMops\n",
                        tid,
                        name,
                        w_rate_gbs,
                        w_rate_mops);
        }

        else if(stats->more_verbose_lvl == 2)
        {

            const int MAX_CHARS = 1024;
            char bring_hw_str[MAX_CHARS];
            char bring_sw_str[MAX_CHARS];
            format_bring_stats(stats, bring_hw, bring_sw, delta_ns, bring_hw_str, bring_sw_str, MAX_CHARS);


            ch_log_info("Writer:%02i %-17s -- %.2fGbps %.2fMops RINGHW %s RINGSW %s\n",
                   tid,
                   name,
                   w_rate_gbs,
                   w_rate_mops,

                   bring_hw_str,
                   bring_sw_str
            );


//            const int MAX_CHARS = 1024;
//            char page_faults_str[MAX_CHARS];
//            int offset = 0;
//            offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "[");
//            for(int wid = 0; wid < bstats_count; wid++)
//            {
//                offset += snprintf(page_faults_str + offset,MAX_CHARS - offset, "%li.%li ", bstats_deltas[wid].majflt, bstats_deltas[wid].minflt );
//            }
//            offset--; //Remove trailing space.
//            offset += snprintf(page_faults_str + offset, MAX_CHARS - offset, "] ");
//
//
//            ch_log_info("Writer:%02i %-17s -- %.2fGbps %.2fMpps (%.2fGbps wire %.2fGbps disk) %.2fMB (%.2fMB %.2fMB) %li Pkts %.3fM Spins Faults:%s\n",
//                        tid,
//                        pretty,
//                        w_pcrate_gbs, w_rate_mpps, w_plrate_gbs, w_drate_gbs,
//                        wstats_delta.pcbytes / 1024.0 / 1024.0,
//                        wstats_delta.plbytes / 1024.0 / 1024.0,
//                        wstats_delta.dbytes / 1024.0 / 1024.0,
//                        wstats_delta.packets,
//                        wstats_delta.spins / 1000.0 / 1000.0,
//                        page_faults_str);

        }

}




static void estats_lprint(exact_stats_t* stats,
                          listen_stats_t* listen_sw,
                          nic_stats_hw_t* nic_hw,
                          bring_stats_sw_t* bring_sw,
                          bring_stats_hw_t* bring_hw,
                          int64_t delta_ns,
                          int64_t tid)

{


    const double nic_hw_rate_mpps = ((double) nic_hw->rx_count ) /
            (delta_ns / 1000.0);

    const double nic_sw_rate_gbs  = ((double) listen_sw->bytes_rx * 8) /
            delta_ns;
    const double nic_sw_rate_mpps = ((double) listen_sw->packets_rx ) /
            (delta_ns / 1000.0);


    int64_t maybe_lost     = nic_hw->rx_count - listen_sw->packets_rx;
    /* Can't have lost -ve lost packets*/
    maybe_lost = maybe_lost < 0 ? 0 : maybe_lost;

    if(stats->more_verbose_lvl == 1 )
    {
        ch_log_info("Listener:%02i %s -- %.2fGbps %.2fMpps %.2fMB %li Pkts %lierrs %lidrp %liswofl\n",
               tid,
               nic_hw->name,

               nic_sw_rate_gbs,
               nic_sw_rate_mpps,

               listen_sw->bytes_rx / 1024.0 / 1024.0,
               listen_sw->packets_rx ,

               listen_sw->errors, listen_sw->dropped, listen_sw->swofl);
    }
    else if(stats->more_verbose_lvl == 2)
    {
        const int MAX_CHARS = 1024;
        char bring_hw_str[MAX_CHARS];
        char bring_sw_str[MAX_CHARS];
        format_bring_stats(stats, bring_hw, bring_sw, delta_ns, bring_hw_str, bring_sw_str, MAX_CHARS);


        ch_log_info("Listener:%02i %-17s -- NICHW [%.2fiMpps %i Pkts] NICSW [%.2fMpps %li Pkts .2fGbps %.2fMB %.3fM Spins1 %.3fM SpinsP %lierrs %lidrp %liswofl %lihwofl] lost?:%li RINGHW %s RINGSW %s\n",
               tid,
               nic_hw->name,

               nic_hw_rate_mpps,
               nic_hw->rx_count,

               nic_sw_rate_mpps,
               listen_sw->packets_rx ,
               nic_sw_rate_gbs,
               listen_sw->bytes_rx / 1024.0 / 1024.0,
               listen_sw->spins1_rx / 1000.0 / 1000.0,
               listen_sw->spinsP_rx / 1000.0 / 1000.0,
               listen_sw->errors,
               listen_sw->dropped,
               listen_sw->swofl,
               listen_sw->hwofl,

               maybe_lost,

               bring_hw_str,
               bring_sw_str

        );

    }

}


exact_stats_sample_t estats_sample_delta(exact_stats_t* stats,
                                         exact_stats_sample_t* lhs,
                                         exact_stats_sample_t* rhs)
{
    exact_stats_sample_t res = {0};

    const ch_word lcount = stats->lcount;
    const ch_word wcount = stats->wcount;

    for(ch_word i = 0; i < lcount; i++)
    {
        ifassert(strcmp(lhs->nic_hw[i].name,rhs->nic_hw[i].name))
        {
            ch_log_warn("Finding delta between different files \"%s\" and \"%s\"\n",
                        lhs->nic_hw[i].name,rhs->nic_hw[i].name);
        }
        res.lthread[i] = lthread_stats_sub(&lhs->lthread[i], &rhs->lthread[i]);
        res.nic_hw[i]  = nic_stats_hw_sub(&lhs->nic_hw[i], &rhs->nic_hw[i]);
        strncpy(res.nic_hw[i].name,lhs->nic_hw[i].name,sizeof(res.nic_hw[i].name));
    }

    for(ch_word i = 0; i < lcount * wcount; i++)
    {
        res.bring_hw_rd[i] = bring_stats_hw_sub(&lhs->bring_hw_rd[i], &rhs->bring_hw_rd[i]);
        res.bring_sw_rd[i] = bring_stats_sw_sub(&lhs->bring_sw_rd[i], &rhs->bring_sw_rd[i]);

        res.bring_hw_wr[i] = bring_stats_hw_sub(&lhs->bring_hw_wr[i], &rhs->bring_hw_wr[i]);
        res.bring_sw_wr[i] = bring_stats_sw_sub(&lhs->bring_sw_wr[i], &rhs->bring_sw_wr[i]);
    }

    for(ch_word i = 0; i < wcount; i++)
    {
        ifassert(strcmp(lhs->file_sw_wr[i].name,rhs->file_sw_wr[i].name ))
        {
            ch_log_warn("Finding delta between different files \"%s\" and \"%s\"\n",
                        lhs->file_sw_wr[i].name, rhs->file_sw_wr[i].name );
        }
        res.file_sw_wr[i] = file_stats_sw_rdwr_sub(&lhs->file_sw_wr[i], &rhs->file_sw_wr[i]);
        strncpy(res.file_sw_wr[i].name,lhs->file_sw_wr[i].name,sizeof(res.file_sw_wr[i].name));
    }

    res.time_ns = lhs->time_ns - rhs->time_ns;

    return res;
}



void estats_output(exact_stats_t* stats, exact_stats_sample_t* now, exact_stats_sample_t* prev)
{
    exact_stats_sample_t delta = estats_sample_delta(stats, now, prev );
    for(int64_t l = 0; l < stats->lcount; l++)
    {
        listen_stats_t* listen_sw      = &delta.lthread[l];
        nic_stats_hw_t* nic_hw         = &delta.nic_hw[l];
        bring_stats_hw_t* bring_hw_wr = &delta.bring_hw_wr[l];
        bring_stats_sw_t* bring_sw_wr = &delta.bring_sw_wr[l];
        estats_lprint(stats, listen_sw, nic_hw, bring_sw_wr, bring_hw_wr, delta.time_ns, l);
    }

    for(int64_t w = 0; w < stats->lcount; w++)
    {
        if(!stats->wparams_list[w].disk_ostream->name)
        {
            //This writer has been cleaned up
            continue;
        }
        bring_stats_hw_t* bring_hw_rd = &delta.bring_hw_rd[w];
        bring_stats_sw_t* bring_sw_rd = &delta.bring_sw_rd[w];
        file_stats_sw_rdwr_t* file_sw_wr = &delta.file_sw_wr[w];
        estats_wprint(stats,bring_hw_rd, bring_sw_rd, file_sw_wr, delta.time_ns, w);
    }


}


void estats_take_sample(exact_stats_t* stats, exact_stats_sample_t* sample)
{
    const ch_word lcount = stats->lcount;
    const ch_word wcount = stats->wcount;

    sample->time_ns = time_now_ns();

    //Gather all listener statistics
    for(int l = 0; l < lcount; l++)
    {
        lparams_t* lparams = &stats->lparams_list[l];
        eio_stream_t* nic_istream  = lparams->nic_istream;

        sample->lthread[l] = lparams->stats;
        eio_rd_hw_stats(nic_istream, &sample->nic_hw[l]);

        for(int w = 0; w < wcount; w++)
        {
            //Listener thread writes to bring, so we need wr stats here
            eio_stream_t* ring_ostream = lparams->rings[l * wcount + w];
            eio_wr_hw_stats(ring_ostream, &sample->bring_hw_wr[l * wcount + w]);
            eio_wr_sw_stats(ring_ostream, &sample->bring_sw_wr[l * wcount + w]);
        }
    }

    //Gather all writer thread statistics
    for(int w = 0; w < wcount; w++)
    {
        wparams_t* wparams = &stats->wparams_list[w];
        eio_stream_t* disk_ostream  = wparams->disk_ostream;
        eio_wr_sw_stats(disk_ostream, &sample->file_sw_wr[w]);

        for(int l = 0; l < lcount; l++)
        {
            //Writer thread reads from bring, so we need rd stats here
            eio_stream_t* ring_istream = wparams->rings[w * lcount + l];
            eio_rd_hw_stats(ring_istream, &sample->bring_hw_rd[w * lcount + l]);
            eio_rd_sw_stats(ring_istream, &sample->bring_sw_rd[w * lcount + l]);
        }
    }

    sample->delay_ns = time_now_ns() - sample->time_ns;

}



exact_stats_t* estats_init(bool verbose, ch_word more_verbose_lvl,
                           lparams_t* lparams_list, ch_word lcount,
                           wparams_t* wparams_list, ch_word wcount)
{
    exact_stats_t* result = calloc(sizeof(exact_stats_t), 1);
    if(!result)
    {
        return result;
    }
    result->lparams_list = lparams_list;
    result->lcount = lcount;
    result->wparams_list = wparams_list;
    result->wcount = wcount;
    result->verbose = verbose;
    result->more_verbose_lvl = more_verbose_lvl;

    return result;
}


