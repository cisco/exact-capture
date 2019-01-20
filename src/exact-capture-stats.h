/*
 * exact-capture-stats.h
 *
 *  Created on: 9 Jan. 2019
 *      Author: mattg
 */

#ifndef SRC_EXACT_CAPTURE_STATS_H_
#define SRC_EXACT_CAPTURE_STATS_H_

#include <chaste/types/types.h>
#include "data_structs/exact_stat_hdr.h"
#include "exact-capture-listener.h"
#include "exact-capture-writer.h"

typedef struct exact_capture_stats_sample {

    int64_t time_ns;  //Time at which sampling began
    int64_t delay_ns; //Time it took to collect sample

    void* nic_sw[MAX_LTHREADS];
    void* nic_hw[MAX_LTHREADS];

    void* bring_hw_wr[MAX_LWCONNS];
    void* bring_sw_wr[MAX_LWCONNS];

    void* bring_hw_rd[MAX_LWCONNS];
    void* bring_sw_rd[MAX_LWCONNS];

    void* file_sw_wr[MAX_WTHREADS];
    void* file_hw_wr[MAX_WTHREADS];

    exact_stats_hdr_t* nic_sw_hdr[MAX_LTHREADS];
    exact_stats_hdr_t* nic_hw_hdr[MAX_LTHREADS];

    exact_stats_hdr_t* bring_hw_wr_hdr[MAX_LWCONNS];
    exact_stats_hdr_t* bring_sw_wr_hdr[MAX_LWCONNS];

    exact_stats_hdr_t* bring_hw_rd_hdr[MAX_LWCONNS];
    exact_stats_hdr_t* bring_sw_rd_hdr[MAX_LWCONNS];

    exact_stats_hdr_t* file_sw_wr_hdr[MAX_WTHREADS];
    exact_stats_hdr_t* file_hw_wr_hdr[MAX_WTHREADS];

}  exact_stats_sample_t;


typedef struct exact_capture_stats {

    lparams_t* lparams_list;
    ch_word lcount;

    wparams_t* wparams_list;
    ch_word wcount;

    bool verbose;
    ch_word more_verbose_lvl;

    int64_t time_now_ns;
    int64_t time_prev_ns;
    int64_t time_start_ns;
    int64_t time_finish_ns;

}  exact_stats_t;



exact_stats_t* estats_init(bool verbose, ch_word more_verbose_lvl,
                           lparams_t* lparams_list, ch_word lcount,
                           wparams_t* wparams_list, ch_word wcount);

void estats_take_sample(exact_stats_t* stats, exact_stats_sample_t* sample);

void estats_output(exact_stats_t* stats, exact_stats_sample_t* now);


void estats_output_summary(exact_stats_t* stats,
                          exact_stats_sample_t* now,
                          exact_stats_sample_t* prev);


void estats_destroy(exact_stats_t* stats);

#endif /* SRC_EXACT_CAPTURE_STATS_H_ */
