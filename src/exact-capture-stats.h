/*
 * exact-capture-stats.h
 *
 *  Created on: 9 Jan. 2019
 *      Author: mattg
 */

#ifndef SRC_EXACT_CAPTURE_STATS_H_
#define SRC_EXACT_CAPTURE_STATS_H_

#include <chaste/types/types.h>
#include "exact-capture-listener.h"
#include "exact-capture-writer.h"

typedef struct exact_capture_stats_sample {

    int64_t time_ns;  //Time at which sampling began
    int64_t delay_ns; //Time it took to collect sample

    //Really this should be removed and replaced with NIC sw stats
    listen_stats_t lthread[MAX_LTHREADS];

    //nic_stats_sw_t nic_sw[MAX_LTHREADS]; -- placeholder
    nic_stats_hw_t nic_hw[MAX_LTHREADS];

    bring_stats_hw_t bring_hw_wr[MAX_LWCONNS];
    bring_stats_sw_t bring_sw_wr[MAX_LWCONNS];

    bring_stats_hw_t bring_hw_rd[MAX_LWCONNS];
    bring_stats_sw_t bring_sw_rd[MAX_LWCONNS];

    file_stats_sw_rdwr_t file_sw_wr[MAX_WTHREADS];
    //file_stats_hw_t file_hw_wr[MAX_WTHREADS]; -- placeholder

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

void estats_output(exact_stats_t* stats,
                   exact_stats_sample_t* now,
                   exact_stats_sample_t* prev);

void estats_output_summary(exact_stats_t* stats,
                          exact_stats_sample_t* now,
                          exact_stats_sample_t* prev);


void estats_destroy(exact_stats_t* stats);

#endif /* SRC_EXACT_CAPTURE_STATS_H_ */
