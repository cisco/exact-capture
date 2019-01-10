/*
 * Copyright (c) 2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     9 January 2019
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Put all the statistics bulk maths operations in one place
 */


#include "exactio/exactio_exanic.h"
#include "exactio/exactio_bring.h"
#include "exactio/exactio_file.h"

#include "exact-capture-listener.h"
#include "exact-capture-stats-math.h"


bring_stats_hw_t bring_stats_hw_sub(bring_stats_hw_t* lhs, bring_stats_hw_t* rhs)
{
    bring_stats_hw_t result = {0};
    result.minflt = lhs->minflt - rhs->minflt;
    result.majflt = lhs->majflt - rhs->majflt;
    result.utime  = lhs->utime  - rhs->utime;
    result.stime  = lhs->stime  - rhs->stime;
    return result;
}


bring_stats_hw_t bring_stats_hw_add(bring_stats_hw_t* lhs, bring_stats_hw_t* rhs)
{
    bring_stats_hw_t result = {0};
    result.minflt = lhs->minflt + rhs->minflt;
    result.majflt = lhs->majflt + rhs->majflt;
    result.utime  = lhs->utime  + rhs->utime;
    result.stime  = lhs->stime  + rhs->stime;
    return result;
}

bring_stats_sw_t bring_stats_sw_sub(bring_stats_sw_t* lhs, bring_stats_sw_t* rhs)
{
    bring_stats_sw_t result = {0};
    result.aq_bytes  = lhs->aq_bytes - rhs->aq_bytes;
    result.aq_hit    = lhs->aq_hit   - rhs->aq_hit;
    result.aq_miss   = lhs->aq_miss  - rhs->aq_miss;
    result.rl_bytes  = lhs->rl_bytes - rhs->rl_bytes;
    return result;
}


bring_stats_sw_t bring_stats_sw_add(bring_stats_sw_t* lhs, bring_stats_sw_t* rhs)
{
    bring_stats_sw_t result = {0};
    result.aq_bytes  = lhs->aq_bytes + rhs->aq_bytes;
    result.aq_hit    = lhs->aq_hit   + rhs->aq_hit;
    result.aq_miss   = lhs->aq_miss  + rhs->aq_miss;
    result.rl_bytes  = lhs->rl_bytes + rhs->rl_bytes;
    return result;
}



listen_stats_t lthread_stats_sub(listen_stats_t* lhs, listen_stats_t* rhs)
{
    listen_stats_t result = {0};
    result.spins1_rx   = lhs->spins1_rx       - rhs->spins1_rx;
    result.spinsP_rx   = lhs->spinsP_rx       - rhs->spinsP_rx;
    result.packets_rx  = lhs->packets_rx      - rhs->packets_rx;
    result.bytes_rx    = lhs->bytes_rx        - rhs->bytes_rx;
    result.dropped     = lhs->dropped         - rhs->dropped;
    result.errors      = lhs->errors          - rhs->errors;
    result.swofl       = lhs->swofl           - rhs->swofl;
    result.hwofl       = lhs->hwofl           - rhs->hwofl;
    return result;
}


listen_stats_t lthread_stats_add(listen_stats_t* lhs, listen_stats_t* rhs)
{
    listen_stats_t result = {0};
    result.spins1_rx   = lhs->spins1_rx       + rhs->spins1_rx;
    result.spinsP_rx   = lhs->spinsP_rx       + rhs->spinsP_rx;
    result.packets_rx  = lhs->packets_rx      + rhs->packets_rx;
    result.bytes_rx    = lhs->bytes_rx        + rhs->bytes_rx;
    result.dropped     = lhs->dropped         + rhs->dropped;
    result.swofl       = lhs->swofl           + rhs->swofl;
    result.hwofl       = lhs->hwofl           + rhs->hwofl;

    return result;
}


nic_stats_hw_t nic_stats_hw_sub(const nic_stats_hw_t* lhs, const nic_stats_hw_t* rhs)
{
    nic_stats_hw_t result = {0};
    result.rx_count          = lhs->rx_count         - rhs->rx_count;
    result.rx_dropped_count  = lhs->rx_dropped_count - rhs->rx_dropped_count;
    result.rx_error_count    = lhs->rx_error_count   - rhs->rx_error_count;
    result.rx_ignored_count  = lhs->rx_ignored_count - rhs->rx_ignored_count;

    return result;
}

nic_stats_hw_t nic_stats_hw_add(const nic_stats_hw_t* lhs, const nic_stats_hw_t* rhs)
{
    nic_stats_hw_t result = {0};
    result.rx_count          = lhs->rx_count         + rhs->rx_count;
    result.rx_dropped_count  = lhs->rx_dropped_count + rhs->rx_dropped_count;
    result.rx_error_count    = lhs->rx_error_count   + rhs->rx_error_count;
    result.rx_ignored_count  = lhs->rx_ignored_count + rhs->rx_ignored_count;
    return result;
}


file_stats_sw_rdwr_t file_stats_sw_rdwr_sub(file_stats_sw_rdwr_t* lhs, file_stats_sw_rdwr_t* rhs)
{
    file_stats_sw_rdwr_t result = {0};
    result.bytes = lhs->bytes - rhs->bytes;
    result.count = lhs->count - rhs->count;
    return result;
}


file_stats_sw_rdwr_t file_stats_sw_rdwr_add(file_stats_sw_rdwr_t* lhs, file_stats_sw_rdwr_t* rhs)
{
    file_stats_sw_rdwr_t result = {0};
    result.bytes = lhs->bytes + rhs->bytes;
    result.count = lhs->count + rhs->count;
    return result;
}



