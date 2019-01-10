/*
 * Copyright (c) 2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     9 January 2019
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Put all the statistics bulk maths operations in one place
 */

#ifndef SRC_EXACT_CAPTURE_STATS_MATH_H_
#define SRC_EXACT_CAPTURE_STATS_MATH_H_

bring_stats_hw_t bring_stats_hw_sub(bring_stats_hw_t* lhs, bring_stats_hw_t* rhs);
bring_stats_hw_t bring_stats_hw_add(bring_stats_hw_t* lhs, bring_stats_hw_t* rhs);
bring_stats_sw_t bring_stats_sw_sub(bring_stats_sw_t* lhs, bring_stats_sw_t* rhs);
bring_stats_sw_t bring_stats_sw_add(bring_stats_sw_t* lhs, bring_stats_sw_t* rhs);
listen_stats_t lthread_stats_sub(listen_stats_t* lhs, listen_stats_t* rhs);
listen_stats_t lthread_stats_add(listen_stats_t* lhs, listen_stats_t* rhs);
nic_stats_hw_t nic_stats_hw_sub(const nic_stats_hw_t* lhs, const nic_stats_hw_t* rhs);
nic_stats_hw_t nic_stats_hw_add(const nic_stats_hw_t* lhs, const nic_stats_hw_t* rhs);
file_stats_sw_rdwr_t file_stats_sw_rdwr_sub(file_stats_sw_rdwr_t* lhs, file_stats_sw_rdwr_t* rhs);
file_stats_sw_rdwr_t file_stats_sw_rdwr_add(file_stats_sw_rdwr_t* lhs, file_stats_sw_rdwr_t* rhs);

#endif /* SRC_EXACT_CAPTURE_STATS_MATH_H_ */
