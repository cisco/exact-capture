/*
 * Copyright (c) 2017, 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of a memory mapped "blocking ring" or circular queue to join
 *  listener and writer threads using the exactio abstract IO interface.
 */

#ifndef EXACTIO_BRING_H_
#define EXACTIO_BRING_H_

#include "exactio_stream.h"

typedef struct  {
    uint64_t slot_size;
    uint64_t slot_count;
    uint64_t dontexpand;
    char* name;
} bring_args_t;


//See http://man7.org/linux/man-pages/man5/proc.5.html /proc/[pid]/stat
typedef struct bring_hw_stats
{
   int pid; //The process ID.
   char comm[255]; //The filename of the executable, in parentheses.
   char state; //State R=Running S=Sleeping D=Disk sleep X=Dead
   int ppid; //Parent PID
   int pgrp;//Process Group ID
   int session; //The session ID of process
   int tty_nr; //The controlling terminal number
   int tpgid;
   unsigned int flags; //See the PF_* defines in include/linux/sched.h.
   int64_t minflt; //minor faults - no loading a memory page from disk.
   int64_t cminflt; //minor faults - child processes
   int64_t majflt; //major faults - pages loaded from disk
   int64_t cmajflt; //major faults - child processes
   int64_t utime; //user mode time in clock ticks
   int64_t stime; //kernel mode time in clock ticks
} bstats_t;



NEW_IOSTREAM_DECLARE(bring,bring_args_t);

#endif /* EXACTIO_BRING_H_ */
