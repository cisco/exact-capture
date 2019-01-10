/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of the file read/write interface using the exactio abstract I/O
 *  interface.
 */

#ifndef EXACTIO_FILE_H_
#define EXACTIO_FILE_H_

#include "exactio_stream.h"

typedef struct  {
    const char* filename;
    uint64_t read_buff_size;
    bool read_on_mod;

    uint64_t write_buff_size;
    bool write_directio;
    uint64_t write_max_file_size;

} file_args_t;


typedef struct file_stats_sw_rdwr_t
{
    int64_t count;
    int64_t bytes;
    char name[20];
} file_stats_sw_rdwr_t;



NEW_IOSTREAM_DECLARE(file, file_args_t);

#endif /* EXACTIO_FILE_H_ */
