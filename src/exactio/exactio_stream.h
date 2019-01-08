/*
 * Copyright (c) 2017, 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     17 Jul 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Definition of the exactio abstract straeming I/O interface. This is loosely
 *  based on code from CAMIO (https://github.com/mgrosvenor/camio2). It provides
 *  a fast way to interface to a number of underlying transports using a common
 *  API. A C++ style interface is implemented directly in C, similar to Linux
 *  kernel abstract interfaces.
 */


#ifndef SRC_EXACTIO_EXACTIO_STREAM_H_
#define SRC_EXACTIO_EXACTIO_STREAM_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <chaste/utils/util.h>
#include "../data_structs/timespecps.h"

//This compile out checks that aren't strictly necessary
#ifdef NOIFASSERT
    #define ifassert(x) if(0 && (x))
#else
    #define ifassert(x) ifunlikely((ssize_t)(x))
#endif



typedef struct exactio_stream_s eio_stream_t;

typedef enum {
    EIO_ENONE =  0,
    EIO_EUNSPEC,    //Unspecified error
    EIO_ETRYAGAIN, //No data available, try again
    EIO_ECLOSED,    //The underlying data source has closed
    EIO_EEOF,       //End of file has been reached
    EIO_ENOTIMPL,   //This function is not implemented
    EIO_ETOOBIG,    //Returned buffer len is too long
    EIO_ERELEASE,   //Release the buffer first before trying acquire again
    EIO_EACQUIRE,   //Acquire the buffer first before trying release again
    EIO_ENOMEM,     //No memory to back this

    //These error codes only apply to fragment based transports.
    EIO_EFRAG_MOR, //More fragments to come
    EIO_EFRAG_EOF, //End of fragment sequence
    EIO_EFRAG_ABT, //Fragment aborted by sender
    EIO_EFRAG_CPT, //Fragment corrupt (e.g. csum failure)

    EIO_EHWOVFL,   //Hardware overflow (e.g. insufficient PCIe bandwidth)
    EIO_ESWOVFL,   //Software overflow (e.g. software not keeping up)

    EIO_EINVALID,   //Something was done wrong

} eio_error_t;

/**
 * Nice simple generic read/write I/O abstraction
 */
typedef struct exactio_stream_interface_s{

    void (*destroy)(eio_stream_t* this);

    //Read operations
    //----------------
    eio_error_t (*read_acquire)(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts );
    eio_error_t (*read_release)(eio_stream_t* this,int64_t* ts);
    eio_error_t (*read_sw_stats)(eio_stream_t* this,void* stats);
    eio_error_t (*read_hw_stats)(eio_stream_t* this,void* stats);


    //Write operations
    //----------------
    //for write_acquire len can be supplied as a hint. If len is 0, the MTU will be used
    //for write_release len is zero, the frame the data is not committed
    eio_error_t (*write_acquire)(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts );
    eio_error_t (*write_release)(eio_stream_t* this, int64_t len, int64_t* ts );
    eio_error_t (*write_sw_stats)(eio_stream_t* this,void* stats);
    eio_error_t (*write_hw_stats)(eio_stream_t* this,void* stats);

    //Auxilary Operations
    //----------------
    //Convert internal timestamp representation to a picosecond times specification
    eio_error_t (*time_to_tsps)(eio_stream_t* this, void* time, timespecps_t* ts );
    eio_error_t (*get_id)(eio_stream_t* this, int64_t* id_major, int64_t* id_minor );

} exactio_stream_interface_t;

/**
 * All streams must implement this. Streams will use the macros provided to overload
 * this structure with and include a private data structure.
 */
struct exactio_stream_s {

    /**
     * vtable that holds the function pointers, usually this would be a pointer to a constant, but saving 6x8bytes seems a
     * little silly when it will cost a pointer dereference on the critical
     * path.
     */
    exactio_stream_interface_t vtable;

    int fd;

    /*
     * A unique name that defines this stream, useful for debugging;
     */
    char* name;

};


#define IOSTREAM_GET_PRIVATE(THIS) ( (void*)(THIS + 1))

#define NEW_IOSTREAM(name, out, args)\
        new_##name##_stream(out, args)

#define NEW_IOSTREAM_DECLARE(NAME, ARGT)\
        int new_##NAME##_stream(eio_stream_t** out, ARGT* args)

#define NEW_IOSTREAM_DEFINE(NAME, ARGT, PRIVATE_TYPE) \
    static const exactio_stream_interface_t NAME##_stream_interface = {\
            .read_acquire   = NAME##_read_acquire,\
            .read_release   = NAME##_read_release,\
			.read_sw_stats  = NAME##_read_sw_stats,\
			.read_hw_stats  = NAME##_read_hw_stats,\
            .write_acquire  = NAME##_write_acquire,\
            .write_release  = NAME##_write_release,\
			.write_sw_stats = NAME##_write_sw_stats,\
			.write_hw_stats = NAME##_write_hw_stats,\
			.time_to_tsps   = NAME##_time_to_tsps,\
			.get_id   	    = NAME##_get_id,\
            .destroy        = NAME##_destroy,\
    };\
    \
    NEW_IOSTREAM_DECLARE(NAME, ARGT)\
    {\
        eio_stream_t* result = (eio_stream_t*)calloc(1,sizeof(eio_stream_t) + sizeof(PRIVATE_TYPE));\
        if(!result) return EIO_ENOMEM;\
        result->vtable = NAME##_stream_interface;\
        result->fd = -1;\
        *out = result;\
        int err = NAME##_construct(result, args);\
        if(err){ free(result); *out = NULL;}\
        return err;\
    }


#endif /* SRC_EXACTIO_EXACTIO_STREAM_H_ */
