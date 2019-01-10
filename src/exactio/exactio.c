/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details. 
 * 
 *  Created:     21 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  A "factory" function for creating and destroying exactio streams.
 */



#include "exactio.h"
#include "exactio_file.h"
#include "exactio_dummy.h"
#include "exactio_exanic.h"
#include "exactio_bring.h"

int eio_new(eio_args_t* args, eio_stream_t** result)
{

    switch(args->type){
        case EIO_FILE: return NEW_IOSTREAM(file,result,&args->args.file);
        case EIO_DUMMY: return NEW_IOSTREAM(dummy,result,&args->args.dummy);
        case EIO_EXA:  return NEW_IOSTREAM(exa,result,&args->args.exa);
        case EIO_BRING:return NEW_IOSTREAM(bring,result,&args->args.bring);
    }

    return -1;
}

void eio_des(eio_stream_t* this)
{
    this->vtable.destroy(this);
}


