/*
 * Copyright (c) 2017,2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     7 July 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Declaration of a libchaste vector containing pthread structures.
 */

#ifndef SRC_DATA_STRUCTS_PTHREAD_VEC_H_
#define SRC_DATA_STRUCTS_PTHREAD_VEC_H_

#include <pthread.h>
#include <chaste/data_structs/vector/vector_typed_declare_template.h>

declare_ch_vector(pthread,pthread_t)


#endif /* SRC_DATA_STRUCTS_PTHREAD_VEC_H_ */
