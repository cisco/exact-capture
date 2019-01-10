/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     7 July 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Implementaton of a libchaste vector containing pthread structures.
 */
#include <chaste/data_structs/vector/vector_typed_define_template.h>
#include "pthread_vec.h"

define_ch_vector(pthread,pthread_t)

define_ch_vector_cmp(pthread,pthread_t)
