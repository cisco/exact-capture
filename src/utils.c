/*
 * Copyright (c) 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     6 Apr. 2018
 *  Author:      Matthew P. Grosvenor
 *  Description: Application wide useful utility functions
 */



#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <exanic/port.h>
#include <exanic/config.h>

#include "data_structs/expcap.h"

#include "utils.h"




int64_t time_now_ns()
{
    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec * 1000ULL * 1000 * 1000 + now.tv_nsec;
}


void init_dummy_data(char* dummy_data, int len)
{
    const char* dummy_text = "EXABLAZEEXACTCAPPADDING PACKET  ";
    const int64_t dummy_text_len = strlen (dummy_text);
    memset (dummy_data, 0xFF, 16);
    for (int i = 16; i < len; i++)
    {
        dummy_data[i] = dummy_text[(i - 16) % dummy_text_len];
    }

}


void print_flags(uint8_t flags)
{
    if(flags & EXPCAP_FLAG_ABRT)    printf("ABRT ");
    if(flags & EXPCAP_FLAG_CRPT)    printf("CRPT ");
    if(flags & EXPCAP_FLAG_HASCRC)  printf("HCRC ");
    if(flags & EXPCAP_FLAG_HWOVFL)  printf("HWOVF ");
    if(flags & EXPCAP_FLAG_SWOVFL)  printf("SWOVF ");
    if(flags & EXPCAP_FLAG_TRNC)    printf("TRNC ");
}


int parse_device_id(const char *str, int* dev_number)
{
    int ret = sscanf(str, "exanic%d", dev_number);
    return ret < 1;
}



//Parses a string of the format "<device>:<port>"
int parse_device_port(const char *str, char *device, int *port_number)
{
    char *p, *q;

    p = strchr(str, ':');
    if (p == NULL){
        return -1;
    }

    if ((p - str) >= 16){
        return -1;
    }

    strncpy(device, str, p - str);
    device[p - str] = '\0';
    *port_number = strtol(p + 1, &q, 10);
    if (*(p + 1) == '\0' || *q != '\0'){
        // strtol failed
        return -1;
    }

    return 0;
}


int parse_device (const char* interface,
                  char device[16], int* dev_number, int *port_number)
{
    if(!exanic_find_port_by_interface_name (interface, device, 16, port_number))
    {
        return parse_device_id(device, dev_number);
    }

    if(!parse_device_port (interface, device, port_number))
    {
        return parse_device_id(device, dev_number);
    }

    return 1;
}



/* This is a dumb way to do this, but who cares? */
static int get_digitsll (int64_t num)
{
    int i = 1;
    for (; num > 0; i++)
    {
        num = num / 10;
    }

    return i;
}

int max_digitsll (int64_t a, int64_t b, int64_t c, int64_t d, int64_t e,
                  int64_t f, int64_t g, int64_t h, int64_t i, int64_t j)
{
    int result = 0;
    result = MAX (result, get_digitsll (a));
    result = MAX (result, get_digitsll (b));
    result = MAX (result, get_digitsll (c));
    result = MAX (result, get_digitsll (d));
    result = MAX (result, get_digitsll (e));
    result = MAX (result, get_digitsll (f));
    result = MAX (result, get_digitsll (g));
    result = MAX (result, get_digitsll (h));
    result = MAX (result, get_digitsll (i));
    result = MAX (result, get_digitsll (j));

    return result;
}

/* This is a dumb way to do this, but who cares? */

static int get_digitsf (double num)
{
    int i = 1;
    for (; num > 1; i++)
    {
        num = num / 10;
    }

    return i;
}

int max_digitsf (double a, double b, double c, double d, double e, double f,
                 double g, double h,  double i, double j)
{
    int result = 0;
    result = MAX (result, get_digitsf (a));
    result = MAX (result, get_digitsf (b));
    result = MAX (result, get_digitsf (c));
    result = MAX (result, get_digitsf (d));
    result = MAX (result, get_digitsf (e));
    result = MAX (result, get_digitsf (f));
    result = MAX (result, get_digitsf (g));
    result = MAX (result, get_digitsf (h));
    result = MAX (result, get_digitsf (i));
    result = MAX (result, get_digitsf (j));
    return result;
}

