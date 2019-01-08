/*
 * Copyright (c) 2017, 2018 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     19 Jun 2017
 *  Author:      Matthew P. Grosvenor
 *  Description:
 *  Implementation of an ExaNIC reader/writer stream using the exactio abstract
 *  I/O interface.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>
#include <chaste/log/log.h>

#include <linux/ethtool.h>
#ifndef ETHTOOL_GET_TS_INFO
#include "ethtool_ts_info.h"
#endif


#include "exactio_exanic.h"

#include "../utils.h"

typedef enum {
    EXACTIO_FILE_MOD_IGNORE = 0,
    EXACTIO_FILE_MOD_RESET  = 1,
    EXACTIO_FILE_MOD_TAIL   = 2,
} exactio_exa_mod_t;



static void exa_destroy(eio_stream_t* this)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    if(priv->closed){
        return;
    }

    if(priv->rx){
        exanic_release_rx_buffer(priv->rx);
    }

    if(priv->tx){
        exanic_release_tx_buffer(priv->tx);
    }

    if(priv->rx_nic){
        exanic_release_handle(priv->rx_nic);
    }

    if(priv->tx_nic){
        exanic_release_handle(priv->tx_nic);
    }

    if(this->name)
    {
        free(this->name);
        this->name = NULL;
    }

    priv->closed = true;

}



//Write operations
static eio_error_t exa_write_acquire(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    ifassert(priv->tx_buffer){
        return EIO_ERELEASE;
    }

    ifassert(*len > (int64_t)priv->max_tx_mtu){
        return EIO_ETOOBIG;
    }

    iflikely(*len == 0){
        *len = priv->max_tx_mtu;
    }

    priv->tx_buffer_len = *len;
    priv->tx_buffer = exanic_begin_transmit_frame(priv->tx,(size_t)*len);

    (void)ts;
    //eio_nowns(ts);
    *buffer = priv->tx_buffer;

    return EIO_ENONE;
}

static eio_error_t exa_write_release(eio_stream_t* this, int64_t len, int64_t* ts)
{
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);
    ifassert(!priv->tx_buffer){
        return EIO_EACQUIRE;
    }

    ifassert(len > priv->tx_buffer_len){
        fprintf(stderr,"Error: length supplied is larger than length of buffer. Corruption likely. Aborting\n");
        exit(-1);
    }

    exanic_cycles32_t old_start = 0;
    exanic_cycles32_t start     = 0;
    ifunlikely(ts){
        old_start = exanic_get_tx_timestamp(priv->tx);
    }

    ifunlikely(len == 0){
        exanic_abort_transmit_frame(priv->tx);
        return EIO_ENONE;
    }

    ifunlikely(exanic_end_transmit_frame(priv->tx,len)){
        return EIO_EUNSPEC;
    }

    ifunlikely(ts){
        do{
            /* Wait for TX frame to leave the NIC */
        }
        while (old_start == start);

        //This is nasty because the last packet sent timestamp will not always
        //be timestamp of the packet sent
        *ts = exanic_expand_timestamp(priv->tx_nic, start);
    }


    priv->tx_buffer     = NULL;
    priv->tx_buffer_len = 0;
    return EIO_ENONE;
}


static inline eio_error_t exa_write_sw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}


static inline eio_error_t exa_write_hw_stats(eio_stream_t* this, void* stats)
{
    (void)this;
    (void)stats;

	return EIO_ENOTIMPL;
}

#define PICOS_PER_SEC (1000ULL * 1000 * 1000 * 1000)
#define EXANIC_HPT_TICK_HZ 4000000000
#define EXANIC_DEFAULT_TICK_HZ 161132800
static inline void temp_exanic_cycles_to_timespecps(exanic_t *exanic, exanic_cycles_t cycles,
        struct exanic_timespecps *tsps)
{
    /* We know that there are a couple of common/default frequencies in tick_hz,
        * optimize for those cases while remaining safe for future cases
        */
       switch(exanic->tick_hz)
       {
           case EXANIC_HPT_TICK_HZ:
           {
               tsps->tv_sec  = cycles / EXANIC_HPT_TICK_HZ;

               /* This complicated bit of maths is necessary to avoid overflows
                * while maintaining precision in the conversion between cycles and
                * picoseconds */
               const uint64_t frac_cycles = cycles % EXANIC_HPT_TICK_HZ;
               tsps->tv_psec = (frac_cycles * (PICOS_PER_SEC / EXANIC_HPT_TICK_HZ))
                       + (frac_cycles * (PICOS_PER_SEC % EXANIC_HPT_TICK_HZ) /
                        EXANIC_HPT_TICK_HZ);
               break;
           }
           case EXANIC_DEFAULT_TICK_HZ:
           {

               tsps->tv_sec  = cycles / EXANIC_DEFAULT_TICK_HZ;

               /* This complicated bit of maths is necessary to avoid overflows
                * while maintaining precision in the conversion between cycles and
                * picoseconds */
               const uint64_t frac_cycles = cycles % EXANIC_DEFAULT_TICK_HZ;
               tsps->tv_psec = (frac_cycles * (PICOS_PER_SEC /
                       EXANIC_DEFAULT_TICK_HZ)) + (frac_cycles * (PICOS_PER_SEC %
                               EXANIC_DEFAULT_TICK_HZ) / EXANIC_DEFAULT_TICK_HZ);
               break;
           }
           default:
           {
               tsps->tv_sec  = cycles / exanic->tick_hz;

               /* This complicated bit of maths is necessary to avoid overflows
                * whilemaintaining precision in the conversion between cycles and
                * picoseconds */
               const uint64_t frac_cycles = cycles % exanic->tick_hz;
               tsps->tv_psec = (frac_cycles * (PICOS_PER_SEC / exanic->tick_hz)) +
                       (frac_cycles * (PICOS_PER_SEC % exanic->tick_hz) /
                               exanic->tick_hz);
           }

       }

}

static eio_error_t exa_time_to_tsps(eio_stream_t* this, void* time, timespecps_t* tsps)
{
    exanic_cycles_t* cycles = (exanic_cycles_t*)time;
    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    iflikely(tsps){
        struct exanic_timespecps exanic_tsps = {0};
        temp_exanic_cycles_to_timespecps(priv->rx_nic, *cycles, &exanic_tsps);
        tsps->secs = exanic_tsps.tv_sec;
        tsps->psecs = exanic_tsps.tv_psec;
    }

    return EIO_ENONE;

}



int ethtool_ioctl(int fd, char *ifname, void *data)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_data = data;

    return ioctl(fd, SIOCETHTOOL, &ifr);
}

static int ethtool_get_priv_flags(int fd, char *ifname, uint32_t *flags)
{
    struct ethtool_value val;
    int ret;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_GPFLAGS;
    ret = ethtool_ioctl(fd, ifname, &val);
    if (ret == 0)
        *flags = val.data;

    return ret;
}


static int ethtool_get_flag_names(int fd, char *ifname,
                                  char flag_names[32][ETH_GSTRING_LEN])
{
    struct ethtool_drvinfo drvinfo;
    struct ethtool_gstrings *strings;
    unsigned len;

    /* Get number of flags from driver info */
    memset(&drvinfo, 0, sizeof(drvinfo));
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    if (ethtool_ioctl(fd, ifname, &drvinfo) == -1)
        return -1;

    len = drvinfo.n_priv_flags;
    if (len > 32)
        len = 32;

    /* Get flag names */
    strings = calloc(1, sizeof(struct ethtool_gstrings) + len * ETH_GSTRING_LEN);
    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_PRIV_FLAGS;
    strings->len = len;
    if (ethtool_ioctl(fd, ifname, strings) == -1)
    {
        free(strings);
        return -1;
    }

    memset(flag_names, 0, 32 * ETH_GSTRING_LEN);
    memcpy(flag_names, strings->data, len * ETH_GSTRING_LEN);

    return 0;
}


static int ethtool_set_priv_flags(int fd, char *ifname, uint32_t flags)
{
    struct ethtool_value val;

    memset(&val, 0, sizeof(val));
    val.cmd = ETHTOOL_SPFLAGS;
    val.data = flags;

    return ethtool_ioctl(fd, ifname, &val);
}

static int set_exanic_params(exanic_t *exanic, char* device, int port_number,
                             bool promisc, bool kernel_bypass)
{
    struct ifreq ifr;
    int fd;

    if (exanic_get_interface_name(exanic, port_number, ifr.ifr_name, IFNAMSIZ) != 0)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                exanic_get_last_error());
        exit(1);
    }


    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
            ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    if(promisc)
        ifr.ifr_flags |= IFF_PROMISC;

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }


    if(!kernel_bypass)
        return 0;


    /* Get flag names and current setting */
    char flag_names[32][ETH_GSTRING_LEN];
    uint32_t flags = 0;
    if (ethtool_get_flag_names(fd, ifr.ifr_name, flag_names) == -1 ||
        ethtool_get_priv_flags(fd, ifr.ifr_name, &flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, strerror(errno));
        exit(1);
    }

    /* Look for flag name */
    int i = 0;
    for (i = 0; i < 32; i++)
        if (strcmp("bypass_only", flag_names[i]) == 0)
            break;
    if (i == 32)
    {
        fprintf(stderr, "%s:%d: could not find bypass-only flag \n",
                device, port_number);
        exit(1);
    }

    flags |= (1 << i);

    /* Set flags */
    if (ethtool_set_priv_flags(fd, ifr.ifr_name, flags) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", device, port_number,
                (errno == EINVAL) ? "Feature not supported on this port"
                                  : strerror(errno));
        exit(1);
    }

    return 0;
}



/*
 * Arguments
 * [0] filename
 * [1] read buffer size
 * [2] write buffer size
 * [3] reset on modify
 */
static eio_error_t exa_construct(eio_stream_t* this, exa_args_t* args)
{
    const char* interface_rx = args->interface_rx;
    const char* interface_tx = args->interface_tx;
    const bool promisc       = args->promisc;
    const bool kernel_bypass = args->kernel_bypass;
    const bool clear_buff    = args->clear_buff;

    ch_log_info("Constructing exanic %s\n", args->interface_rx);
    /*TODO for the moment just use the RX interface name. Should think of
     * something smarter to do here? Maybe "rx:tx"?
     */
    const char* name = args->interface_rx;
    const int64_t name_len = strnlen(name, 1024);
    this->name = calloc(name_len + 1, 1);
    memcpy(this->name, name, name_len);

    exa_priv_t* priv = IOSTREAM_GET_PRIVATE(this);

    if(interface_rx){
        if(parse_device(interface_rx, priv->rx_dev, &priv->rx_dev_id, &priv->rx_port))
        {
            fprintf (stderr, "%s: no such interface or not an ExaNIC\n",
                     interface_rx);
            return 1;
        }

        priv->rx_nic = exanic_acquire_handle(priv->rx_dev);
        if (!priv->rx_nic){
            fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
            return 1;
        }

        priv->rx = exanic_acquire_rx_buffer(priv->rx_nic, priv->rx_port, 0);
        if (!priv->rx){
            fprintf(stderr, "exanic_acquire_rx_buffer: %s\n", exanic_get_last_error());
            return 1;
        }

        if(clear_buff){
            ch_log_warn("Warning: clearing rx buffer on %s\n", interface_rx);
            const size_t rx_buff_sz = 64 * 1024;
            char rx_buff[rx_buff_sz];
            int64_t clear_cnt = -1;
            for(ssize_t err = -1; err != 0; clear_cnt++){
                 err =exanic_receive_frame(priv->rx, rx_buff, rx_buff_sz, NULL);
                 if(err < 0){
                     ch_log_warn("Warning: rx error %li on %s\n", err, interface_rx);
                 }
            }
            if(clear_cnt > 0){
                ch_log_warn("Cleared stale packets from rx buffer on %s\n",
                            interface_rx);
            }
            ch_log_info("Done clearing rx buffer on %s\n", interface_rx);
        }

        if(set_exanic_params(priv->rx_nic, priv->rx_dev, priv->rx_port,
                             promisc,kernel_bypass)){
            return 1;
        }

    }

    if(interface_tx){
        if(parse_device(interface_tx, priv->tx_dev, &priv->tx_dev_id, &priv->tx_port))
        {
            fprintf (stderr, "%s: no such interface or not an ExaNIC\n",
                     interface_tx);
            return 1;
        }


        priv->tx_nic = exanic_acquire_handle(priv->tx_dev);
        if (!priv->tx_nic){
            fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
            return 1;
        }

        priv->max_tx_mtu = exanic_get_tx_mtu(priv->tx);

        priv->tx = exanic_acquire_tx_buffer(priv->tx_nic, priv->tx_port, 0);
        if (!priv->tx){
            fprintf(stderr, "exanic_acquire_tx_buffer: %s\n", exanic_get_last_error());
            return 1;
        }
    }


    //priv->eof    = 0;
    priv->closed = false;

    return 0;

}

NEW_IOSTREAM_DEFINE(exa,exa_args_t, exa_priv_t)

