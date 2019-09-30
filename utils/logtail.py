#! /usr/bin/env python 

import os
import sys
import time
import subprocess
import select
import json
import datetime
import numpy as np


if len(sys.argv) < 2:
    print "Usage: logtail filename"
    sys.exit(1)
    
filename = sys.argv[1]

f = subprocess.Popen(['tail','-f',filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)

prev_packets = None
prev_bytes   = None
prev_spins1  = None
prev_spinsR  = None

prev_values = None

first = True
s = 0
spin = ['|','/','-','\\',]
while True:   
    jobj_str = f.stdout.readline()
    #print jobj_str[:-1]
    jobj = json.loads(jobj_str);
    __tag      = jobj["__tag"]
    
    values = []
    for k in jobj.keys():
        v = jobj[k]
        if isinstance(v, int):
            values.append(v)
            
    values = np.array(values)
    
    if first:
        prev_values = values
        first = False
        continue
    
    delta = values - prev_values
    prev_values = values
    
    delta_jobj = jobj.copy()
    i = 0;
    for k in jobj.keys():
        v = jobj[k]
        if isinstance(v, int):            
            delta_jobj[k] = delta[i]
            i += 1
                    
    ts         = jobj["ts"]
    delay      = jobj["delay"]
    dropped    = jobj["nic_sw_rx_dropped"]
    swofl      = jobj["nic_sw_rx_swofl"]
    
    delta_ts         = delta_jobj["ts"]    
    delta_rx_packets = delta_jobj["nic_sw_rx_packets_rx"]
    delta_rx_bytes   = delta_jobj["nic_sw_rx_bytes_rx"]
    delta_spins1     = delta_jobj["nic_sw_rx_spins_first"]        
    delta_spinsR     = delta_jobj["nic_sw_rx_spins_more"]
    
    delta_packets_mmps = delta_rx_packets / (delta_ts * 1.0) * 1000
    delta_bytes_gbps   = delta_rx_bytes * 8 /(delta_ts * 1.0) 
    delta_spins1_msps  = delta_spins1 / (delta_ts * 1.0) * 1000
    delta_spinsR_msps  = delta_spinsR / (delta_ts * 1.0) * 1000
    
    ts = datetime.datetime.fromtimestamp(ts/1000/1000/1000)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
    
    print " %s Rx packet rate=%.2fMpps (%.2fGbs) Dropped=%i SWOFL=%i spins1=%.2fM spinsR=%.2fM          %c\r" % (ts_str, delta_packets_mmps, delta_bytes_gbps, dropped, swofl, delta_spins1_msps, delta_spinsR_msps, spin[s%4]),
    s+=1
    
        
        
    
    

