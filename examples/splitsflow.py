#!/usr/bin/env python3
'''
    splitsflow - split sFlow Sample records based on destination IP prefix
    sent splitted records to the destination collector specified per ASN

    @author: Pim van Stam <pim@svsnet.nl>
    Created on 21 jun. 2016
    
    
    The MIT License (MIT)

    Copyright (c) 2016-2019 - Pim van Stam <pim@svsnet.nl>
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
'''
__version__ = "0.5.1"
__modified__ = "18-08-2021"

import os
import sys
import configparser
import argparse
import daemon
import signal
import socket
import threading
import queue
import struct
import copy
import ipaddress

try:
    import sflow
    import util
except:
    from sflow import sflow
    from sflow import util


# =============================================================================
# Configuration items
# =============================================================================

config = {'configfile'    : '/etc/splitsflow.conf',
          'loglevel'      : 'info',
          'prefixlist'    : 'bgp_prefixes.txt',
          'collectorlist' : 'collectorlist.txt',
          'logfile'       : '/var/log/splitsflow.log',
          'outfile'       : '/var/log/splitsflowerr.log',
          'port'          : '5700',
          'pid_splitsflow': '/var/run/splitsflow.pid',
          'my_asn'        : '200020'
         }

# =============================================================================
# End of configuration
# =============================================================================


seqnr_list = { 1: 1 }
prefix_list = []    # consists of 3 elements: (network, masklen, ID)
collector_list = {} # dictionary of class Collector()
logger = None

class Collector():
    """
        Collector is a list of collector's config
        Collector itself: Ip, port
        Thread for delivering flows
        A queue is created to communicate with collector's thread for sending data
    """
    def __init__(self, c_id, host, port):
        self.c_id = c_id
        self.host = host
        self.port = port
        # create a queue for the collector and a thread for sending data
        self.queue = queue.Queue()
        self.thread = FlowThread(c_id, host, port, self.queue)
        self.thread.setDaemon(True)
        self.thread.start()
    
    def senddata(self, data):
        logger.debug("Collector: put data on the queue of collector %d (%d bytes)" % (self.c_id, len(data)))
        self.queue.put(data)



class FlowThread(threading.Thread):
    """
        A thread which polls a given queue and transmits received flow data
        to a specified target host.
    """

    def __init__(self, target, host, port, queue):
        self.queue  = queue
        self.target = target
        self.host   = host # host in dotted notation
        self.port   = int(port)
        self.count  = 0
        threading.Thread.__init__(self)
        logger.info("FlowThread: Thread %s started, destination host %s, port %s" % 
                     (self.target, self.host, self.port))


    def run(self):
        try:
            logger.debug("FlowThread: create socket for %s on port %d" % (self.host, self.port))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except:
            exctype, excvalue = sys.exc_info()[:2]
            logger.error("FlowThread: ERROR: can't create socket, exception: %s - %s" % (exctype, excvalue))

            sys.exit(1)

        while True:
            data = self.queue.get()
            if data == "TERMINATE":
                logger.info("FlowThread: terminating thread with id " + str(self.target))
                break
            else:
                logger.debug("FlowThread: send data to %s on port %d (%d bytes)" % (self.host, self.port, len(data)))
                sock.sendto(data, (self.host, self.port))
                self.count += len(data)
                self.queue.task_done()
                logger.debug("FlowThread: new count is " + str(self.count))


def read_config(confg, cfgfile, context):
    '''
        read config file
    '''
    if os.path.isfile(cfgfile):
        configs = configparser.RawConfigParser()
        configs.read(cfgfile)

        for option in configs.options(context):
            confg[option]=configs.get(context,option)

    return confg


def show_ipv4_addr(flow_datagram):
    """
        get from the flow records, the IPv4 src and dst IP addresses
        from raw Flow sample records
    """
    retstr = "\n"
    for sample in flow_datagram.sample_records:
        if sample.sample_type == 1: # FlowSample
            for rec in sample.flow_records:
                if rec.type == sflow.FLOW_DATA_RAW_HEADER:
                    pkt = rec.sampled_packet
                    if pkt != None:
                        payl = pkt.payload
                        if payl != None:
                            id_ = get_prefixid(payl.dst)
                            retstr += "%s -> %d\n" % (util.ip_to_string(payl.dst), id_)
    return retstr


def read_prefixlist(fn):
    """
        Read prefixlist in fn and store in memory object list
        the prefixlist is built as:
            prefix (CIDR),id
        Input: fn is the filename of the prefixlist
        Output is the global prefix_list with elements:
            IP network, netmask, ID (i.e. AS-number)
    """
    global prefix_list
    prefix_list = []
    fp = open(fn, "r")
    for line in fp:
        elem = line.split("\t")
        if len(elem) >= 2:
            if elem[1] == 'I':
                id_ = int(config['my_asn'])
            else:
                id_ = int(elem[1])
            
            ipprefix = ipaddress.ip_network(elem[0])
            network = ipprefix.network_address
            mask = int(ipprefix.netmask)
            #print("%15s / %s -> %6d" % (str(network), str(ipprefix.prefixlen), id_))
            #print("   %15d / %d -> %6d" % (int(network), int(mask), id_))
            prefix_list.append((int(network), int(mask), id_))
            logger.info("read_prefixlist: added prefix %s/%s with id %s to list" % (str(network), str(ipprefix.prefixlen), str(id_)))

    fp.close()


def read_collectorlist(fn):
    """
        Read the list of destination collector from fn and store in the list object
        The collectors list consists of:
            collectorid, IP address, Port number (UDP)
            
        The list in the inputs file must be comma separated
        
        Input: fn is the filename of the stored collectors list
        Output is the global collector_list
    """
    global collector_list
    tmplist=[]
    fp = open(fn, "r")
    for line in fp:
        elem = line.split(",")
        if len(elem) >= 3:
            id_ = int(elem[0])
            ipaddr = elem[1]
            port = int(elem[2])
            tmplist.append(id_)
            if id_ in collector_list:
                # check if collector has changed, remove existing entry and create new changed one
                if collector_list[id_].host != ipaddr or collector_list[id_].port != port:
                    logger.info("read_collectorlist: modifying collector with id " + str(id_))
                    collector_list[id_].senddata("TERMINATE")
                    collector_list.pop(id_)
                    collector_list[id_] = Collector(id_, ipaddr, port)
            else:
                # add new collector and put it in the list
                logger.info("read_collectorlist: add collector with id " + str(id_))
                collector_list[id_] = Collector(id_, ipaddr, port)
    fp.close()
    
    # remove left over collectors
    keys = list(collector_list.keys())
    for id_ in keys:
        if id_ not in tmplist:
            logger.info("read_collectorlist: removing collector with id " + str(id_))
            collector_list[id_].senddata("TERMINATE")
            collector_list.pop(id_)

    logger.info("read_collectorlist: number of active threads: " + str(threading.active_count()))
    
    return len(collector_list)
    

def get_nextseqnr(seqid=1):
    '''
        Get the next sequence number for a flow packet for a specific collector
        seqid = the sequence counter in the counter list. This represents the flow collector
    '''
    global seqnr_list

    if seqid not in seqnr_list:
        seqnr_list[seqid]=0
    seqnr_list[seqid] += 1
    return seqnr_list[seqid]


def get_prefixid(ipaddr):
    """
        Get from the static list the collector ID of this IP address
        List is built as:
            prefix_start,prefix_end,id
        Input: Numeric value of the IP address to check, in network byte order
        Return value: the collectors ID; default 1 for missing id in the prefix_list
    """
    global prefix_list
    
    id_ = 0
    for netaddr, netmask, prefid in prefix_list:
        if (ipaddr & netmask) == (netaddr & netmask):
            id_ = prefid
            break
    
    return id_


def pack_flow(flow_dg, flow_sample, flow_record, seqnr):
    """
        pack a flow record into a sflow FlowSample diagram
        Input: flow_dg is original datagram, for default values
               flow_record of type sflow.FlowSample(), is flow to pack
        Output: sflow Datagram
    """

    # restructure flow datagram from flow records, to flow sample, to datagram    
    sample_record = copy.deepcopy(flow_sample)
    sample_record.num_flow_records = 1
    sample_record.flow_records = []
    sample_record.flow_records.append(flow_record)
    
    datagram = copy.deepcopy(flow_dg)
    datagram.sequence_number = seqnr
    datagram.num_samples = 1
    datagram.sample_records = []
    datagram.sample_records.append(sample_record)
  
    return datagram.pack()


def send_datagram(collector_id, datagram):
    """
        send data to the collector with collid
        only if the collector is defined
        collectors queue to send data to is in the collector_list
    """
    global collector_list

    addr = ['127.0.0.2', 12345]
    fdata = sflow.Datagram()
    fdata.unpack(addr, datagram)

    try:
        collector_list[collector_id].senddata(datagram)
    except KeyError:
        logger.debug("send_datagram: no collector in list for ID " + str(collector_id))
    except:
        exctype, excvalue = sys.exc_info()[:2]
        logger.error("send_datagram: Unknown exception: %s - %s" % (exctype, excvalue))



def split_records(flow_datagram):
    """
        get from the flow records, the IPv4 src and dst IP addresses
        from raw Flow sample records

        Structure in case of sampled IP payload
        datagram.sample_records[].flow_records[].sampled_packet.payload
    """

    logger.debug("datagram has " + str(len(flow_datagram.sample_records)) + " records")
    for sample in flow_datagram.sample_records:
        logger.debug("split_records: " + repr(sample))
        if ((sample.sample_type == sflow.SAMPLE_DATA_FLOW_RECORD) or 
            (sample.sample_type == sflow.SAMPLE_DATA_FLOW_EXPANDED_RECORD)):
            logger.debug("flowsample has " + str(len(sample.flow_records)) + " sample records")
            for rec in sample.flow_records:
                if rec.type == sflow.FLOW_DATA_RAW_HEADER:
                    pkt = rec.sampled_packet
                    if pkt is not None:
                        payl = pkt.payload
                        if payl is not None:
                            # check dst ip address against collectors list
                            logger.debug("split_records: found sample with dst IP " + util.ip_to_string(payl.dst))
                            collectid = get_prefixid(payl.dst)
                            logger.debug("split_records: collector id is: %d" % collectid)
                            if collectid != 0:
                                seqnr = get_nextseqnr(collectid)
                                sflow_dg = pack_flow(flow_datagram, sample, rec, seqnr)
                                send_datagram(collectid, sflow_dg)
                            else:
                                logger.debug("split_records: unknown collector for IP " + util.ip_to_string(payl.dst))
                        else:
                            logger.debug("split_records: sample without payload")
                    else:
                        logger.debug("split_records: record without sample packet")
                else:
                    logger.debug("split_records: sample record not raw type (%d)" % rec.type)



def sighup_handler(signum, frame):
    '''
        Handle SIGHUP event, reload prefix list
    '''
    logger.info("Received SIGHUP, reloading prefix list")
    read_prefixlist(cfg['prefixlist'])
    read_collectorlist(cfg['collectorlist'])


def write_pid():
    pid = os.getpid()
    with open(config['pid_splitsflow'], "w") as fpid:
        fpid.write("%d\n" % pid)
    return pid


def mainroutine():
    '''
        main routine of the daemon process
    '''
    global logger
    prevlen=0

    write_pid()

    # Register sighup_handler to be called on SIGHUP
    signal.signal(signal.SIGHUP, sighup_handler)

    logger = util.set_logging(cfg['logfile'], cfg['loglevel'])
    read_prefixlist(cfg['prefixlist'])
    read_collectorlist(cfg['collectorlist'])
        
    listen_addr = ("0.0.0.0", int(cfg['port']))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(listen_addr)
#TODO: test creation of socket

    logger.info("Splitsflow application has started")
    
    
    try:
        while True:
            # compare prefix list
            newlen = len(prefix_list)
            if newlen != prevlen:
                logger.debug("Prefix list changed!")
                prevlen = newlen

            data, addr = sock.recvfrom(65535)
            flow_data = sflow.Datagram()
            flow_data.unpack(addr, data)
                
            split_records(flow_data)

    except KeyboardInterrupt:
        # stop threads if any
        logger.info("Keyboard interrupt or SIGINT received. Stopping program")
        return
        # exit main routine and program

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Split sFlow data based on destination AS number")
    parser.add_argument("-c", "--configfile", help="Configuration file")
    parser.add_argument("-d", "--nodaemon", default=False,
                        action='store_true', help="Do not enter daemon mode")

    options = parser.parse_args()
    if options.configfile != None:
        config['configfile'] = options.configfile

    cfg = read_config(config, config['configfile'], 'common')

    fileout = open(cfg['outfile'], "a")
    if not options.nodaemon:
        with daemon.DaemonContext(stderr=fileout, stdout=fileout):
            mainroutine()
        fileout.close()
    else:
        mainroutine()
