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
__version__ = "0.4.6b"
__modified__ = "10-05-2019"

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
          'pid_splitsflow': '/var/run/splitsflow.pid'
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
        logger.debug("FlowThread: Thread %s started, destination host %s, port %s" % 
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
            # now let's change the header:
            # modify count and flow_sequence so it makes sense for the receiver
            data = self.queue.get()
            #hdata = struct.unpack("!HHIIIIBBH", header)
            #hdr = struct.pack("!HHIIIIBBH", hdata[0], len(data), hdata[2], hdata[3], hdata[4], count, hdata[6], hdata[7], hdata[8])

            #sock.sendto("%s%s" % (hdr, "".join(data)), (self.host, self.port))
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
            id_ = int(elem[1])
            network, mask = elem[0].split('/')
            #print("%15s / %s -> %6d" % (network, mask, id_))
            netaddr = struct.unpack('!L',socket.inet_aton(network))[0]
            netmask = ((1<<(32-int(int(mask)))) - 1)^0xffffffff
            prefix_list.append((netaddr, netmask, id_))
            logger.debug("read_prefixlist: added prefix %s/%s with id %s to list" % (network, mask, str(id_)))
                    
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
    collector_list = {}  # clear the list
    fp = open(fn, "r")
    cnt = 0
    for line in fp:
        elem = line.split(",")
        if len(elem) >= 3:
            cnt += 1
            id_ = int(elem[0])
            #ipaddr = struct.unpack('!L',socket.inet_aton(elem[1]))[0]
            #ipaddr = socket.ntohl(ipaddr)
            ipaddr = elem[1]
            port = int(elem[2])
            collector_list[id_] = Collector(id_, ipaddr, port)
    fp.close()
    return cnt # number of elements in the list
    

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
    
    id_ = 1
    #ipaddr = socket.ntohl(ipaddr)
    #ip = struct.unpack('!L',socket.inet_aton(ipaddr))[0]
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
    #sys.stdout.write(repr(fdata))


    try:
        collector_list[collector_id].senddata(datagram)
    except KeyError:
        """ Do nothing, no collector defined for this datagram """
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
    #retstr = "Start splitting:\n"
    retstr = "split_records: "
    for sample in flow_datagram.sample_records:
        if sample.sample_type == 1: # FlowSample
            for rec in sample.flow_records:
                if rec.type == sflow.FLOW_DATA_RAW_HEADER:
                    pkt = rec.sampled_packet
                    if pkt != None:
                        payl = pkt.payload
                        if payl != None:
                            # check dst ip address against collectors list
                            logger.debug("split_records: found sample with dst ip " + str(payl.dst))
                            collectid = get_prefixid(payl.dst)
                            if collectid != None:
                                seqnr = get_nextseqnr(collectid)
                                retstr += "  %s (%d), seqnr=%d\n" % (util.ip_to_string(payl.dst), collectid, seqnr)
                                sflow_dg = pack_flow(flow_datagram, sample, rec, seqnr)
                                send_datagram(collectid, sflow_dg)
                            else:
                                retstr += "  unknown collector for IP " + util.ip_to_string(payl.dst)
                else:
                    retstr += "  " + str(rec.type) + "\n"
        else: # CounterSample
            retstr += "  CounterSample\n"
            logger.debug("split_records: " + repr(sample))
    return retstr


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
    
            #ip = show_ipv4_addr(flow_data)
            #sys.stdout.write(show_ipv4_addr(flow_data))
            #sys.stdout.write(repr(flow_data))
            
            retval = split_records(flow_data)
#            if len(retval) > 1:
#                logger.debug("mainroutine: " + retval)
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

    fileout = open(cfg['outfile'], "w")
    if not options.nodaemon:
        with daemon.DaemonContext(stderr=fileout, stdout=fileout):
            mainroutine()
        fileout.close()
    else:
        mainroutine()
