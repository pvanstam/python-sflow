'''
    splitsflow - split sFlow Sample records based on destination IP prefix
    sent splitted records to the destination collector specified per ASN

    @author: Pim van Stam <pim@svsnet.nl>
    Created on 21 jun. 2016
    
    
    The MIT License (MIT)

    Copyright (c) 2016 Pim van Stam <pim@svsnet.nl>
    
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
__version__ = "0.1"
__modified__ = "19-09-2016"

import sys
import socket
import struct
import copy

try:
    import sflow
    import util
except:
    from sflow import sflow
    from sflow import util

PREFIXLIST = "../bgp_prefixes.txt"
COLLECTORLIST = "collectorlist.txt"

seqnr_list = { 1: 1 }
prefix_list = []    # consists of 3 elements: (network, masklen, ID)
collector_list = [] # consists of collectorid, IP, Port

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
                    
    fp.close()
    #print(prefix_list)
    #for na, nm, ni in prefix_list:
    #    print("%s / %s = %d" % (util.ip_to_string(na), util.ip_to_string(nm), ni))


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
    collector_list = []  # clear the list
    fp = open(fn, "r")
    cnt = 0
    for line in fp:
        elem = line.split(",")
        if len(elem) >= 3:
            cnt += 1
            id_ = int(elem[0])
            ipaddr = struct.unpack('!L',socket.inet_aton(elem[1]))[0]
            port = int(elem[2])
            collector_list.append((id_, ipaddr, port))
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
    ipaddr = socket.ntohl(ipaddr)
    #ip = struct.unpack('!L',socket.inet_aton(ipaddr))[0]
    for netaddr, netmask, prefid in prefix_list:
        if (ipaddr & netmask) == (netaddr & netmask):
            id_ = prefid
            break
    
    return id_


def pack_flow(flow_dg, flow_record, seqnr):
    """
        pack a flow record into a sflow FlowSample diagram
        Input: flow_dg is original datagram, for default values
               flow_record of type sflow.FlowSample(), is flow to pack
        Output: sflow Datagram
    """
    
    datagram = copy.deepcopy(flow_dg)
    datagram.sequence_number = seqnr
    datagram.num_samples = 1
    datagram.sample_records = []
    datagram.sample_records.append(flow_record)
  
    return datagram.pack()


def send_flow(datagram, collid):
    """
        Send the sFlow datagra to the sFlow collector, identified by
        the collid
        return True of False on success of the transfer
    """
    global collector_list
    coll_ip = None
    coll_port = None
    for id_, ip, port in collector_list:
        if id_ == collid:
            coll_ip = ip
            coll_port = port
            break

    if coll_ip != None:
        print("Flow sample for collector " + util.ip_to_string(socket.ntohl(coll_ip)) + " on port " + str(coll_port))
        return (coll_ip, coll_port)
    else:
        print("No collector defined")
        return None


def split_records(flow_datagram):
    """
        get from the flow records, the IPv4 src and dst IP addresses
        from raw Flow sample records

        Structure in case of sampled IP payload
        datagram.sample_records[].flow_records[].sampled_packet.payload
    """
    #retstr = "Start splitting:\n"
    retstr = ""
    for sample in flow_datagram.sample_records:
        if sample.sample_type == 1: # FlowSample
            for rec in sample.flow_records:
                if rec.type == sflow.FLOW_DATA_RAW_HEADER:
                    pkt = rec.sampled_packet
                    if pkt != None:
                        payl = pkt.payload
                        if payl != None:
                            # check dst ip address against collectors list
                            collectid = get_prefixid(payl.dst)
                            if collectid != None:
                                seqnr = get_nextseqnr(collectid)
                                retstr += "  %s (%d), seqnr=%d\n" % (util.ip_to_string(payl.dst), collectid, seqnr)
                                sflow_dg = pack_flow(flow_datagram, rec, seqnr)
                                send_flow(sflow_dg, collectid)
                            else:
                                retstr += "  unknown collector for IP " + util.ip_to_string(payl.dst)
#                else:
#                    retstr += "  " + str(rec.type) + "\n"
#        else:
#            retstr += "  CounterSample\n"
    return retstr





if __name__ == '__main__':
    
    read_prefixlist(PREFIXLIST)
    print(read_collectorlist(COLLECTORLIST))
    
    listen_addr = ("0.0.0.0", 5700)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(listen_addr)

    while True:
        data, addr = sock.recvfrom(65535)
        flow_data = sflow.Datagram()
        flow_data.unpack(addr, data)
        
        #ip = show_ipv4_addr(flow_data)

        #sys.stdout.write(show_ipv4_addr(flow_data))
        #sys.stdout.write(repr(flow_data))
        retval = split_records(flow_data)
        if len(retval) > 1:
            sys.stdout.write(retval)

        