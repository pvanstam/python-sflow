'''
Created on 21 jun. 2016

@author: pim
'''

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

seqnr_list = { 1: 1 }
prefix_list = []    # consists of 3 elements: (network, masklen, ID)


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


def get_seqnr(seqid=1):
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
        Return value: the collectors ID
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
    
    return True


def split_records(flow_datagram):
    """
        get from the flow records, the IPv4 src and dst IP addresses
        from raw Flow sample records

        Structure in case of sampled IP payload
        datagram.sample_records[].flow_records[].sampled_packet.payload
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
                            # check dst ip address against collectors list
                            collectid = get_prefixid(payl.dst)
                            if collectid != None:
                                seqnr = get_seqnr(collectid)
                                retstr += "%s (%d), seqnr=%d\n" % (util.ip_to_string(payl.dst), collectid, seqnr)
                                #sflow_dg = pack_flow(flow_datagram, rec, seqnr)
                                #send_flow(sflow_dg, collectid)
    return retstr





if __name__ == '__main__':
    
    read_prefixlist(PREFIXLIST)
    
    listen_addr = ("0.0.0.0", 5700)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(listen_addr)

    while True:
        data, addr = sock.recvfrom(65535)
        flow_data = sflow.Datagram()
        flow_data.unpack(addr, data)
        
        #ip = show_ipv4_addr(flow_data)

        #sys.stdout.write(show_ipv4_addr(flow_data))
        sys.stdout.write(split_records(flow_data))

        