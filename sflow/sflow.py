"""
    Library for parsing sFlow (v5) datagrams.

    Standards and Specs
    The sFlow v5 format is documented in
    www.sflow.org/sflow_version_5.txt, a copy of which is included in
    the doc/ subdirectory of the pyflow repo.  Page numbers refer to
    this document.

    Since the datagram format is specified using XDR the following RFCs
    may be useful: 1014, 1832, 4506.

    The IEEE 802.x / ISO/IEC 8802.x and IPv4 headers are documented at
    http://de.wikipedia.org/wiki/IPv4#Header-Format
    http://en.wikipedia.org/wiki/IEEE_802.1Q
    http://en.wikipedia.org/wiki/Ethernet
    
    original source: https://github.com/kok/pyflow (Kai Kaminski)
    
    @author: Pim van Stam <pim@svsnet.nl>
    
    
    The MIT License (MIT)

    Copyright (c) 2016 Pim van Stam <pim@svsnet.nl>
    Copyright (c) 2024 Ian A. Underwood <ian@underwood-hq.org>
    
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
"""
__version__ = "0.2.5"
__modified__ = "2024-08-31"

import sys
import xdrlib
import socket
import math

try:
    import util
except:
    from sflow import util


# Constants for the sample_data member of 'struct sample_record'
# numbers in: http://www.sflow.org/developers/structures.php
SAMPLE_DATA_FLOW_RECORD = 1
SAMPLE_DATA_COUNTER_RECORD = 2
SAMPLE_DATA_FLOW_EXPANDED_RECORD = 3
SAMPLE_DATA_COUNTER_EXPANDED_RECORD = 4
SAMPLE_DATA_DISCARDED_PACKET = 5


# Constants for the flow_format member of 'struct flow_record'
# (p. 29).  See pp. 35-41 for the meaning of these values.
FLOW_DATA_RAW_HEADER = 1
FLOW_DATA_ETHERNET_HEADER = 2
FLOW_DATA_IPV4_HEADER = 3
FLOW_DATA_IPV6_HEADER = 4
FLOW_DATA_EXT_SWITCH = 1001
FLOW_DATA_EXT_ROUTER = 1002
FLOW_DATA_EXT_GATEWAY = 1003
FLOW_DATA_EXT_USER = 1004
FLOW_DATA_EXT_URL = 1005
FLOW_DATA_EXT_MPLS = 1006
FLOW_DATA_EXT_NAT = 1007
FLOW_DATA_EXT_MPLS_TUNNEL = 1008
FLOW_DATA_EXT_MPLS_VC = 1009
FLOW_DATA_EXT_MPLS_FEC = 1010
FLOW_DATA_EXT_MPLS_LVP_FEC = 1011
FLOW_DATA_EXT_VLAN_TUNNEL = 1012


COUNTER_DATA_GENERIC = 1
COUNTER_DATA_ETHERNET= 2
COUNTER_DATA_TOKENRING = 3
COUNTER_DATA_VG = 4
COUNTER_DATA_VLAN = 5
COUNTER_DATA_IEEE80211 = 6
COUNTER_DATA_LAG_PORT = 7
COUNTER_DATA_SLOW_PATH = 8
COUNTER_DATA_IB = 9
COUNTER_DATA_SFP = 10
COUNTER_DATA_PROCESSOR = 1001

# Constants for 'enum header_protocol'.  See p.35 of the sFlow v5
# spec.
HEADER_PROTO_ETHERNET_ISO88023 = 1
HEADER_PROTO_ISO88024_TOKENBUS = 2
HEADER_PROTO_ISO88025_TOKENRING = 3,
HEADER_PROTO_FDDI = 4
HEADER_PROTO_FRAME_RELAY = 5
HEADER_PROTO_X25 = 6
HEADER_PROTO_PPP = 7
HEADER_PROTO_SMDS = 8
HEADER_PROTO_AAL5 = 9
HEADER_PROTO_AAL5_IP = 10
HEADER_PROTO_IPV4 = 11
HEADER_PROTO_IPV6 = 12
HEADER_PROTO_MPLS = 13
HEADER_PROTO_POS = 14


# Constants decribing the values of the 'type' field of 
#IEEE802.3/IEEE802.1Q headers.
ETHER_TYPE_IEEE8021Q = 0x8100

'''
    typedefs:
    typedef opaque mac[6]; -> (un)pack_fopaque(6)

'''

"""
    Top level class of sFlow packets
    Datagram
        - Datagrm header
        - Sample records, FlowSample or CounterSample
"""

class Datagram(object):
    """
        Describes the header data of an sFlow v5 datagram.
        Datagram is de header of a sFlow datagram and contains 1 or more 
        flow records
        Datagram.aaa
            sample_records[]. records with type FlowSample or CounterSample
                sample.ccc; type is FlowSample or CounterSample
                    sample_records; type is SampleRecord or CounterRecord
                    
    """
    
    def __init__(self):
        self.version = 5
        self.src_addr = None
        self.src_port = None
        self.agent_address_type = 0
        self.agent_address = 0
        self.sub_agent_id = 0
        self.sequence_number = 0
        self.uptime = 0
        self.num_samples = 0
        self.sample_records = []
    

    def unpack(self, addr, data):
        '''
            unpack data from data argument and store in class elements
        '''
        self.src_addr = addr[0]
        self.src_port = addr[1]
        
        up = xdrlib.Unpacker(data)
        self.version = up.unpack_int()
        if not self.version == 5:       # sFlow version 5
            util.hexdump_bytes(data)
            raise Exception()
            return False

        self.agent_address_type = up.unpack_int()
        if self.agent_address_type == 1:                 # IPv4
            self.agent_address = up.unpack_uint()
        else:
            # IPv6 not supported yet
            raise Exception()
            return False
        
        self.sub_agent_id = up.unpack_uint()
        self.sequence_number = up.unpack_uint()
        self.uptime = up.unpack_uint()
        self.num_samples = up.unpack_uint()
        if self.num_samples == None:
            self.num_samples = 0

        # Iterating over sample records
        for i in range(self.num_samples):
            sample_type = up.unpack_uint()
            if sample_type != None:
                sample = get_sample_object(sample_type)
                if sample != None:
                    data = up.unpack_bytes()
                    if data != None:
                        sample.len = len(data)
#TODO: check / try for len > 0; unpack fails from time to time
                        sample.unpack(data)
                        self.sample_records.append(sample)
            
        # we should be ready now
        #up.done()
        
    def pack(self):
        '''
            pack the datagram class record into a binary datagram object
        '''
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_int(self.version)
        packdata.pack_int(self.agent_address_type)
        packdata.pack_uint(self.agent_address) # IPv4; IPv6 not supported yet; see unpack
        packdata.pack_uint(self.sub_agent_id)
        packdata.pack_uint(self.sequence_number)
        packdata.pack_uint(self.uptime)
        packdata.pack_uint(self.num_samples)

        # Iterating over sample records
        for i in range(self.num_samples):
            rec = self.sample_records[i]
            packdata.pack_uint(rec.sample_type)
            packdata.pack_bytes(rec.pack())


        return packdata.get_buffer()


    def __repr__(self):
        repr_ = ('\nDatagram| src: %s/%d, agent: %s(%d), seq: %d, uptime: %dh; samples: %d\n'
                % (self.src_addr, 
                   self.src_port, 
                   util.ip_to_string(self.agent_address),
                   self.sub_agent_id, 
                   self.sequence_number, 
                   math.floor(self.uptime/3600000.0),
                   self.num_samples))
        for rec in self.sample_records:
            repr_ += repr(rec)
        return repr_


def get_sample_object(sample_type):
    """
    return object of a sFlow sample class

    :param sample_type:
    :return:
    """
    if sample_type == SAMPLE_DATA_FLOW_RECORD:
        return FlowSample()
    elif sample_type == SAMPLE_DATA_COUNTER_RECORD:
        return CounterSample()
    elif sample_type == SAMPLE_DATA_FLOW_EXPANDED_RECORD:
        return ExpandedFlowSample()
    elif sample_type == SAMPLE_DATA_DISCARDED_PACKET:
        return DiscardedPacketSample()
    else:
        return None


"""
    Sample records classes as part of the sFlow Diagram
    - FlowSample
    - CounterSample
"""


class FlowSample ():
    """
        sFlow sample type Flow Sample
    """

    def __init__(self):
        self.sample_type = SAMPLE_DATA_FLOW_RECORD
        self.len = 0
        self.sequence_number = 0
        self.source_id = 0
        self.sampling_rate = 0
        self.sample_pool = 0
        self.drops = 0
        self.input_if = 0
        self.output_if = 0
        self.num_flow_records = 0
        self.flow_records = []


    def unpack(self, data):
        pdata = xdrlib.Unpacker(data)
        self.sequence_number = pdata.unpack_uint()
        self.source_id = pdata.unpack_uint()
        self.sampling_rate = pdata.unpack_uint()
        self.sample_pool = pdata.unpack_uint()
        self.drops = pdata.unpack_uint()
        self.input_if = pdata.unpack_uint()
        self.output_if = pdata.unpack_uint()
        self.num_flow_records = pdata.unpack_uint()

        for i in range(self.num_flow_records):
            flow_record = get_sample_record_object(SAMPLE_DATA_FLOW_RECORD, 
                                                  pdata.unpack_uint(),
                                                  pdata.unpack_bytes())            
            self.flow_records.append(flow_record)


    def pack(self):
        '''
            Pack data object
        '''
        packdata = xdrlib.Packer() # create the packed object
#        packdata.pack_uint(self.sample_type)
#        packdata.pack_uint(self.len)
        packdata.pack_uint(self.sequence_number)

        packdata.pack_uint(self.source_id)
        packdata.pack_uint(self.sampling_rate)
        packdata.pack_uint(self.sample_pool)
        packdata.pack_uint(self.drops)
        packdata.pack_uint(self.input_if)
        packdata.pack_uint(self.output_if)
        packdata.pack_uint(self.num_flow_records)

        for i in range(self.num_flow_records):
            rec = self.flow_records[i]
            packdata.pack_uint(rec.type)
            packdata.pack_bytes(rec.pack())

        return packdata.get_buffer()

        
    def __repr__(self):
        repr_ = ('  FlowSample: len: %d, seq: %d, in_if: %d, out_if: %d, rate: %d>, records: %d\n' %
                (self.len,
                 self.sequence_number,
                 self.input_if,
                 self.output_if,
                 self.sampling_rate,
                 self.num_flow_records))
        for rec in self.flow_records:
            repr_ += repr(rec)

        return repr_



class ExpandedFlowSample():
    """
        sFlow sample type Expanded Flow Sample
    """

    def __init__(self):
        self.sample_type = SAMPLE_DATA_FLOW_EXPANDED_RECORD
        self.len = 0
        self.sequence_number = 0
        self.source_id_type = 0 # specific for expanded type
        self.source_id = 0
        self.sampling_rate = 0
        self.sample_pool = 0
        self.drops = 0
        self.input_if_format = 0 # specific for expanded type
        self.input_if = 0
        self.output_if_format = 0 # specific for expanded type
        self.output_if = 0
        self.num_flow_records = 0
        self.flow_records = []


    def unpack(self, data):
        pdata = xdrlib.Unpacker(data)
        self.sequence_number = pdata.unpack_uint()
        self.source_id_type = pdata.unpack_uint()
        self.source_id = pdata.unpack_uint()
        self.sampling_rate = pdata.unpack_uint()
        self.sample_pool = pdata.unpack_uint()
        self.drops = pdata.unpack_uint()
        self.input_if_format = pdata.unpack_uint()
        self.input_if = pdata.unpack_uint()
        self.output_if_format = pdata.unpack_uint()
        self.output_if = pdata.unpack_uint()
        self.num_flow_records = pdata.unpack_uint()

        for i in range(self.num_flow_records):
            flow_record = get_sample_record_object(SAMPLE_DATA_FLOW_RECORD, 
                                                  pdata.unpack_uint(),
                                                  pdata.unpack_bytes())            
            self.flow_records.append(flow_record)


    def pack(self):
        '''
            Pack data object
        '''
        packdata = xdrlib.Packer() # create the packed object
#        packdata.pack_uint(self.sample_type)
#        packdata.pack_uint(self.len)
        packdata.pack_uint(self.sequence_number)

        packdata.pack_uint(self.source_id_type)
        packdata.pack_uint(self.source_id)
        packdata.pack_uint(self.sampling_rate)
        packdata.pack_uint(self.sample_pool)
        packdata.pack_uint(self.drops)
        packdata.pack_uint(self.input_if_format)
        packdata.pack_uint(self.input_if)
        packdata.pack_uint(self.output_if_format)
        packdata.pack_uint(self.output_if)
        packdata.pack_uint(self.num_flow_records)

        for i in range(self.num_flow_records):
            rec = self.flow_records[i]
            packdata.pack_uint(rec.type)
            packdata.pack_bytes(rec.pack())

        return packdata.get_buffer()

        
    def __repr__(self):
        repr_ = ('  FlowSample: len: %d, seq: %d, in_if: %d, out_if: %d, rate: %d>, records: %d\n' %
                (self.len,
                 self.sequence_number,
                 self.input_if,
                 self.output_if,
                 self.sampling_rate,
                 self.num_flow_records))
        for rec in self.flow_records:
            repr_ += repr(rec)

        return repr_



class CounterSample():
    '''
        sFlow sample type Counter Sample
    '''
    
    def __init__(self):
        self.sample_type = SAMPLE_DATA_COUNTER_RECORD
        self.len = 0
        self.sequence_number = 0
        self.source_id = 0
        self.num_counter_records = 0
        self.counter_records = []


    def unpack(self, data):
        '''
            unpack elements in data for CounterSample sFlow record
        '''
        pdata = xdrlib.Unpacker(data)
        if data != None and len(data) > 0:
            self.sequence_number = pdata.unpack_uint()
            self.source_id = pdata.unpack_uint()
            self.num_counter_records = pdata.unpack_uint()
            
            for i in range(self.num_counter_records):
                cnt_record = get_sample_record_object(SAMPLE_DATA_COUNTER_RECORD, 
                                                      pdata.unpack_uint(),
                                                      pdata.unpack_bytes())
                self.counter_records.append(cnt_record)


    def pack(self):
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_uint(self.sequence_number)
        packdata.pack_uint(self.source_id)
        packdata.pack_uint(self.num_counter_records)

        for i in range(self.num_counter_records):
            rec = self.counter_records[i]
            packdata.pack_uint(rec.type)
            packdata.pack_bytes(rec.pack())

        return packdata.get_buffer()


    def __repr__(self):
        repr_ = ('  CounterSample: len: %d, seq: %d, srcid: %d, cntrs: %d\n' % 
                 (self.len,
                  self.sequence_number,
                  self.source_id,
                  self.num_counter_records))
        for rec in self.counter_records:
            repr_ += repr(rec)

        return repr_


class DiscardedPacketSample():
    """
        Discarded Packet Sampling
    """

    def __init__(self):
        self.sample_type = SAMPLE_DATA_DISCARDED_PACKET
        self.len = 0
        self.sequence_number = 0
        self.ds_class = 0
        self.ds_index = 0
        self.drops = 0
        self.input_if = 0
        self.output_if = 0
        self.reason = 0
        self.num_records = 0
        self.flow_records = []

    def unpack(self, data):
        pdata = xdrlib.Unpacker(data)
        self.sequence_number = pdata.unpack_uint()
        self.ds_class = pdata.unpack_uint()
        self.ds_index = pdata.unpack_uint()
        self.drops = pdata.unpack_uint()
        self.input_if = pdata.unpack_uint()
        self.output_if = pdata.unpack_uint()
        self.reason = pdata.unpack_uint()
        self.num_records = pdata.unpack_uint()

        for i in range(self.num_records):
            flow_record = get_sample_record_object(SAMPLE_DATA_FLOW_RECORD,
                                                   pdata.unpack_uint(),
                                                   pdata.unpack_bytes())
            self.flow_records.append(flow_record)

    def pack(self):
        # Need to complete this.
        return

    def __repr__(self):
        repr_ = ('  DiscardedPacket: len: %d, seq: %d, drops: %d, in_if: %d, out_if: %d, reason: %d, records: %d\n' %
                 (self.len,
                  self.sequence_number,
                  self.drops,
                  self.input_if,
                  self.output_if,
                  self.reason,
                  self.num_records))

        for rec in self.flow_records:
            repr_ += repr(rec)

        return repr_


def get_sample_record_object(sample_type, record_type, data):
    '''
        get a object from a records class
        sample_type is Flow Sample or Counter Sample
        record_type is type in one of the sample types
        
        After determining the record type, the basic info is set
        This is the length and record_type
        Then the data of the record is unpacked according to the type
        The unpacked record is returned
    '''
    if sample_type == SAMPLE_DATA_FLOW_RECORD:

        if record_type == FLOW_DATA_RAW_HEADER:
            record = flowdata_record_raw()
        elif record_type == FLOW_DATA_ETHERNET_HEADER:
            record = flowdata_record_ethernet()
        elif record_type == FLOW_DATA_IPV4_HEADER:
            # TODO: import from: read_sampled_ipv4(up_flow_data)
            record = flowdata_record_ipv4()
        elif record_type == FLOW_DATA_IPV6_HEADER:
            # TODO: import from: read_sampled_ipv6(up_flow_data)
            record = flowdata_record_ipv6()
        elif record_type == FLOW_DATA_EXT_SWITCH:
            record = flowdata_record_extswitch()
        else:
            record = sample_record_unknown()
    
    elif sample_type == SAMPLE_DATA_COUNTER_RECORD:
        
        if record_type == COUNTER_DATA_GENERIC:
            record = counter_record_if()
        elif record_type == COUNTER_DATA_ETHERNET:
            record = counter_record_ethernet()
        elif record_type == COUNTER_DATA_TOKENRING:
            # TODO: import from: read_tokenring_counters(up_flow_data)
            record = counter_record_tokenring()
        elif record_type == COUNTER_DATA_VG:
            # TODO: import from: read_vg_counters(up_flow_data)
            record = counter_record_vg()
        elif record_type == COUNTER_DATA_VLAN:
            # TODO: import from: read_vlan_counters(up_flow_data)
            record = counter_record_vlan()
        elif record_type == COUNTER_DATA_IEEE80211:
            # TODO: implement ieee80311 class
            record = counter_record_ieee80211()
        elif record_type == COUNTER_DATA_LAG_PORT:
            record = counter_record_lag()
        elif record_type == COUNTER_DATA_SLOW_PATH:
            # TODO: implement slow_path class
            record = counter_record_slow_path()
        elif record_type == COUNTER_DATA_IB: # InfiniBand
            # TODO: implement infiniband class
            record = counter_record_ib()
        elif record_type == COUNTER_DATA_SFP:
            # TODO: implement SFP class
            record = counter_record_sfp()
        else:
            record = sample_record_unknown()

    else:
        record = sample_record_unknown()

    record.len = len(data)
    record.type = record_type
    record.unpack(data)
    return record


class sample_record_unknown():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        self.data = None
        
    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data
    
    def pack(self):
        return self.data

    
    def __repr__(self):
        return("    RecordUndefined: Undefined record of type: %d, len: %d\n" % (self.type, self.len))


"""
    FlowSample - flow records classes and code/decode functions
    
    each class must have:
    init()
    unpack(data)
    pack()
    __repr__()
    
    # TODO:
    check functions: read_sampled_ipv4

"""
class flowdata_record_raw():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
        # TODO: add sFlow specs of the Raw FlowSample record
    '''
    def __init__(self):
        self.type = FLOW_DATA_RAW_HEADER
        self.len = 0
        self.header_protocol = 0
        self.frame_length = 0
        self.stripped = 0
        self.header = 0
        self.sampled_packet = None
        
    def unpack(self, data):
        self.len = len(data)
        pdata = xdrlib.Unpacker(data)
        self.header_protocol = pdata.unpack_int()
        self.frame_length = pdata.unpack_uint()
        self.stripped = pdata.unpack_uint()
        self.header = pdata.unpack_opaque()
    
        if self.header_protocol == HEADER_PROTO_ETHERNET_ISO88023:
            self.sampled_packet = decode_iso88023(self.header)
        else:
            self.sampled_packet = None

    def pack(self):
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_int(self.header_protocol)
        packdata.pack_uint(self.frame_length)
        packdata.pack_uint(self.stripped)
        packdata.pack_opaque(self.header)
        return packdata.get_buffer()


    def __repr__(self):
        repr_ = ("    RawPacketHeader: type: %d, len: %d, hdr proto: %d, len hdr: %d\n" % 
                 (self.type, self.len, self.header_protocol, len(self.header)))
        if self.sampled_packet != None:
            repr_ += repr(self.sampled_packet)
        return repr_


class flowdata_record_ethernet():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = FLOW_DATA_ETHERNET_HEADER
        self.len = 0
        self.mac_length = 0
        self.src_mac = 0
        self.dst_mac = 0
        self.eth_type = 0

    def unpack(self, data):
        self.len = len(data)
        pdata = xdrlib.Unpacker(data)
        self.mac_length = pdata.unpack_uint()
        self.src_mac = pdata.unpack_fopaque(6)
        self.dst_mac = pdata.unpack_fopaque(6)
        self.eth_type = pdata.unpack_uint()

    def pack(self):
        '''
            Pack data object
        '''
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_uint(self.mac_length)
        packdata.pack_fopaque(6, self.src_mac)
        packdata.pack_fopaque(6, self.dst_mac)
        packdata.pack_uint(self.eth_type)
        return packdata.get_buffer()


    def __repr__(self):
        return("    EthernetPacketHeader: type: %d, len: %d, src_mac: %s, dst_mac: %s, eth_type: %s, mac_len: %d\n" % 
               (self.type, self.len,
                util.mac_to_string(self.src_mac),
                util.mac_to_string(self.dst_mac),
                util.ether_type_to_string(self.eth_type),
                self.mac_length))


class flowdata_record_ipv4():
    '''
        struct sampled_ipv4 {
           unsigned int length;     /* The length of the IP packet excluding 
                                       lower layer encapsulations */
           unsigned int protocol;   /* IP Protocol type
                                       (for example, TCP = 6, UDP = 17) */
           ip_v4 src_ip;            /* Source IP Address */
           ip_v4 dst_ip;            /* Destination IP Address */
           unsigned int src_port;   /* TCP/UDP source port number or equivalent */
           unsigned int dst_port;   /* TCP/UDP destination port number or equivalent */
           unsigned int tcp_flags;  /* TCP flags */
           unsigned int tos;        /* IP type of service */
        }

        not implemented yet
    '''
    def __init__(self):
        self.type = FLOW_DATA_IPV4_HEADER
        self.len = 0
        self.data = None
        
    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data
        return None

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
#        packdata = xdrlib.Packer() # create the packed object
#        packdata.pack_fopaque(len(self.data), self.data)
#        return packdata.get_buffer()
        return self.data

    def __repr__(self):
        return("    IPv4PacketHeader: type: %d, len: %d\n" % (self.type, self.len))

class flowdata_record_ipv6():
    '''
        struct sampled_ipv6 {
           unsigned int length;     /* The length of the IP packet excluding
                                       lower layer encapsulations */
           unsigned int protocol;   /* IP next header
                                       (for example, TCP = 6, UDP = 17) */
           ip_v6 src_ip;            /* Source IP Address */
           ip_v6 dst_ip;            /* Destination IP Address */
           unsigned int src_port;   /* TCP/UDP source port number or equivalent */
           unsigned int dst_port;   /* TCP/UDP destination port number or equivalent */
           unsigned int tcp_flags;  /* TCP flags */
           unsigned int priority;   /* IP priority */
        }
 
        not implemented yet
    '''
    def __init__(self):
        self.type = FLOW_DATA_IPV6_HEADER
        self.len = 0
        self.data = None
        
    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data
        return None

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
#        packdata = xdrlib.Packer() # create the packed object
#        packdata.pack_fopaque(len(self.data), self.data)
#        return packdata.get_buffer()
        return self.data

    def __repr__(self):
        return("    IPv6PacketHeader: type: %d, len: %d\n" % (self.type, self.len))


class flowdata_record_extswitch():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
        struct extended_switch {
           unsigned int src_vlan;     /* The 802.1Q VLAN id of incoming frame */
           unsigned int src_priority; /* The 802.1p priority of incoming frame */
           unsigned int dst_vlan;     /* The 802.1Q VLAN id of outgoing frame */
           unsigned int dst_priority; /* The 802.1p priority of outgoing frame */
        }
    '''
    def __init__(self):
        self.type = FLOW_DATA_EXT_SWITCH
        self.len = 0
        self.src_vlan = 0
        self.src_priority = 0
        self.dst_vlan = 0
        self.dst_priority = 0

    def unpack(self, data):
        self.len = len(data)
        pdata = xdrlib.Unpacker(data)
        self.src_vlan = pdata.unpack_uint()
        self.src_priority = pdata.unpack_uint()
        self.dst_vlan = pdata.unpack_uint()
        self.dst_priority = pdata.unpack_uint()

    def pack(self):
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_uint(self.src_vlan)
        packdata.pack_uint(self.src_priority)
        packdata.pack_uint(self.dst_vlan)
        packdata.pack_uint(self.dst_priority)
        return packdata.get_buffer()

    def __repr__(self):
        return("    ExtSwitchData: type: %d, len: %d, vlan/prio src: %d/%d, dst: %d/%d\n" % 
               (self.type, self.len, self.src_vlan, self.src_priority, self.dst_vlan, self.dst_priority))




"""
    CounterSample - counter records classes and code/decode functions
"""
class counter_record_if():
    '''
        struct if_counters {
           unsigned int ifIndex;
           unsigned int ifType;
           unsigned hyper ifSpeed;
           unsigned int ifDirection;    /* derived from MAU MIB (RFC 2668)
                                           0 = unkown, 1=full-duplex, 2=half-duplex,
                                           3 = in, 4=out */
           unsigned int ifStatus;       /* bit field with the following bits assigned
                                           bit 0 = ifAdminStatus (0 = down, 1 = up)
                                           bit 1 = ifOperStatus (0 = down, 1 = up) */
           unsigned hyper ifInOctets;
           unsigned int ifInUcastPkts;
           unsigned int ifInMulticastPkts;
           unsigned int ifInBroadcastPkts;
           unsigned int ifInDiscards;
           unsigned int ifInErrors;
           unsigned int ifInUnknownProtos;
           unsigned hyper ifOutOctets;
           unsigned int ifOutUcastPkts;
           unsigned int ifOutMulticastPkts;
           unsigned int ifOutBroadcastPkts;
           unsigned int ifOutDiscards;
           unsigned int ifOutErrors;
           unsigned int ifPromiscuousMode;
        }
        
        not implemented yet
    '''

    def __init__(self):
        self.type = COUNTER_DATA_GENERIC
        self.len = 0
        self.data = None

        self.ifIndex = 0
        self.ifType = 0
        self.ifSpeed = 0
        self.ifDirection = 0
        self.ifStatus = 0
        self.ifInOctets = 0
        self.ifInUcastPkts = 0
        self.ifInMulticastPkts = 0
        self.ifInBroadcastPkts = 0
        self.ifInDiscards = 0
        self.ifInErrors = 0
        self.ifInUnknownProtos = 0
        self.ifOutOctets = 0
        self.ifOutUcastPkts = 0
        self.ifOutMulticastPkts = 0
        self.ifOutBroadcastPkts = 0
        self.ifOutDiscards = 0
        self.ouifOutErrorst_errors = 0
        self.ifPromiscuousMode = 0

    def unpack(self, data):
        self.len = len(data)
        pdata = xdrlib.Unpacker(data)
        self.ifIndex = pdata.unpack_uint()
        self.ifType = pdata.unpack_uint()
        self.ifSpeed = pdata.unpack_uhyper()
        self.ifDirection = pdata.unpack_uint()
        self.ifStatus = pdata.unpack_uint()
        self.ifInOctets = pdata.unpack_uhyper()
        self.ifInUcastPkts = pdata.unpack_uint()
        self.ifInMulticastPkts = pdata.unpack_uint()
        self.ifInBroadcastPkts = pdata.unpack_uint()
        self.ifInDiscards = pdata.unpack_uint()
        self.ifInErrors = pdata.unpack_uint()
        self.ifInUnknownProtos = pdata.unpack_uint()
        self.ifOutOctets = pdata.unpack_uhyper()
        self.ifOutUcastPkts = pdata.unpack_uint()
        self.ifOutMulticastPkts = pdata.unpack_uint()
        self.ifOutBroadcastPkts = pdata.unpack_uint()
        self.ifOutDiscards = pdata.unpack_uint()
        self.ouifOutErrorst_errors = pdata.unpack_uint()
        self.ifPromiscuousMode = pdata.unpack_uint()

    def pack(self):
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_uint(self.ifIndex)
        packdata.pack_uint(self.ifType)
        packdata.pack_uhyper(self.ifSpeed)
        packdata.pack_uint(self.ifDirection)
        packdata.pack_uint(self.ifStatus)
        packdata.pack_uhyper(self.ifInOctets)
        packdata.pack_uint(self.ifInUcastPkts)
        packdata.pack_uint(self.ifInMulticastPkts)
        packdata.pack_uint(self.ifInBroadcastPkts)
        packdata.pack_uint(self.ifInDiscards)
        packdata.pack_uint(self.ifInErrors)
        packdata.pack_uint(self.ifInUnknownProtos)
        packdata.pack_uhyper(self.ifOutOctets)
        packdata.pack_uint(self.ifOutUcastPkts)
        packdata.pack_uint(self.ifOutMulticastPkts)
        packdata.pack_uint(self.ifOutBroadcastPkts)
        packdata.pack_uint(self.ifOutDiscards)
        packdata.pack_uint(self.ouifOutErrorst_errors)
        packdata.pack_uint(self.ifPromiscuousMode)
        return packdata.get_buffer()

    def __repr__(self):
        return("    CountersIf: type: %d, len: %d, idx: %d, speed: %s, in_octets: %d, out_octets: %d\n" %
                (self.type, self.len, self.ifIndex,
                 util.speed_to_string(self.ifSpeed), self.ifInOctets, self.ifOutOctets))



class counter_record_ethernet():
    '''
        struct ethernet_counters {
           unsigned int dot3StatsAlignmentErrors;
           unsigned int dot3StatsFCSErrors;
           unsigned int dot3StatsSingleCollisionFrames;
           unsigned int dot3StatsMultipleCollisionFrames;
           unsigned int dot3StatsSQETestErrors;
           unsigned int dot3StatsDeferredTransmissions;
           unsigned int dot3StatsLateCollisions;
           unsigned int dot3StatsExcessiveCollisions;
           unsigned int dot3StatsInternalMacTransmitErrors;
           unsigned int dot3StatsCarrierSenseErrors;
           unsigned int dot3StatsFrameTooLongs;
           unsigned int dot3StatsInternalMacReceiveErrors;
           unsigned int dot3StatsSymbolErrors;
        }
    '''

    def __init__(self):
        self.type = COUNTER_DATA_ETHERNET
        self.len = 0
        self.dot3StatsAlignmentErrors = 0
        self.dot3StatsFCSErrors = 0
        self.dot3StatsSingleCollisionFrames = 0
        self.dot3StatsMultipleCollisionFrames = 0
        self.dot3StatsSQETestErrors = 0
        self.dot3StatsDeferredTransmissions = 0
        self.dot3StatsLateCollisions = 0
        self.dot3StatsExcessiveCollisions = 0
        self.dot3StatsInternalMacTransmitErrors = 0
        self.dot3StatsCarrierSenseErrors = 0
        self.dot3StatsFrameTooLongs = 0
        self.dot3StatsInternalMacReceiveErrors = 0
        self.dot3StatsSymbolErrors = 0


    def unpack(self, data):
        self.len = len(data)
        pdata = xdrlib.Unpacker(data)
        self.dot3StatsAlignmentErrors = pdata.unpack_uint()
        self.dot3StatsFCSErrors = pdata.unpack_uint()
        self.dot3StatsSingleCollisionFrames = pdata.unpack_uint()
        self.dot3StatsMultipleCollisionFrames = pdata.unpack_uint()
        self.dot3StatsSQETestErrors = pdata.unpack_uint()
        self.dot3StatsDeferredTransmissions = pdata.unpack_uint()
        self.dot3StatsLateCollisions = pdata.unpack_uint()
        self.dot3StatsExcessiveCollisions = pdata.unpack_uint()
        self.dot3StatsInternalMacTransmitErrors = pdata.unpack_uint()
        self.dot3StatsCarrierSenseErrors = pdata.unpack_uint()
        self.dot3StatsFrameTooLongs = pdata.unpack_uint()
        self.dot3StatsInternalMacReceiveErrors = pdata.unpack_uint()
        self.dot3StatsSymbolErrors = pdata.unpack_uint()


    def pack(self):
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_uint(self.dot3StatsAlignmentErrors)
        packdata.pack_uint(self.dot3StatsFCSErrors)
        packdata.pack_uint(self.dot3StatsSingleCollisionFrames)
        packdata.pack_uint(self.dot3StatsMultipleCollisionFrames)
        packdata.pack_uint(self.dot3StatsSQETestErrors)
        packdata.pack_uint(self.dot3StatsDeferredTransmissions)
        packdata.pack_uint(self.dot3StatsLateCollisions)
        packdata.pack_uint(self.dot3StatsExcessiveCollisions)
        packdata.pack_uint(self.dot3StatsInternalMacTransmitErrors)
        packdata.pack_uint(self.dot3StatsCarrierSenseErrors)
        packdata.pack_uint(self.dot3StatsFrameTooLongs)
        packdata.pack_uint(self.dot3StatsInternalMacReceiveErrors)
        packdata.pack_uint(self.dot3StatsSymbolErrors)
        return packdata.get_buffer()

    def __repr__(self):
        return("    CountersEthernet: type: %d, len: %d, collisions: %d, carrier sense errors: %d\n" %
               (self.type, self.len, self.dot3StatsSingleCollisionFrames, self.dot3StatsCarrierSenseErrors))


class counter_record_tokenring():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = COUNTER_DATA_TOKENRING
        self.len = 0
        self.data = None

    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
        return self.data
  
    def __repr__(self):
        return("    CountersTokenRing: type: %d, len: %d\n" % (self.type, self.len))


class counter_record_vg():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = COUNTER_DATA_VG
        self.len = 0
        self.data = None

    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
        return self.data
 
    def __repr__(self):
        return("    CountersVG: type: %d, len: %d\n" % (self.type, self.len))


class counter_record_vlan():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = COUNTER_DATA_VLAN
        self.len = 0
        self.data = None

    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
        return self.data
  
    def __repr__(self):
        return("    CountersVLAN: type: %d, len: %d\n" % (self.type, self.len))


class counter_record_ieee80211():
    '''
        Counter IEEE 802.11 structure
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = COUNTER_DATA_IEEE80211
        self.len = 0
        self.data = None

    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
        return self.data
  
    def __repr__(self):
        return("    CountersIEEE80211: type: %d, len: %d\n" % (self.type, self.len))


class counter_record_lag():
    '''
        Counter LAG structure (Link Aggregation Group)

        struct lag_port_stats {
          mac dot3adAggPortActorSystemID;
          mac dot3adAggPortPartnerOperSystemID;
          unsigned int dot3adAggPortAttachedAggID;
          opaque dot3adAggPortState[4]; /*
                                     Bytes are assigned in following order:
                                     byte 0, value dot3adAggPortActorAdminState
                                     byte 1, value dot3adAggPortActorOperState
                                     byte 2, value dot3adAggPortPartnerAdminState
                                     byte 3, value dot3adAggPortPartnerOperState
                                         */
          unsigned int dot3adAggPortStatsLACPDUsRx;
          unsigned int dot3adAggPortStatsMarkerPDUsRx;
          unsigned int dot3adAggPortStatsMarkerResponsePDUsRx;
          unsigned int dot3adAggPortStatsUnknownRx;
          unsigned int dot3adAggPortStatsIllegalRx;
          unsigned int dot3adAggPortStatsLACPDUsTx;
          unsigned int dot3adAggPortStatsMarkerPDUsTx;
          unsigned int dot3adAggPortStatsMarkerResponsePDUsTx;
        }

    '''
    def __init__(self):
        self.type = COUNTER_DATA_LAG_PORT
        self.len = 0
        self.dot3adAggPortActorSystemID = 0
        self.dot3adAggPortPartnerOperSystemID = 0
        self.dot3adAggPortAttachedAggID = 0
        self.dot3adAggPortState = 0
        self.dot3adAggPortStatsLACPDUsRx = 0
        self.dot3adAggPortStatsMarkerPDUsRx = 0
        self.dot3adAggPortStatsMarkerResponsePDUsRx = 0
        self.dot3adAggPortStatsUnknownRx = 0
        self.dot3adAggPortStatsIllegalRx = 0
        self.dot3adAggPortStatsLACPDUsTx = 0
        self.dot3adAggPortStatsMarkerPDUsTx = 0
        self.dot3adAggPortStatsMarkerResponsePDUsTx = 0        

    def unpack(self, data):
        self.len = len(data)
        pdata = xdrlib.Unpacker(data)
        self.dot3adAggPortActorSystemID = pdata.unpack_fopaque(6)
        self.dot3adAggPortPartnerOperSystemID = pdata.unpack_fopaque(6)
        self.dot3adAggPortAttachedAggID = pdata.unpack_uint()
        self.dot3adAggPortState = pdata.unpack_fopaque(4)
        self.dot3adAggPortStatsLACPDUsRx = pdata.unpack_uint()
        self.dot3adAggPortStatsMarkerPDUsRx = pdata.unpack_uint()
        self.dot3adAggPortStatsMarkerResponsePDUsRx = pdata.unpack_uint()
        self.dot3adAggPortStatsUnknownRx = pdata.unpack_uint()
        self.dot3adAggPortStatsIllegalRx = pdata.unpack_uint()
        self.dot3adAggPortStatsLACPDUsTx = pdata.unpack_uint()
        self.dot3adAggPortStatsMarkerPDUsTx = pdata.unpack_uint()
        self.dot3adAggPortStatsMarkerResponsePDUsTx = pdata.unpack_uint()        


    def pack(self):
        packdata = xdrlib.Packer() # create the packed object
        packdata.pack_fopaque(6, self.dot3adAggPortActorSystemID)
        packdata.pack_fopaque(6, self.dot3adAggPortPartnerOperSystemID)
        packdata.pack_uint(self.dot3adAggPortAttachedAggID)
        packdata.pack_fopaque(4, self.dot3adAggPortState)
        packdata.pack_uint(self.dot3adAggPortStatsLACPDUsRx)
        packdata.pack_uint(self.dot3adAggPortStatsMarkerPDUsRx)
        packdata.pack_uint(self.dot3adAggPortStatsMarkerResponsePDUsRx)
        packdata.pack_uint(self.dot3adAggPortStatsUnknownRx)
        packdata.pack_uint(self.dot3adAggPortStatsIllegalRx)
        packdata.pack_uint(self.dot3adAggPortStatsLACPDUsTx)
        packdata.pack_uint(self.dot3adAggPortStatsMarkerPDUsTx)
        packdata.pack_uint(self.dot3adAggPortStatsMarkerResponsePDUsTx)
        return packdata.get_buffer()

  
    def __repr__(self):
        return("    CountersLAG: type: %d, len: %d; Actor: %s, Partner: %s\n      RX: LACP: %d, Marker: %d, MarkerResponse: %d. Unknown: %d, Illegal: %d\n      Tx: LACP: %d, Marker: %d, MarkerResponse: %d\n" % 
               (self.type, self.len, util.mac_to_string(self.dot3adAggPortActorSystemID), util.mac_to_string(self.dot3adAggPortPartnerOperSystemID),
                self.dot3adAggPortStatsLACPDUsRx, self.dot3adAggPortStatsMarkerPDUsRx, self.dot3adAggPortStatsMarkerResponsePDUsRx, self.dot3adAggPortStatsUnknownRx, self.dot3adAggPortStatsIllegalRx,
                self.dot3adAggPortStatsLACPDUsTx, self.dot3adAggPortStatsMarkerPDUsTx, self.dot3adAggPortStatsMarkerResponsePDUsTx))


class counter_record_slow_path():
    '''
        Counter Slow Path structure
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = COUNTER_DATA_SLOW_PATH
        self.len = 0
        self.data = None

    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
        return self.data
  
    def __repr__(self):
        return("    CountersSlowPath: type: %d, len: %d\n" % (self.type, self.len))

 
class counter_record_ib():
    '''
        Counter Infiniband structure
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = COUNTER_DATA_IB
        self.len = 0
        self.data = None

    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
        return self.data
  
    def __repr__(self):
        return("    CountersIB: type: %d, len: %d\n" % (self.type, self.len))


class counter_record_sfp():
    '''
        Counter SFP
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = COUNTER_DATA_SFP
        self.len = 0
        self.data = None

    def unpack(self, data):
        #TODO: implement unpack function
        self.data = data

    def pack(self):
        '''
            Pack data object
            TO BE IMPLEMENTED
        '''
        #TODO: implement pack function
        return self.data
  
    def __repr__(self):
        return("    CountersSFP: type: %d, len: %d\n" % (self.type, self.len))



"""
    Representation helper functions
    ===============================
    
    Raw ethernet / IP / TCP / UDP header classes for sFlow raw flows
"""
class EthernetHeader():
    """Represents an IEEE 802.3 header including its payload."""

    def __init__(self, header):
        self.src = header[0:6]
        self.dst = header[6:12]
        self.ether_type = header[12] * 256 + header[13]
        self.payload = None

    def __repr__(self):
        repr_ = ('      EthernetHeader| src: %s, dst: %s, type: %s\n' %
                (util.mac_to_string(self.src),
                 util.mac_to_string(self.dst),
                 util.ether_type_to_string(self.ether_type)))
        if self.payload:
            repr_ += repr(self.payload)
        return repr_


class IEEE8021QHeader():
    """Represents an IEEE 802.1Q header including its payload."""

    def __init__(self, header):
        self.dst = header[0:6]
        self.src = header[6:12]
        # header[12:14] contains the value 0x8100, indicating that
        # this is not a regular Ethernet frame, but a IEEE 802.1q
        # frame.
        self.vlan_id = header[14] * 256 + header[15]
        self.ether_type = header[16] * 256 + header[17]
        self.payload = None

    def __repr__(self):
        repr_ = ('      IEEE8021QHeader| vlan_id: %d, src: %s, dst: %s, type: %s\n' %
                 (self.vlan_id,
                  util.mac_to_string(self.src),
                  util.mac_to_string(self.dst),
                  util.ether_type_to_string(self.ether_type)))
        if self.payload:
            repr_ += repr(self.payload)
        return repr_



class IPv4Header ():
    """Represents an IPv4 header including the (possibly incomplete)
    payload."""

    def __init__(self, header):
        self.version = (header[0] & 0xf0) >> 4
        self.ihl = header[0] & 0x0f
        self.tos = header[1]
        self.length = header[2] * 256 + header[3]
        self.ident = header[4] * 256 + header[5]
        self.flags = header[6] & 0x07
        self.fragment_offset = ((header[6] & 0xf8) >> 3) * 256 + header[7]
        self.ttl = header[8]
        self.protocol = header[9]
        self.chksum = header[10] * 256 + header[11]
        self.src = ((header[12] << 24) +
                    (header[13] << 16) +
                    (header[14] << 8) +
                    header[15])
        self.dst = ((header[16] << 24) +
                    (header[17] << 16) +
                    (header[18] << 8) +
                    header[19])
        self.payload = None
        if len(header) > 20:
            if self.protocol == 6:
                self.payload = TCPHeader(header[20:])
            elif self.protocol == 17:
                self.payload = UDPHeader(header[20:])

    def __repr__(self):
        repr_ = ('        IPv4Header| src: %s, dst: %s, proto: %s, paylen: %d\n' %
                 (util.ip_to_string(self.src),
                  util.ip_to_string(self.dst),
                  util.ip_proto_to_string(self.protocol),
                  self.length - self.ihl * 4))
        if self.payload != None:
            repr_ += repr(self.payload)
        return repr_


class TCPHeader ():

    def __init__(self, header):
        self.src_port = header[0] * 256 + header[1]
        self.dst_port = header[2] * 256 + header[3]

    def __repr__(self):
        return ('        TCPHeader| src_port: %d, dst_port: %d\n' %
                (self.src_port, self.dst_port))


class UDPHeader ():
    def __init__(self, header):
        self.src_port = header[0] * 256 + header[1]
        self.dst_port = header[2] * 256 + header[3]

    def __repr__(self):
        return ('        UDPHeader| src_port: %d, dst_port: %d\n' %
                (self.src_port, self.dst_port))


"""
    Defined functions - not in a rubric yet - need to be imported into the right
    sample record class
    # TODO: import functions inro classes
"""


def decode_sflow_data_source(sflow_data_source):
    """Decodes a sflow_data_source as described in the sFlow v5
    spec."""
    # source type should be one of
    #   0 = ifIndex
    #   1 = smonVlanDataSource
    #   2 = entPhysicalEntry

    source_type = sflow_data_source >> 24
    value = sflow_data_source & 0xfff

    return (source_type, value)


def decode_iso88023(header):
    # Full ethernet header included?
    if len(header) >= 14:
        ether_type = header[12] * 256 + header[13]        
        if ether_type == ETHER_TYPE_IEEE8021Q:
            h = IEEE8021QHeader(header)
            # 18 + 20 = <bytes read so far> + <minimal IP header length>
            if len(header) >= 18 + 20:
                h.payload = IPv4Header(header[18:])
            return h
        else:
            h = EthernetHeader(header)
            if len(header) >= 14 + 20:
                h.payload = IPv4Header(header[14:])
            return h

    

def read_sampled_ipv4(up, sample_datagram):

    # Unpack Packet IP version 4 data
    #     unsigned int length;
    #         The length of the IP packet excluding lower layer encapsulations
    #     unsigned int protocol;
    #         IP Protocol type (for example, TCP = 6, UDP = 17)
    #     ip_v4 src_ip;            Source IP Address
    #     ip_v4 dst_ip;            Destination IP Address
    #     unsigned int src_port;   TCP/UDP source port number or equivalent
    #     unsigned int dst_port;   TCP/UDP destination port number or equivalent
    #     unsigned int tcp_flags;  TCP flags
    #     unsigned int tos;        IP type of service

    # Unpack fields
    length = up.unpack_uint()
    protocol = up.unpack_uint()
    src_ip = up.unpack_fopaque(4)
    dst_ip = up.unpack_fopaque(4)
    src_port = up.unpack_uint()
    dst_port = up.unpack_uint()
    tcp_flags = up.unpack_uint()
    tos = up.unpack_uint()

    return None



def read_tokenring_counters(up):

    # Unpack tokenring_counters structure
    #     unsigned int dot5StatsLineErrors;
    #     unsigned int dot5StatsBurstErrors;
    #     unsigned int dot5StatsACErrors;
    #     unsigned int dot5StatsAbortTransErrors;
    #     unsigned int dot5StatsInternalErrors;
    #     unsigned int dot5StatsLostFrameErrors;
    #     unsigned int dot5StatsReceiveCongestions;
    #     unsigned int dot5StatsFrameCopiedErrors;
    #     unsigned int dot5StatsTokenErrors;
    #     unsigned int dot5StatsSoftErrors;
    #     unsigned int dot5StatsHardErrors;
    #     unsigned int dot5StatsSignalLoss;
    #     unsigned int dot5StatsTransmitBeacons;
    #     unsigned int dot5StatsRecoverys;
    #     unsigned int dot5StatsLobeWires;
    #     unsigned int dot5StatsRemoves;
    #     unsigned int dot5StatsSingles;
    #     unsigned int dot5StatsFreqErrors;

    dot5StatsLineErrors = up.unpack_uint()
    dot5StatsBurstErrors = up.unpack_uint()
    dot5StatsACErrors = up.unpack_uint()
    dot5StatsAbortTransErrors = up.unpack_uint()
    dot5StatsInternalErrors = up.unpack_uint()
    dot5StatsLostFrameErrors = up.unpack_uint()
    dot5StatsReceiveCongestions = up.unpack_uint()
    dot5StatsFrameCopiedErrors = up.unpack_uint()
    dot5StatsTokenErrors = up.unpack_uint()
    dot5StatsSoftErrors = up.unpack_uint()
    dot5StatsHardErrors = up.unpack_uint()
    dot5StatsSignalLoss = up.unpack_uint()
    dot5StatsTransmitBeacons = up.unpack_uint()
    dot5StatsRecoverys = up.unpack_uint()
    dot5StatsLobeWires = up.unpack_uint()
    dot5StatsRemoves = up.unpack_uint()
    dot5StatsSingles = up.unpack_uint()
    dot5StatsFreqErrors = up.unpack_uint()

    return None


def read_vg_counters(up):

    # Unpack 100 BaseVG interface counters
    #     unsigned int dot12InHighPriorityFrames;
    #     unsigned hyper dot12InHighPriorityOctets;
    #     unsigned int dot12InNormPriorityFrames;
    #     unsigned hyper dot12InNormPriorityOctets;
    #     unsigned int dot12InIPMErrors;
    #     unsigned int dot12InOversizeFrameErrors;
    #     unsigned int dot12InDataErrors;
    #     unsigned int dot12InNullAddressedFrames;
    #     unsigned int dot12OutHighPriorityFrames;
    #     unsigned hyper dot12OutHighPriorityOctets;
    #     unsigned int dot12TransitionIntoTrainings;
    #     unsigned hyper dot12HCInHighPriorityOctets;
    #     unsigned hyper dot12HCInNormPriorityOctets;
    #     unsigned hyper dot12HCOutHighPriorityOctets;

    dot12InHighPriorityFrames = up.unpack_uint()
    dot12InHighPriorityOctets = up.unpack_uhyper()
    dot12InNormPriorityFrames = up.unpack_uint()
    dot12InNormPriorityOctets = up.unpack_uhyper()
    dot12InIPMErrors = up.unpack_uint()
    dot12InOversizeFrameErrors = up.unpack_uint()
    dot12InDataErrors = up.unpack_uint()
    dot12InNullAddressedFrames = up.unpack_uint()
    dot12OutHighPriorityFrames = up.unpack_uint()
    dot12OutHighPriorityOctets = up.unpack_uhyper()
    dot12TransitionIntoTrainings = up.unpack_uint()
    dot12HCInHighPriorityOctets = up.unpack_uhyper()
    dot12HCInNormPriorityOctets = up.unpack_uhyper()
    dot12HCOutHighPriorityOctets = up.unpack_uhyper()

    return None


def read_vlan_counters(up):

    # Unpack VLAN counters
    #     unsigned int vlan_id;
    #     unsigned hyper octets;
    #     unsigned int ucastPkts;
    #     unsigned int multicastPkts;
    #     unsigned int broadcastPkts;
    #     unsigned int discards;

    vlan_id = up.unpack_uint()
    octets = up.unpack_uhyper()
    ucastPkts = up.unpack_uint()
    multicastPkts = up.unpack_uint()
    broadcastPkts = up.unpack_uint()
    discards = up.unpack_uint()

    return None

