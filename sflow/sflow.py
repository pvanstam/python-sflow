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
    
    original source: https://github.com/kok/pyflow
    Kai Kaminski 
    
    @author: Pim van Stam <pim@svsnet.nl>
    
    
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
"""
__version__ = "0.01"
__modified__ = "27-06-2016"

import sys
import xdrlib
import socket
import math

try:
    import util
except:
    from sflow import util


# Constants for the sample_data member of 'struct sample_record'
# (p. 32).  See pp. 29-31 for the meaning of these values.
SAMPLE_DATA_FLOW_RECORD = 1
SAMPLE_DATA_COUNTER_RECORD = 2


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
            self.agent_address = socket.ntohl(up.unpack_uint())
        else:
            # IPv6 not supported yet
            raise Exception()
            return False
        
        self.sub_agent_id = up.unpack_uint()
        self.sequence_number = up.unpack_uint()
        self.uptime = up.unpack_uint()
        self.num_samples = up.unpack_uint()

        # Iterating over sample records
        for i in range(self.num_samples):
            sample_type = up.unpack_uint()
            sample = get_sample_object(sample_type)
            
            data = up.unpack_bytes()
            sample.len = len(data)
            sample.unpack(xdrlib.Unpacker(data))
            self.sample_records.append(sample)
            
        # we should be ready now
        #up.done()


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
    '''
        return object of a sFlow sample class
    '''
    if sample_type == SAMPLE_DATA_FLOW_RECORD:
        return FlowSample()
    elif sample_type == SAMPLE_DATA_COUNTER_RECORD:
        return CounterSample()
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
        self.sequence_number = data.unpack_uint()
        self.source_id = data.unpack_uint()
        self.sampling_rate = data.unpack_uint()
        self.sample_pool = data.unpack_uint()
        self.drops = data.unpack_uint()
        self.input_if = data.unpack_uint()
        self.output_if = data.unpack_uint()
        self.num_flow_records = data.unpack_uint()

        for i in range(self.num_flow_records):
            flow_record = get_sample_record_object(SAMPLE_DATA_FLOW_RECORD, 
                                                  data.unpack_uint(),
                                                  data.unpack_bytes())            
            self.flow_records.append(flow_record)

        
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
        self.sequence_number = data.unpack_uint()
        self.source_id = data.unpack_uint()
        self.num_counter_records = data.unpack_uint()
        
        for i in range(self.num_counter_records):
            cnt_record = get_sample_record_object(SAMPLE_DATA_COUNTER_RECORD, 
                                                  data.unpack_uint(),
                                                  data.unpack_bytes())
            self.counter_records.append(cnt_record)


    def __repr__(self):
        repr_ = ('  CounterSample: len: %d, seq: %d, srcid: %d, cntrs: %d\n' % 
                 (self.len,
                  self.sequence_number,
                  self.source_id,
                  self.num_counter_records))
        for rec in self.counter_records:
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
        elif record_type == FLOW_DATA_EXT_SWITCH:
            record = flowdata_record_extswitch()
        else:
            record = sample_record_unknown()
    
    elif sample_type == SAMPLE_DATA_COUNTER_RECORD:
        
        if record_type == COUNTER_DATA_GENERIC:
            # TODO: import from: read_if_counters(up_counter_data)
            record = counter_record_if()
        elif record_type == COUNTER_DATA_ETHERNET:
            # TODO: import from: read_ethernet_counters(up_flow_data)
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
        else:
            record = sample_record_unknown()

    else:
        record = sample_record_unknown()

    record.len = len(data)
    record.type = record_type
    record.unpack(xdrlib.Unpacker(data))
    return record


class sample_record_unknown():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        self.data = data
    
    def __repr__(self):
        return("    RecordUndefined: Undefined record of type: %d, len: %d\n" % (self.type, self.len))


"""
    FlowSample - flow records classes and code/decode functions
    
    check functions: read_sampled_xxx

"""
class flowdata_record_raw():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
        # TODO: add sFlow specs of the Raw FlowSample record
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        self.header_protocol = 0
        self.frame_length = 0
        self.stripped = 0
        self.header = 0
        self.sampled_packet = None
        
    def unpack(self, data):
        self.header_protocol = data.unpack_int()
        self.frame_length = data.unpack_uint()
        self.stripped = data.unpack_uint()
        self.header = data.unpack_opaque()
    
        if self.header_protocol == HEADER_PROTO_ETHERNET_ISO88023:
            self.sampled_packet = decode_iso88023(self.header)
        else:
            self.sampled_packet = None

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
        self.type = 0
        self.len = 0
        self.mac_length = 0
        self.src_mac = 0
        self.dst_mac = 0
        self.eth_type = 0

    def unpack(self, data):
        self.mac_length = data.unpack_uint()
        self.src_mac = data.unpack_fopaque(6)
        self.dst_mac = data.unpack_fopaque(6)
        self.eth_type = data.unpack_uint()
    
    def __repr__(self):
        return("    EthernetPacketHeader: type: %d, len: %d, src_mac: %s, dst_mac: %s, eth_type: %s, mac_len: %d\n" % 
               (self.type, self.len,
                util.mac_to_string(self.src_mac),
                util.mac_to_string(self.dst_mac),
                util.ether_type_to_string(self.eth_type),
                self.mac_length))


class flowdata_record_ipv4():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        return None
    
    def __repr__(self):
        return("    IPv4PacketHeader: type: %d, len: %d\n" % (self.type, self.len))


class flowdata_record_extswitch():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        self.data = data
    
    def __repr__(self):
        return("    ExtSwitchData: type: %d, len: %d\n" % (self.type, self.len))




"""
    CounterSample - counter records classes and code/decode functions
"""
class counter_record_if():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        self.data = data
    
    def __repr__(self):
        return("    CountersIf: type: %d, len: %d\n" % (self.type, self.len))




class counter_record_ethernet():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        self.data = data
    
    def __repr__(self):
        return("    CountersEthernet: type: %d, len: %d\n" % (self.type, self.len))

class counter_record_tokenring():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        self.data = data
    
    def __repr__(self):
        return("    CountersTokenRing: type: %d, len: %d\n" % (self.type, self.len))

class counter_record_vg():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        self.data = data
    
    def __repr__(self):
        return("    CountersVG: type: %d, len: %d\n" % (self.type, self.len))


class counter_record_vlan():
    '''
        not defined sample record in  Flow or Counter samples
        class is most simple form of a sample record object
    '''
    def __init__(self):
        self.type = 0
        self.len = 0
        
    def unpack(self, data):
        self.data = data
    
    def __repr__(self):
        return("    CountersVLAN: type: %d, len: %d\n" % (self.type, self.len))





"""
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
        self.src = ((header[15] << 24) +
                    (header[14] << 16) +
                    (header[13] << 8) +
                    header[12])
        self.dst = ((header[19] << 24) +
                    (header[18] << 16) +
                    (header[17] << 8) +
                    header[16])
        self.payload = None
        if len(header) > 20:
            if self.protocol == 6:
                self.payload = TCPHeader(header[20:])
            elif self.protocol == 17:
                self.payload = UDPHeader(header[20:])

    def __repr__(self):
        repr_ = ('        IPv4Header| src: %s, dst: %s, proto: %s paylen: %d\n' %
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


class CounterRecord ():
    def __init__(self, counter_sample, data):
        self.counter_sample = counter_sample
        self.data = data

    def __repr__(self):
        return ('<CounterRecord>\n  %s\n  %s' %
                (repr(self.counter_sample),
                 repr(self.data)))




class IfCounters ():
    def __init__(self, up):
        self.index = up.unpack_uint()
        self.if_type = up.unpack_uint()
        self.speed = up.unpack_uhyper()
        self.direction = up.unpack_uint()
        self.status = up.unpack_uint()
        self.in_octets = up.unpack_uhyper()
        self.in_ucasts = up.unpack_uint()
        self.in_mcasts = up.unpack_uint()
        self.in_bcasts = up.unpack_uint()
        self.in_discards = up.unpack_uint()
        self.in_errors = up.unpack_uint()
        self.in_unknown_protos = up.unpack_uint()
        self.out_octets = up.unpack_uhyper()
        self.out_ucasts = up.unpack_uint()
        self.out_mcasts = up.unpack_uint()
        self.out_bcasts = up.unpack_uint()
        self.out_discards = up.unpack_uint()
        self.out_errors = up.unpack_uint()
        self.promiscuous_mode = up.unpack_uint()

    def __repr__(self):
        return ('<IfCounters| idx: %d, speed: %s, in_octets: %d, out_octets: %d>' %
                (self.index,
                 util.speed_to_string(self.speed),
                 self.in_octets,
                 self.out_octets))


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



def read_if_counters(up):

    # Unpack Generic Interface Counters
    #     unsigned int ifIndex;
    #     unsigned int ifType;
    #     unsigned hyper ifSpeed;
    #     unsigned int ifDirection;      derived from MAU MIB (RFC 2668)
    #                                    0 = unkown, 1=full-duplex, 2=half-duplex,
    #                                    3 = in, 4=out
    #     unsigned int ifStatus;         bit field with the following bits assigned
    #                                    bit 0 = ifAdminStatus (0 = down, 1 = up)
    #                                    bit 1 = ifOperStatus (0 = down, 1 = up)
    #     unsigned hyper ifInOctets;
    #     unsigned int ifInUcastPkts;
    #     unsigned int ifInMulticastPkts;
    #     unsigned int ifInBroadcastPkts;
    #     unsigned int ifInDiscards;
    #     unsigned int ifInErrors;
    #     unsigned int ifInUnknownProtos;
    #     unsigned hyper ifOutOctets;
    #     unsigned int ifOutUcastPkts;
    #     unsigned int ifOutMulticastPkts;
    #     unsigned int ifOutBroadcastPkts;
    #     unsigned int ifOutDiscards;
    #     unsigned int ifOutErrors;
    #     unsigned int ifPromiscuousMode;
    
    return IfCounters(up)
    

def read_ethernet_counters(up):

    # Unpack ethernet_counters structure
    #      unsigned int dot3StatsAlignmentErrors;
    #      unsigned int dot3StatsFCSErrors;
    #      unsigned int dot3StatsSingleCollisionFrames;
    #      unsigned int dot3StatsMultipleCollisionFrames;
    #      unsigned int dot3StatsSQETestErrors;
    #      unsigned int dot3StatsDeferredTransmissions;
    #      unsigned int dot3StatsLateCollisions;
    #      unsigned int dot3StatsExcessiveCollisions;
    #      unsigned int dot3StatsInternalMacTransmitErrors;
    #      unsigned int dot3StatsCarrierSenseErrors;
    #      unsigned int dot3StatsFrameTooLongs;
    #      unsigned int dot3StatsInternalMacReceiveErrors;
    #      unsigned int dot3StatsSymbolErrors;

    dot3StatsAlignmentErrors = up.unpack_uint()
    dot3StatsFCSErrors = up.unpack_uint()
    dot3StatsSingleCollisionFrames = up.unpack_uint()
    dot3StatsMultipleCollisionFrames = up.unpack_uint()
    dot3StatsSQETestErrors = up.unpack_uint()
    dot3StatsDeferredTransmissions = up.unpack_uint()
    dot3StatsLateCollisions = up.unpack_uint()
    dot3StatsExcessiveCollisions = up.unpack_uint()
    dot3StatsInternalMacTransmitErrors = up.unpack_uint()
    dot3StatsCarrierSenseErrors = up.unpack_uint()
    dot3StatsFrameTooLongs = up.unpack_uint()
    dot3StatsInternalMacReceiveErrors = up.unpack_uint()
    dot3StatsSymbolErrors = up.unpack_uint()

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



