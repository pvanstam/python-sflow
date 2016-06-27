'''
Created on 27 jun. 2016

@author: pim
'''
import socket
import sys

try:
    import sflow
    import util
except:
    from sflow import sflow
    from sflow import util


def show_num_records(s_records):
    for sample in s_records:
        if sample.sample_type == 1:
            return("    FlowSample: %d records\n" % sample.num_flow_records)
        elif sample.sample_type == 2:
            return("    CountersSample: %d records\n" % sample.num_counter_records)

def repr_flow(flow_datagram):
#    print(repr(flow_datagram))
    return repr(flow_datagram)


def show_ipv4_addr(flow_datagram):
    """
        get from the flow records, the IPv4 src and dst IP addresses
        from raw Flow sample records
    """
    retstr = "\nFlow: %d (%d samples)\n" % (flow_datagram.sequence_number, flow_datagram.num_samples)
    n = 1
    for sample in flow_datagram.sample_records:
        m=1
        if sample.sample_type == 1: # FlowSample
            for rec in sample.flow_records:
                if rec.type == sflow.FLOW_DATA_RAW_HEADER:
                    retstr += "  Raw FlowSample %d(%d).%d (proto %d)\n" % (n, sample.num_flow_records, m, rec.header_protocol)
                    m += 1
                    pkt = rec.sampled_packet
                    if pkt != None:
                        payl = pkt.payload
                        if payl != None:
                            retstr += "    src: %s; dst: %s\n" % (util.ip_to_string(payl.src), util.ip_to_string(payl.dst))
            n += 1
    return retstr



if __name__ == '__main__':
    listen_addr = ("0.0.0.0", 5700)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(listen_addr)

    while True:
        data, addr = sock.recvfrom(65535)
        flow_data = sflow.Datagram()
        flow_data.unpack(addr, data)

        # Test 1
        #print("Flow: %d (%d samples)" % (flow_data.sequence_number, flow_data.num_samples))
        #sys.stdout.write(show_num_records(flow_data.sample_records))

        # Test 2
        sys.stdout.write(repr_flow(flow_data))

        # Test 3
        #sys.stdout.write(show_ipv4_addr(flow_data))

