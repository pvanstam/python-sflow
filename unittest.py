'''
Created on 27 jun. 2016

@author: pim
'''
import socket
import sflow

def show_num_records(s_records):
    for sample in s_records:
        if sample.sample_type == 1:
            print("    FlowSample: %d records" % sample.num_flow_records)
            recs = sample.flow_records
        elif sample.sample_type == 2:
            print("    CountersSample: %d records" % sample.num_counter_records)

def repr_flow(flow_datagram):
    return repr(flow_datagram)


if __name__ == '__main__':
    listen_addr = ("0.0.0.0", 5700)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(listen_addr)

    while True:
        data, addr = sock.recvfrom(65535)
        flow_data = sflow.Datagram()
        flow_data.unpack(addr, data)

        # Test 1
        # print("Flow: %d (%d samples)" % (flow_data.sequence_number, flow_data.num_samples))
        #show_num_records(flow_data.sample_records)

        # Test 2
        print(repr_flow)
        