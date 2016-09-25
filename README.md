# python-sflow
Python library for decoding (unpck) and encoding (pack) sFlow data

sFlow data is stored in classes.
Each sFlow IP datagram can contain multiple sample records. sFlow defines two Sample types, e.g.:
* FlowSample (packet header)
* CounterSample (devices counter)

A FlowSample or CounterSample record can contain multiple flows or counters within it.
A FlowSample can contain multiple samples of IP headers of multiple sampled packets. The samples can be of different types and different sources/destinations. Types like ethernet header, vlan header, ipv4 header, etc.

Counters can be types like interface counters and ethernet counters.

Basic usage:
import sflow
flow_data = sflow.Datagram()
flow_data.unpack(addr, data)
sys.stdout.write(repr(flow_data))
data = flow_data.pack()


In examples/splisflow.py
Sample application for splitting sFlow Sample records based on the destination IP prefix. Sent splitted sFlow records to the destination collector defined per AS number. This ASnumber is the BGP destination of the destination of the IP address in the flow sample.

 