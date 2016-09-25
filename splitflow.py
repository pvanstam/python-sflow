#!/usr/bin/env python2

# =============================================================================
# splitflow - receives Netflow v5 flows and retransmits them to various
#             targets based on the destination IP or ASN
#
# Written by Teun Vink - teun@bit.nl
#
# Version $Id: splitflow 1915 2014-11-14 09:39:42Z teun $
#
# Sources used:
# http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
# http://blog.devicenull.org/2013/09/04/python-netflow-v5-parser.html
# =============================================================================



# =============================================================================
# Imports
# =============================================================================

import socket, struct, sys, ConfigParser, threading, Queue, time
from syslog import openlog, syslog, LOG_CRIT, LOG_WARNING, LOG_INFO

try:
    import ipaddr
except:
    sys.stderr.write("ERROR: Python ipaddr package not found. Please install it.\n\n");
    sys.exit(1)


# =============================================================================
# Constants and global variables
# =============================================================================

CONFIG_FILE = "/server/splitflow/splitflow.conf" # config file
HSIZE       = 24  # size of the netflow header
RSIZE       = 48  # size of a netflow record
config      = {}


# =============================================================================
# Classes
# =============================================================================

class FlowThread(threading.Thread):
    """
        A thread which polls a given queue and transmits received netflow data
        to a specified target host.
    """

    def __init__(self, target, host, port, queue):
        self.queue  = queue
        self.target = target
        self.host   = host
        self.port   = int(port)
        self.count  = 0
        threading.Thread.__init__(self)
        log("   - Thread %s started, destination host %s, port %s" % (target, host, port), LOG_INFO)


    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except:
            log("ERROR: can't create socket", LOG_ERR)
            sys.exit(1)

        while True:
            # now let's change the header:
            # modify count and flow_sequence so it makes sense for the receiver
            (header, data) = self.queue.get()
            hdata = struct.unpack("!HHIIIIBBH", header)
            hdr = struct.pack("!HHIIIIBBH", hdata[0], len(data), hdata[2], hdata[3], hdata[4], count, hdata[6], hdata[7], hdata[8])

            sock.sendto("%s%s" % (hdr, "".join(data)), (self.host, self.port))
            self.count += len(data)

            self.queue.task_done()


# =============================================================================
# Functions
# =============================================================================

def log(msg, level=LOG_INFO):
    """
        Write a message to log and to console
    """
    syslog(level, msg)
    if level == LOG_INFO:
        print msg
    else:
        sys.stderr.write("%s\n" % msg)


def pprint(num):
    """
        Pretty print a number
    """
    pfx = ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
    if num == 0:
        return num
    while (num > 1000 and len(pfx) > 1):
        num = num / 1000.0
        pfx = pfx[1:]

    if pfx[0] == "":
        return "%d" % num
    else:
        return "%.1f%s" % (num, pfx[0])



def readconfig():
    """
        Read and parse the configuration file
    """
    try:
        conf = ConfigParser.ConfigParser()
        conf.read(CONFIG_FILE)
    except:
        log("Failed to read config file '%s'." % CONFIG_FILE, LOG_ERR)
        sys.exit(1)


    config     = {}
    prefixlist = {}
    aslist     = {}
    targets    = {}
    sections   = conf.sections()

    for section in sections:
        prefixes = []
        asns = []
        for option in conf.options(section):
            if not config.has_key(section):
                config[section] = {}
            config[section][option] = conf.get(section, option)

            # split lists of prefixes
            if option == "prefixes":
                plist = [p.strip() for p in conf.get(section, option).split(",")]
                for prefix in plist:
                    try:
                        pfx = ipaddr.IPv4Network(prefix)
                        prefixes.append(pfx)
                    except:
                        log(" ! WARNING: Invalid prefix in section '%s': %s, skipping it." % (section, prefix), LOG_WARNING)

            # split lists of asnumbers
            if option == "asn":
                ases = [a.strip() for a in conf.get(section, option).split(",")]
                for asn in ases:
                    try:
                        asns.append(int(asn))
                    except:
                        log(" ! WARNING: Invalid ASN in section '%s': %s, skipping it." % (section, asn), LOG_WARNING)

        # check if we have a host and port to send flows to if this is a target
        if section != 'General':
            if not "host" in config[section].keys():
                log(" ! WARNING: No destination host found in section '%s', skipping it." % section, LOG_WARNING)
            elif not "port" in config[section].keys():
                log(" ! WARNING: No destination port found in section '%s'm skipping it." % section, LOG_WARNING)
            else:
                targets[section] = (config[section]["host"], config[section]["port"])
            if len(prefixes) == 0 and len(asns) == 0:
                log("WARNING: No prefixes and ASNs found in section '%s'." % section, LOG_WARNING)

            prefixlist[section] = prefixes
            aslist[section] = asns
            log("   - read %d prefixes and %d ASNs for %s" % (len(prefixes), len(asns), section))

    return (config, prefixlist, aslist, targets)



# ==============================================================================
# Main
# ==============================================================================

if __name__ == "__main__":

    # start syslog
    try:
        openlog("splitflow")
    except:
        sys.stderr.write("WARNING: Can't open syslog")


    # read the config file
    log("splitflow - split netflow based on destination address - Written by Teun Vink - teun@bit.nl")
    log(" * Reading configuration from %s" % CONFIG_FILE)
    (config, prefixlist, asnlist, targets) = readconfig()

    # try to start up the listener
    try:
        host = config["General"]["listen"]
        port = int(config["General"]["port"])
    except:
        log("ERROR: No host and/or port to bind to configured in the configfile.", LOG_CRIT)
        sys.exit(1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
    except:
        print e
        log("ERROR: failed to bind to %s port %s." % (host, port), LOG_CRIT)
        sys.exit(1)

    log(" * Opening receive socket on address %s, port %s" % (host, port))

    # create a queue and thread for each target
    log(" * Creating sender threads and queues")
    threads = {}
    queues  = {}
    newq    = {}
    stats   = {}
    stats["records"] = 0
    stats["datagrams"] = 0
    for target in targets.keys():
        queues[target] = Queue.Queue()
        threads[target] = FlowThread(target, targets[target][0], targets[target][1], queues[target])
        threads[target].setDaemon(True)
        threads[target].start()

    log(" * Ready to receive netflow data")

    tstamp = time.time()

    # main loop for receiving flows starts here
    while True:
        buf, addr = sock.recvfrom(1500)

        # check the Netflow version and number of flows
        (version, count) = struct.unpack('!HH',buf[0:4])
        if version != 5:
            log("WARNING: Received datagram is not NetFlow v5! Can't process it.\n", LOG_WARNING)
            continue

        stats["records"] += count
        stats["datagrams"] += 1

        # create a new temporary output queue for each target
        # use a map to enforce uniqueness
        for target in targets.keys():
            newq[target] = {}

        # read every record in the netflow data
        for i in range(0, count):
            try:
                base = HSIZE+(i*RSIZE)
                dst_asn = struct.unpack('!H',buf[base+42:base+44])[0]

                # check if this flow record matches based on the dst ASN
                match = 0
                for target in asnlist.keys():
                    for asn in asnlist[target]:
                        if asn == dst_asn:
                            newq[target][i] = 1
                            stats[target] = stats.get(target,0) + 1
                            match = 1

                # check if this flow record matches based on the destination IP
                if not match or config.get("CheckASNandPrefix", 1) == 1:
                    dst_ip = socket.inet_ntoa(buf[base+4:base+8])
                    ip = ipaddr.IPv4Address(dst_ip)
                    for target in prefixlist.keys():
                        for prefix in prefixlist[target]:
                            if ip in prefix:
                                newq[target][i] = 1
                                stats[target] = stats.get(target, 0) + 1


            except Exception, e:
                continue

        # now push all temp queues to threaded queues for redistribution
        for t in newq.keys():
            if len(newq[t]) > 0:
                outq = []
                for item in newq[t].keys():
                    base = HSIZE+(item*RSIZE)
                    outq.append(buf[base:base+RSIZE])
                queues[t].put((buf[0:24],outq))

        # print statistics every 1000 rounds
        if stats["datagrams"] % 1000 == 0:
            delta = int(time.time()-tstamp)
            stat = " records, ".join( ["%s: %s" % (target, pprint(stats.get(target,0))) for target in targets.keys() ] )
            log("[%s] datagrams received: %s, records received: %s in %d seconds, %s records" % (time.strftime('%H:%M:%S'),
                pprint(stats["datagrams"]), pprint(stats["records"]), delta, stat))
