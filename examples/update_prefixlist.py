'''
    update_prefixlist - update the prefixlist file with updates from message bus
    using nawasmq to get BGP updates (advertisements/withdraws)
    
    @author: Pim van Stam <pim@svsnet.nl>
    Created on 25 Apr 2019

    The MIT License (MIT)

    Copyright (c) 2019 - Pim van Stam <pim@svsnet.nl>
    
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
__version__="0.1"
import os
import configparser
import argparse
import daemon
import nawasmq

d_prefix = {} # consists of d_prefix[prefix]=asn)

# =============================================================================
# Configuration items
# =============================================================================

config = {'configfile'    : '/etc/splitsflow.conf',
          'loglevel'      : 'info',
          'prefixlist'    : 'bgp_prefixes.txt',
          'logfile'       : '/var/log/update_prefix.log',
          'outfile'       : '/var/log/update_prefix.err',
         }

# =============================================================================
# End of configuration
# =============================================================================

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


def read_prefixlist():
    """
        Read the prefixlist and stotr in the memory object list
    """
    global d_prefix
    
    try:
        with open(config['prefixlist'], "r") as fp:
            prefixdata = fp.readlines()
    except:
        print("cannot read the prefixlist file")
        return
    
    for line in prefixdata:
        items = line[:-1].split()
        if len(items) == 3:
            d_prefix[items[0]] = items[1]


def write_prefixlist():
    """
        Write the prefixlist to fn from the memory object list
        the prefixlist is: IP network, netmask, ID (i.e. AS-number)
        Output is the stored prefix list in format:
        prefix/netmask    ASnumber    next-hop
        
        Next-hop is not known, written as 1.2.3.4
    """

    try:
        fp = open(config['prefixlist'], "w")
    except:
        print("cannot create prefixlist file")
        return
    
    for key in sorted(d_prefix.keys()):
        fp.write(key + "\t" + d_prefix[key] + "\t1.2.3.4\n")                    
    fp.close()
  
# TODO: signal splitsflow process  


def callback_prefix_updates(message:nawasmq.PrefixMessage):
    '''
        Callback routine for the AMQP messages
        Receive messages and print on screen.
    '''
    msg = message.get_message()
    print(msg['type'] + " " + msg['prefix'] + " by " + msg['asn'])
    try:
        if msg['type'] == 'announce':
            d_prefix[msg['prefix']] = msg['asn']
        elif msg['type'] == 'withdraw':
            del d_prefix[msg['prefix']]
        else:
            print("unknown message type: " + msg['type'])
            return
    except:
        print("exception occurred")

#TODO: put write into a new thread
    write_prefixlist()


def mainroutine():
    read_prefixlist()
    lstnr = nawasmq.Listener("config.yml")
    lstnr.listen(nawasmq.PrefixMessage, callback_prefix_updates)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Update prefixlist from message bus prefix advertisements or withdraws")
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


