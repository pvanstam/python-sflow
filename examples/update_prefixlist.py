'''
    update_prefixlist - update the prefixlist file with updates from message bus
    using nawasmq to get BGP updates (advertisements/withdraws)
    
    @author: Pim van Stam <pim@svsnet.nl>
    Created on 25 Apr 2019

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

import nawasmq

def write_prefixlist(fn):
    """
        Write the prefixlist to fn from the memory object list
        the prefixlist is: IP network, netmask, ID (i.e. AS-number)
        Output is the stored prefix list in format:
        prefix/netmask    ASnumber    next-hop
        
        Next-hop is not known, written as 1.2.3.4
    """
    global prefix_list

    fp = open(fn, "w")
    for netaddr, netmask, asn in prefix_list:
        fp.write(netaddr + "/" + netmask + "\t" + asn + "\t1.2.3.4")                    
    fp.close()



if __name__ == '__main__':
    pass