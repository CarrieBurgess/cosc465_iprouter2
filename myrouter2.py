#!/usr/bin/env python
#Brett and Carrie
#project 04

'''
Basic IPv4 router (static routing) in Python, stage 1.
'''

import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp
from pox.lib.addresses import EthAddr,IPAddr, netmask_to_cidr
from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger

#to do: build static forwarding table, forward packets appropriately, make ARP requests
#for other hosts to get their MAC address (so basically the flip side of part 1 of this
#project)

class Router(object):
    def __init__(self, net):
        self.net = net

    def router_main(self):    
        while True:
            try:
                dev,ts,pkt = self.net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                # log_debug("Timeout waiting for packets")
                continue
            except SrpyShutdown:
                return
            #part 2: building forwarding table
            forwarding_table = []
            neighbors = [] #seperate for now to use in packet ARP replies
            for intf in self.net.interfaces(): #getting immediate neighbor info
                neighbors = neighbors + [(intf.ipaddr, intf.netmask, intf.ipaddr, intf.name)]
            with open('forwarding_table.txt') as f: #getting not immediate neighbors from file
                for line in f:
                    info = f.split()
                    interface = (info[3].split('-'))[1] #get the 'eth0' out of 'router-eth0'
                    forwarding_table = forwarding_table + [(info[0], info[1], info[2], interface)]
                    #in format of (network prefix, network mask, next hop IP, interface name)
            forwarding_table = neighbors + forwarding_table            
            #part 2: forwarding packets and making ARP_request to obtain MAC address
            if pkt.type == pkt.IP_TYPE: #!!!!if just a packet to be forwarded.  Not sure about this...
                destIP = (pkt.dstip).toUnsigned()
                tuple_num = 100 #a number clearly outside of boundaries
                cidrlen = 100
                for i in forwarding_table:  #!!!NEED TO DEAL WITH IF OWN IP/INTERFACE
                    netmask = IPAddr(str(forwarding_table[i][1]))
                    length = netmask_to_cidr(netmask)
                    compare = int('1'*length + '0'*(32-length))
                    forwardIP = (forwarding_table[i][0]).toUnsigned()
                    if((destIP & compare) == (forwardIP & compare)):
                        if(length<cidrlen): #update so know looking at longest match
                            tuple_num = i
                            cidrlen = length
                if tuple_num = 100:  #no match was found
                    break
                else:
                    #finding MAC address -> SENDING ARP_REQUEST
                    #!!!!! NOTE: NEED TO MAKE A QUEUE
                    arp_request = pktlib.arp()
                    arp_request.opcode = pkt.arp.REQUEST
                    arp_request.protosrc = pkt.srcip
                    arp_request.protodst = forwarding_table[tuple_num][2] #next hop IP addr
                    arp_request = hwsrc
                    ether = pktlib.ethernet()
                    ether.type = ether.ARP_TYPE
                    #ether.src
                    #ether.dst
                    ether.set_payload(arp_request)
                    self.net.send_packet(dev, ether)
                    #sending packet... so this is if get ARP_reply....
                    pkt.ttl = pkt.ttl - 1 #decrement TTL field
                    ether = pktlib.ethernet()
                    ether.type = ether.IP_TYPE
                    ether.src = pkt.srcip
                    ether.dst = arp_request.hwsrc
                    pkt.protocol = pktlib.UDP_PROTOCOL
                    #!!!!!!!!not sure what else need/ how to incorporate payload
            #part 1: responding to ARP request
            if pkt.type == pkt.ARP_TYPE:
                arp_request = pkt.payload
                for intf in self.net.interfaces(): #!!! REPLACE WITH INFO FROM NEIGHBORS ARRAY
                    if (intf.ipaddr==arp_request.protodst):
                        arp_reply = pktlib.arp()
                        arp_reply.protodst = arp_request.protosrc
                        arp_reply.protosrc = intf.ipaddr
                        arp_reply.hwsrc = intf.ethaddr
                        arp_reply.hwdst = arp_request.hwsrc
                        arp_reply.opcode = pktlib.arp.REPLY
                        ether = pktlib.ethernet()
                        ether.type = ether.ARP_TYPE
                        ether.src = intf.ethaddr
                        ether.dst = arp_request.hwsrc
                        ether.set_payload(arp_reply)
                        self.net.send_packet(dev, ether)
                        #self.net.send_packet(dev, arp_reply)
                        break

def srpy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
    
