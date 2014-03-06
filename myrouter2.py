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
from math import floor
from time import time

#to do: build static forwarding table, forward packets appropriately, make ARP requests
#for other hosts to get their MAC address (so basically the flip side of part 1 of this
#project)

class Router(object):
	def __init__(self, net):
		self.net = net
		#part 2: building forwarding table
		#forwarding_table = []
		fwd = []
		my_intfs = []
		#neighbors = [] #seperate for now to use in packet ARP replies
		for intf in self.net.interfaces(): #getting immediate neighbor info
			#forwarding_table = forwarding_table + [(intf.ipaddr, intf.netmask, intf.ipaddr, intf.name)]
			my_intfs.append((intf.ipaddr, intf.netmask, IPAddr('0.0.0.0'), intf.name))
		f = open('forwarding_table.txt', 'r') #getting not immediate neighbors from file
		for line in f:
			info = line.split(' ')
			interface = info[3]
			interface = interface[:len(interface)-1] #get the 'eth0' out of 'router-eth0'
			print interface
			#forwarding_table = forwarding_table + [(info[0], info[1], info[2], interface)]
			fwd = fwd + [(IPAddr(info[0]), IPAddr(info[1]), IPAddr(info[2]), interface)]
			#in format of (network prefix, network mask, next hop IP, interface name)
			fwd = fwd + [(IPAddr(info[2]), IPAddr('255.255.255.255'), IPAddr(info[2]), interface)]
	   #     for entry in my_intfs:  #for the next hops - not immediately connected, not very far away
	   #     	print 'FT mask: ' + str(IPAddr(entry[1]).toUnsigned()) + ', FT addr: ' + str(IPAddr(entry[0]).toUnsigned())
	   #     	AND = ((entry[1].toUnsigned())&(entry[0].toUnsigned))
	   #     	print 'the AND of that: ' + str(AND)
	   #     	print 'Compare to ' + str(IPAddr(info[2]).toUnsigned())
	   #     	if (((entry[1].toUnsigned()) & (entry[0].toUnsigned)) == (IPAddr(info[2].toUnsigned()))):
	   #     		fwd = fwd + [(info[2]), (entry[1]), IPAddr(info[2]), entry[3]]
		f.close()
		#self.forwarding_table = forwarding_table

		self.fwd = fwd
		self.my_intfs = my_intfs
		self.forwarding_table = my_intfs + fwd 
		self.queue = [] #a list of tuples for storing ARP requested packets
		self.macaddrs = {} #cache of {IP:addr} mappings to cut down ARP requests
	def router_main(self):    
		while True:
			try:
				dev,ts,pkt = self.net.recv_packet(timeout=1.0)
			except SrpyNoPackets:
				# log_debug("Timeout waiting for packets")
				continue
			except SrpyShutdown:
				return          
			#part 2: forwarding packets and making ARP_request to obtain MAC address
			#debugger()
			if pkt.type == pkt.IP_TYPE: #!!!!if just a packet to be forwarded.  Not sure about this...
				pkt = pkt.payload
				destIP = pkt.dstip
				matches = []
				cidrlen = 0
				for i in self.forwarding_table:  #!!!NEED TO DEAL WITH IF OWN IP/INTERFACE
					netmask = i[1]
					#(IPAddr(str(self.forwarding_table[i][1]))).toUnsigned()
					length = netmask_to_cidr(netmask)
					#compare = int('1'*length + '0'*(32-length))
					forwardIP = i[0]
					nexthop = i[2]
					ifname = i[3]
					print 'forward IP: ' + str(forwardIP) + ', Dest IP & mask: ' + str(IPAddr(destIP.toUnsigned() & netmask.toUnsigned()))
					print 'pkt.dstip: ' + str(pkt.dstip) + ', the prefix in question: ' + str(forwardIP)
					if((forwardIP.toUnsigned() & netmask.toUnsigned()) == (destIP.toUnsigned() & netmask.toUnsigned())):
						matches.append((length, forwardIP, nexthop, ifname))  #length, net_prefix, next hop, eth#

				if len(matches)!=0: #if we have at least one match 
					print ' got into else statement to send request packet'
					#finding MAC address -> SENDING ARP_REQUEST
					low = 0
					match = ()
					for i in matches:
						if(i[0]>low):
							match = i
					if match[2]==IPAddr('0.0.0.0'): #packet for us, drop it on the floor
						continue;
					if match[2] not in self.macaddrs:
						self.send_arp_request(match)
						self.queue.append((match, floor(time()), pkt, 0))
					else:
						self.send_packet(match, pkt)
						
			#part 1: responding to ARP request
			#debugger()
			elif pkt.type == pkt.ARP_TYPE:
				arp = pkt.payload
				if (arp.opcode == pktlib.arp.REPLY): #if it is a reply to own request
					timenow = floor(time())
					for elem in self.queue:
						pktdst = elem[0][1]
						nexthop = elem[0][2]
						ifname = elem[0][3]
						time_added = elem[1]
						ippkt = elem[2]
						arpcount = elem[3]
						if(arp.protosrc == nexthop): #we found our guy
							self.macaddrs[nexthop] = arp.hwsrc
							self.queue.remove(elem)
							self.send_packet(elem[0],ippkt)
						if arpcount==5:
							self.queue.remove(elem)
							#timeout :(
						if timenow-time_added-arpcount>=1:
							self.send_arp_request(elem[0])
							elem[3] = arpcount+1
							
							
					'''
					for arr in self.queue:
						oldreq = arr[0]
						if (oldreq.protodst == arp.protosrc): #if right element in queue
							old_pkt = arr[1]
							old_pkt.ttl = old_pkt.ttl - 1 #decrement TTL field
							ether = pktlib.ethernet()
							ether.type = ether.IP_TYPE
							ether.src = old_pkt.
							ether.dst = arp.hwsrc
							ether.payload = old_pkt
						   #pkt.protocol = pkt.UDP_PROTOCOL
							self.net.send_packet(arr[2][3], ether)
							break
						else:								#if wrong element in queue, put back
							self.queue.put(arr)
						i = i+1;
					print 'Did not find packet to respond to arp request.  :(\n'
					'''
				else:
					for intf in self.net.interfaces(): #if request from someone else/ need reply
						if (intf.ipaddr==arp_request.protodst):
							arp = pktlib.arp()
							arp.protodst = arp_request.protosrc
							arp.protosrc = intf.ipaddr
							arp.hwsrc = intf.ethaddr
							arp.hwdst = arp_request.hwsrc
							arp.opcode = pktlib.arp.REPLY
							ether = pktlib.ethernet()
							ether.type = ether.ARP_TYPE
							ether.src = intf.ethaddr
							ether.dst = arp_request.hwsrc
							ether.set_payload(arp)
							self.net.send_packet(dev, ether)
							#self.net.send_packet(dev, arp_reply)
							break

	#tup = (prefixlength, destIP, nexthop, ifname)
	def send_arp_request(self, tup):
		preflen = tup[0]
		destIP = tup[1]
		nexthop = tup[2]
		ifname = tup[3]
		intf = self.net.interface_by_name(ifname)
	
		arp_pkt = pktlib.arp()
		arp_pkt.protosrc = intf.ipaddr #the ip address of the interface we're sending the request out
		arp_pkt.protodst = nexthop 
		arp_pkt.hwsrc = intf.ethaddr
		arp_pkt.hwdst = ETHER_BROADCAST
		arp_pkt.opcode = pktlib.arp.REQUEST

		ether = pktlib.ethernet()
		ether.type = ether.ARP_TYPE
		ether.src = intf.ethaddr
		ether.dst = ETHER_BROADCAST
		ether.set_payload(arp_pkt)
		self.net.send_packet(ifname, ether)
	#isn't this so pretty?  Functions are our FRIENDS :)



	#tup is a FT match tuple, like above
	#tup = (prefixlength, destIP, nexthop, ifname)
	def send_packet(self, tup, pkt):
		preflen = tup[0]
		destIP = tup[1]
		nexthop = tup[2]
		ifname = tup[3]
		intf = self.net.interface_by_name(ifname)
		
		pkt.ttl = pkt.ttl-1
		ether = pktlib.ethernet()
		ether.type = ether.IP_TYPE
		ether.src = intf.ethaddr
		ether.dst = self.macaddrs[nexthop]
		ether.set_payload(pkt)
		self.net.send_packet(ifname, ether)

def srpy_main(net):
	'''
	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
	
