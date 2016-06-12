#!/usr/bin/python
# -*- coding:utf-8 -*-

import socket
from struct import *
import pcapy
import threading

class PcapThread(threading.Thread):
    def __init__(self, dev, filter, verbose = False):
        threading.Thread.__init__(self)
        self.dev = dev
        self.filter = filter
        self.verbose = verbose

        # Python simple memory model ensure it is ok to share this variable
        # between 2 threads
        self.pcap_should_stop = True
    
    def init_pcap(self, file):
        # Arguments here are:
        #   device
        #   snaplen (maximum number of bytes to capture _per_packet_)
        #   promiscious mode (1 for true)
        #   timeout (in milliseconds)
        self.pcap = pcapy.open_live(self.dev , 65536 , 0 , 1000)
        self.pcap.setfilter(self.filter)
        self.dumpfd = self.pcap.dump_open(file)

        self.pcap_should_stop = False
    
    # thread major routine
    def run(self):
        while True:
            if self.pcap_should_stop:
                break
    
            header, packet = self.pcap.next()
            if header != None:
                if self.verbose:
                    self.parse_packet(packet)
                self.dumpfd.dump(header, packet)

        self.dumpfd = None # NOTE: free the dumpfd then python would do IO flush
    
    def end_pcap(self):
        self.pcap_should_stop = True
        
    def eth_addr(self, a):
    	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    	return b
    
    def parse_packet(self, packet):
    	# parse ethernet header
    	eth_length = 14
    	
    	eth_header = packet[:eth_length]
    	eth = unpack('!6s6sH' , eth_header)
    	eth_protocol = socket.ntohs(eth[2])
    	print 'Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Source MAC : ' + self.eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    
    	# parse IP packets, IP Protocol number = 8
    	if eth_protocol == 8:
    		# parse IP header
    		# take first 20 characters for the ip header
    		ip_header = packet[eth_length:20 + eth_length]
    		
    		iph = unpack('!BBHHHBBH4s4s' , ip_header)
    
    		version_ihl = iph[0]
    		version = version_ihl >> 4
    		ihl = version_ihl & 0xF
    
    		iph_length = ihl * 4
    
    		ttl = iph[5]
    		protocol = iph[6]
    		s_addr = socket.inet_ntoa(iph[8]);
    		d_addr = socket.inet_ntoa(iph[9]);
    
    		print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
    
    		# TCP protocol
    		if protocol == 6:
    			t = iph_length + eth_length
    			tcp_header = packet[t:t + 20]
    
    			tcph = unpack('!HHLLBBHHH' , tcp_header)
    			
    			source_port = tcph[0]
    			dest_port = tcph[1]
    			sequence = tcph[2]
    			acknowledgement = tcph[3]
    			doff_reserved = tcph[4]
    			tcph_length = doff_reserved >> 4
    			
    			print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
    			
    			h_size = eth_length + iph_length + tcph_length * 4
    			data_size = len(packet) - h_size
    			
    			# get data from the packet
    			data = packet[h_size:]
    			#print 'Data : ' + data
    		#some other IP packet
    		else:
    			print 'Other protocol'
