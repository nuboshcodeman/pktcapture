#!/usr/bin/python

import os
import dpkt
import pcapy

class MyHTTPPacket:
    def __init__(self, pcap_file, verbose = False):
        self.verbose = verbose
        self.pcap_file = pcap_file

    def output_filepath(self):
        dirname = os.path.dirname(self.pcap_file)
        basename = os.path.basename(self.pcap_file)

        return os.path.join(dirname, "%s-%s" % ("filter", basename))

    def parse(self):
        try:
            inputfp = open(self.pcap_file)
            reader = dpkt.pcap.Reader(inputfp)

            outputfp = open(self.output_filepath(), 'wb')
            writer = dpkt.pcap.Writer(outputfp)

            for ts, buf in reader:
                pkt_dump = False

                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data

                if tcp.dport == 80 and len(tcp.data) > 0:
                    http = dpkt.http.Request(tcp.data)
                    
                    if self.verbose:
                        print "===> %s %s" % (http.method, http.uri)

                    pkt_dump = True

                if tcp.sport == 80 and len(tcp.data) > 0:
                    # FIXME: not sure what's wrong
                    #try:
                    #    http = dpkt.http.Response(tcp.data)
                    #    print http.status
                    #except Exception, e:
                    #    print e
                    pkt_dump = True

                if pkt_dump:
                    writer.writepkt(buf)

            inputfp.close()
            outputfp.close()
        except Exception, e:
            print "*** ERROR: cannot filter %s" % self.pcap_file
    
#if __name__ == "__main__":
#    filepath = "/root/pktcapture/pcap_capture_dumps/10003-2-2.pcap"
#    
#    mypacket = MyHTTPPacket(filepath, True)
#    mypacket.parse()
