#!/usr/bin/python

import os
import dpkt
import pcapy
import commands


class MyTCPPacket:
    def __init__(self, pcap_file, verbose = False):
        self.verbose = verbose
        self.pcap_file = pcap_file

    def output_filepath(self):
        dirname = os.path.dirname(self.pcap_file)
        basename = os.path.basename(self.pcap_file)

        return os.path.join(dirname, "%s-%s" % ("filter", basename))

    def parse(self):
        inputfp = None
        outputfp = None
        try:
            inputfp = open(self.pcap_file, 'r')
            reader = dpkt.pcap.Reader(inputfp)

            outputfp = open(self.output_filepath(), 'wb')
            writer = dpkt.pcap.Writer(outputfp)

            for ts, buf in reader:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data

                if self.want_packet(tcp):
                    writer.writepkt(buf)
        except Exception, e:
            print "*** ERROR: cannot filter %s %s" % (self.pcap_file, e)
        finally:
            if inputfp != None:
                inputfp.close()
            if outputfp != None:
                outputfp.close()


class MyHTTPPacket(MyTCPPacket):
    def want_packet(self, tcp):
        interested = False

        if tcp.dport == 80 and len(tcp.data) > 0:
            http = dpkt.http.Request(tcp.data)
            
            if self.verbose:
                print "===> %s %s" % (http.method, http.uri)
            print "===> http host: \033[4;40;33m%s\033[0m" % http.headers["host"]

            interested = True

        if tcp.sport == 80 and len(tcp.data) > 0:
            # FIXME: not sure what's wrong
            #try:
            #    http = dpkt.http.Response(tcp.data)
            #    print http.status
            #except Exception, e:
            #    print e
            interested = True

        return interested


class MyHTTPSPacket(MyTCPPacket):
    def want_packet(self, tcp):
        interested = False

        if tcp.dport == 443 and len(tcp.data) > 0:
            interested = self.parse_ssl(tcp.data)

        if tcp.sport == 443 and len(tcp.data) > 0:
            interested = self.parse_ssl(tcp.data)

        return interested

    def parse_ssl(self, data):
        ssl_packet = False

        record = None
        try:
            record = dpkt.ssl.TLSRecord(data)
        except Exception, e:
            if self.verbose:
                print "*** WARN: %s" % e
            return ssl_packet
            
        if record.type not in dpkt.ssl.RECORD_TYPES:
            return ssl_packet

        try:
            record = dpkt.ssl.RECORD_TYPES[record.type](record.data)
        except Exception, e:
            if self.verbose:
                print "*** WARN: incomplete possible TLS handshake record"
            return ssl_packet

        ssl_packet = True
        
        if isinstance(record, dpkt.ssl.TLSHandshake):
            if isinstance(record.data, dpkt.ssl.TLSClientHello):
                ch = record.data
                if ch.version == dpkt.ssl.SSL3_V:
                    if self.verbose:
                        print "===> SSL3 Client Hello"
                elif ch.version == dpkt.ssl.TLS1_V:
                    if self.verbose:
                        print "===> TLSv1 Client Hello"
                elif ch.version == dpkt.ssl.TLS11_V:
                    if self.verbose:
                        print "===> TLSv1.1 Client Hello"
                elif ch.version == dpkt.ssl.TLS12_V:
                    if self.verbose:
                        print "===> TLSv1.2 Client Hello"
            elif isinstance(record.data, dpkt.ssl.TLSServerHello):
                if self.verbose:
                    print "===> TLS Server Hello"
            elif isinstance(record.data, dpkt.ssl.TLSCertificate):
                if self.verbose:
                    print "===> TLSCertificate"
        elif isinstance(record, dpkt.ssl.TLSChangeCipherSpec):
            if self.verbose:
                print "===> TLSChangeCipherSpec"
        elif isinstance(record, dpkt.ssl.TLSAppData):
            if self.verbose:
                print "===> TLSAppData"

        return ssl_packet


#if __name__ == "__main__":
#    filepath = "pcap_capture_dumps/10001-0.pcap"
#    
#    mypacket = MyHTTPPacket(filepath, True)
#    mypacket.parse()
