#!/usr/bin/python

import os, sys, getopt
import pcapy
import commands
import uuid
import time
import json

from mypcap import *

def main(conf):
    urls = []

    dev = conf.get("dev", "eth0")
    filter = conf.get("filter", "port 80")
    outputdir = conf.get("output", "result")
    verbose = conf.get("verbose", False)

    devices = pcapy.findalldevs()
    if not dev in devices:
        print "*** ERROR: system does not have netdev '%s'" % dev
        sys.exit(1)

    apps = conf.get("apps", None)
    if apps == None:
        print "*** WARN: nothing to do"
        sys.exit(0)

    if os.path.exists(outputdir):
        commands.getstatusoutput("rm -rf %s" % outputdir)
    os.mkdir(outputdir)

    for id, url in apps.items():
        print id
        print url

        pcap_thread = PcapThread(dev, filter, verbose)

        file = os.path.join(outputdir, str(id) + ".pcap")
        print file
        pcap_thread.init_pcap(file)
        pcap_thread.start()

        # start web crawler
        status, _ = commands.getstatusoutput("wget " + url)
        if status == 0:
            print "=================>  done"

        pcap_thread.end_pcap()
        pcap_thread.join()

        time.sleep(1)

def usage():
    usage = '''
    %s -c <config>
    
    -h or --help
    -c or --config="config file path"
    ''' % sys.argv[0]
    print usage

if __name__ == "__main__":
    json_conf = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:", ["help", "config="])

        if len(opts) == 0:
            usage()
            sys.exit(0)

        for option, value in opts:
            if option in ("-h", "--help"):
                usage()
                sys.exit(0)
            elif option in ("-c", "--config"):
                json_conf = value
            else:
                usage()
                sys.exit(-1)

        if not os.path.exists(json_conf):
            print "*** ERROR: cannot see config file '%s'" % json_conf
            sys.exit(-1)

        json_data = open(json_conf, 'r').read()
        main(json.loads(json_data.lower()))
    except Exception, e:
        raise
        #print e
        #sys.exit(-1)
