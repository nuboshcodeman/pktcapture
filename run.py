#!/usr/bin/python

import os, sys, getopt
import pcapy
import commands
import uuid
import time
import json

from mypcap import *
from mypacket import *

visit = 0
limit = 0

def inc_visit_count():
    global visit
    visit += 1


def run_web_crawler(dev, filter, verbose, url, pcap_dir, temp_dir, dump_prefix, depth, maxdepth):
    global visit
    global limit

    if depth > maxdepth:
        return

    if visit > limit:
        return

    pcap_thread = PcapThread(dev, filter, verbose)

    pcap_file = os.path.join(pcap_dir, dump_prefix + ".pcap")
    pcap_thread.init_pcap(pcap_file)
    pcap_thread.start()

    # start web crawler
    temp_file = os.path.join(temp_dir, dump_prefix + ".json")
    binpath = os.path.join(os.path.curdir, "mycrawler.py")
    try:
        status, output = commands.getstatusoutput("%s \"%s\" %s" % (binpath, url, temp_file))
        if status == 0:
            print "%s ================> done" % url
        else:
            print "%s ================> error" % url
    except Exception, e:
        print "*** ERROR: fault url is %s" % url

    pcap_thread.end_pcap()
    pcap_thread.join()

    time.sleep(1)

    # filter dump pcap file
    mypacket = MyHTTPPacket(pcap_file, False)
    mypacket.parse()

    inc_visit_count()

    fp = open(temp_file, "r")
    lines = fp.readlines()
    fp.close()

    index = 0
    # breadth first search
    for line in lines:
        childurl = json.loads(line.strip()).get("url", None)
        if childurl == None:
            continue
        new_dump_prefix = "%s-%d" % (dump_prefix, index)
        # FIXME: how to handle link loop ??? duplicate link ???
        run_web_crawler(dev, filter, verbose, childurl, pcap_dir, temp_dir, new_dump_prefix, depth + 1, maxdepth)
        index += 1


def main(conf):
    global visit
    global limit

    dev = conf.get("dev", "eth0")
    filter = conf.get("filter", "port 80")
    maxdepth = conf.get("maxdepth", 2)
    limit = conf.get("limit", 50)
    output = conf.get("output", None)
    verbose = conf.get("verbose", False)

    pcap_dir = "pcap_capture_dumps"
    temp_dir = "web_crawler_output"
    if output != None:
       pcap_dir = output.get("pcap_dir", pcap_dir)
       temp_dir = output.get("temp_dir", temp_dir)

    devices = pcapy.findalldevs()
    if not dev in devices:
        print "*** ERROR: system does not have netdev '%s'" % dev
        sys.exit(-1)

    apps = conf.get("apps", None)
    if apps == None:
        print "*** WARN: nothing to do"
        sys.exit(0)

    if os.path.exists(pcap_dir):
        commands.getstatusoutput("rm -rf %s" % pcap_dir)
    os.mkdir(pcap_dir)

    if os.path.exists(temp_dir):
        commands.getstatusoutput("rm -rf %s" % temp_dir)
    os.mkdir(temp_dir)

    for id, url in apps.items():
        visit = 0
        run_web_crawler(dev, filter, verbose, url, pcap_dir, temp_dir, str(id), 0, maxdepth)


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
