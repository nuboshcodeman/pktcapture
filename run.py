#!/usr/bin/python
# -*- coding:utf-8 -*-

import os, sys, getopt
import pcapy
import commands
import subprocess
import uuid
import time
import json

from mypcap import *
from mypacket import *

visit = 0
limit = 0


def remove_dup_entry(fpath):
    records = []
    try:
        fp = open(fpath, 'r')
        for line in fp.readlines():
            record = line.strip().lower()
            if not record in records:
                records.append(record)
        fp.close()

        fp = open(fpath, 'w')
        for record in records:
            fp.write(record + "\n")
        fp.close()
    except Exception, e:
        raise


def inc_visit_count():
    global visit
    visit += 1


def run_web_crawler(dev, filter, verbose, url, pcap_dir, temp_dir, dump_prefix, depth, maxdepth, info_fp):
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
        command = "%s '%s' %s" % (binpath, url, temp_file)
        
        # NOTE: here we cannot call commands.getstatusoutput because
        # it would run into encoding error
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ""
        for line in p.stdout.readlines():
            output += line
        for line in p.stderr.readlines():
            output += line
        status = p.wait()
        
        if status == 0:
            print "%s ===> \033[1;40;34m%s\033[0m" % (url, "done")
        else:
            print "%s ===> \033[1;40;31m%s\033[0m" % (url, "error")

    except Exception, e:
        print "*** ERROR: fault url is %s, detailed error %s" % (url, e)

    # stop pcap monitor thread
    pcap_thread.end_pcap()
    pcap_thread.join()

    time.sleep(1)

    # filter dump pcap file
    mypacket = None
    if url.startswith("http://"):
        mypacket = MyHTTPPacket(pcap_file, verbose)
    elif url.startswith("https://"):
        mypacket = MyHTTPSPacket(pcap_file, verbose)
    mypacket.parse(info_fp)

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
        run_web_crawler(dev, filter, verbose, childurl, pcap_dir, temp_dir, new_dump_prefix, depth + 1, maxdepth, info_fp)
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
    info_dir = "app_info_output"
    temp_dir = "web_crawler_output"
    if output != None:
       pcap_dir = output.get("pcap_dir", pcap_dir)
       info_dir = output.get("info_dir", info_dir)
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

    if os.path.exists(info_dir):
        commands.getstatusoutput("rm -rf %s" % info_dir)
    os.mkdir(info_dir)

    if os.path.exists(temp_dir):
        commands.getstatusoutput("rm -rf %s" % temp_dir)
    os.mkdir(temp_dir)

    for appid, url in apps.items():
        visit = 0

        info_file = os.path.join(info_dir, "%s-hosts" % str(appid))
        info_fp = open(info_file, 'w')
        run_web_crawler(dev, filter, verbose, url, pcap_dir, temp_dir, str(appid), 0, maxdepth, info_fp)
        info_fp.close()

        # NOTE: currently do simple string compare
        remove_dup_entry(info_file)


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
