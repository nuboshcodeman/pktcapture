#!/usr/bin/python

#import scrapy
from scrapy.spiders import Spider
from scrapy.selector import Selector
from scrapy.http import HtmlResponse
from scrapy.crawler import CrawlerProcess
from scrapy.settings import Settings
from scrapy.utils.project import get_project_settings

import json
import sys
import re

class JsonWriterPipeline(object):
    def __init__(self, output_file):
        try:
            self.fpath = output_file
        except Exception, e:
            raise e

    @classmethod
    def from_crawler(cls, crawler):
        settings = crawler.settings
        return cls(settings.get("OUTPUT_FILE"))

    def open_spider(self, spider):
        self.outfd = open(self.fpath, "wb")

    def close_spider(self, spider):
        self.outfd.flush()
        self.outfd.close()
    
    def process_item(self, item, spider):
        line = json.dumps(dict(item)) + "\n"
        self.outfd.write(line)
        return item

class MyCrawler(Spider):
    name = "mycrawler"

    #allowed_domains = ["*"] 

    def __init__(self, start_urls):
        super(MyCrawler, self).__init__()
        self.start_urls = start_urls
    
    def parse(self, response):
        items = []

        self.__parse_http_header(response.headers)
        sites = self.__parse_html_href(response)
        for site in sites:
            #yield scrapy.Request(response.urljoin(site), self.parse)
            item = {}
            item['url'] = site
            items.append(item)

        return items

    # private method
    def __parse_http_header(self, header):
        pass

    def __parse_html_href(self, html):
        # Example:
        # <html>
        #     <head>
        #         <link rel="stylesheet" href="http://example.com/homepage.css" type="text/css">
        #     </head>
        #     <body>
        #         <a href="http://example.com/index.html" target="_top">click here!</a>
        #     </body>
        # </html>
        #
        # TODO: do we miss something ???
        #

        #print "*********************"
        #print html
        #print "---"
        #print html.body
        #print "---"
        #print html.text
        #print "---"
        #print dir(html)
        #print "*********************"

        links = []
        for href_link in html.xpath("//a/@href").extract():
            if self.__href_link_good_or_not(href_link):
                links.append(href_link)
        return links

    def __href_link_good_or_not(self, href):
        # TODO: we might need a fine-grained filtering rule.
        if href.startswith("http://"):
            return True
        elif href.startswith("https://"):
            return True
        else:
            return False

def init_and_run_web_crawler(url, tempfile):
    settings = get_project_settings()
    
    ITEM_PIPELINES = {
        "mycrawler.JsonWriterPipeline": 300
    }
    settings.set("ITEM_PIPELINES", ITEM_PIPELINES, 300)
    settings.set("OUTPUT_FILE", tempfile, 300)

    process = CrawlerProcess(settings)
    process.crawl(MyCrawler, start_urls=[url])
    process.start()
    process.stop()

if __name__ == "__main__":
    url = sys.argv[1]
    fpath = sys.argv[2]
    init_and_run_web_crawler(url, fpath)
