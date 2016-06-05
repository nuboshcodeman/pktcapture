#!/usr/bin/python

#import scrapy
from scrapy.spiders import Spider
from scrapy.selector import Selector
from scrapy.http import HtmlResponse
from scrapy.crawler import CrawlerProcess
from scrapy.settings import Settings
from scrapy.utils.project import get_project_settings

import json

class JsonWriterPipeline(object):
    def __init__(self):
        self.file = open('output.json', 'wb')
    
    def process_item(self, item, spider):
        line = json.dumps(dict(item)) + "\n"
        self.file.write(line)
        return item

class MyCrawler(Spider):
    name = "mycrawler"

    #allowed_domains = ["*"] 

    def __init__(self, start_urls):
        super(MyCrawler, self).__init__()
        self.start_urls = start_urls
    
    def parse(self, response):
        sel = Selector(response)

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

if __name__ == "__main__":
    settings = get_project_settings()
    
    ITEM_PIPELINES = {
        'mycrawler.JsonWriterPipeline': 300,
    }

    settings.set('ITEM_PIPELINES', ITEM_PIPELINES, 300)
    process = CrawlerProcess(settings)
    process.crawl(MyCrawler, start_urls=['http://www.baidu.com/'])
    process.start()
