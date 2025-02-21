from scrapy import Spider, Request
from scrapy.crawler import CrawlerProcess
import asyncio
import aiohttp
from fake_useragent import UserAgent
import snowflake.connector
from typing import Dict, List
import logging
import json
from datetime import datetime

class ThreatDetectionSpider(Spider):
    name = 'threat_detector'
    
    def __init__(self, *args, **kwargs):
        super(ThreatDetectionSpider, self).__init__(*args, **kwargs)
        self.user_agent = UserAgent()
        self.setup_snowflake_connection()
        
    def setup_snowflake_connection(self):
        self.snow_conn = snowflake.connector.connect(
            user=self.settings.get('SNOWFLAKE_USER'),
            password=self.settings.get('SNOWFLAKE_PASSWORD'),
            account=self.settings.get('SNOWFLAKE_ACCOUNT'),
            warehouse=self.settings.get('SNOWFLAKE_WAREHOUSE'),
            database=self.settings.get('SNOWFLAKE_DATABASE'),
            schema=self.settings.get('SNOWFLAKE_SCHEMA')
        )
        
    def start_requests(self):
        urls = self.settings.get('START_URLS', [])
        for url in urls:
            yield Request(
                url=url,
                headers={'User-Agent': self.user_agent.random},
                callback=self.parse,
                errback=self.handle_error,
                meta={'proxy': self.get_next_proxy()}
            )

    def parse(self, response):
        try:
            # Extract basic page information
            page_data = {
                'url': response.url,
                'timestamp': datetime.utcnow().isoformat(),
                'html_content': response.text,
                'headers': dict(response.headers),
                'status': response.status
            }
            
            # Store in Snowflake
            self.store_page_data(page_data)
            
            # Follow links for crawling
            for href in response.css('a::attr(href)').extract():
                yield Request(
                    url=response.urljoin(href),
                    callback=self.parse,
                    headers={'User-Agent': self.user_agent.random},
                    meta={'proxy': self.get_next_proxy()}
                )
                
        except Exception as e:
            logging.error(f"Error processing {response.url}: {str(e)}")

    def store_page_data(self, data: Dict):
        cur = self.snow_conn.cursor()
        try:
            cur.execute("""
                INSERT INTO raw_crawl_data (url, timestamp, html_content, headers, status)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                data['url'],
                data['timestamp'],
                data['html_content'],
                json.dumps(data['headers']),
                data['status']
            ))
        finally:
            cur.close()

    def get_next_proxy(self) -> str:
        # Implement proxy rotation logic here
        proxies = self.settings.get('PROXY_LIST', [])
        return proxies[0] if proxies else None

    def handle_error(self, failure):
        logging.error(f"Request failed: {failure.value}")

# Crawler settings
settings = {
    'BOT_NAME': 'threat_detector',
    'ROBOTSTXT_OBEY': True,
    'CONCURRENT_REQUESTS': 32,
    'DOWNLOAD_DELAY': 1,
    'COOKIES_ENABLED': False,
    'TELNETCONSOLE_ENABLED': False,
    'DEFAULT_REQUEST_HEADERS': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en',
    },
    'SPIDER_MIDDLEWARES': {
        'scrapy.spidermiddlewares.httperror.HttpErrorMiddleware': True,
    },
    'DOWNLOADER_MIDDLEWARES': {
        'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware': None,
        'scrapy.downloadermiddlewares.retry.RetryMiddleware': True,
    },
    'ITEM_PIPELINES': {
        'threat_detector.pipelines.SnowflakePipeline': 300,
    },
}

if __name__ == '__main__':
    process = CrawlerProcess(settings)
    process.crawl(ThreatDetectionSpider)
    process.start()
