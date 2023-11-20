import logging

import httpx

from analyzers.common import Analyzer

logger = logging.getLogger(__name__)


class QueryAnalyzer(Analyzer):

    async def analyze(self):
        try:
            async with httpx.AsyncClient() as client:
                if self.request.body:
                    print(self.request.headers)
                    httpx_response = await client.request(self.request.method,
                                                          self.request.url,
                                                          headers=self.request.headers,
                                                          cookies=self.request.cookie,
                                                          content=self.request.body,
                                                          timeout=5)
                else:
                    httpx_response = await client.request(self.request.method,
                                                          self.request.url,
                                                          headers=self.request.headers,
                                                          cookies=self.request.cookie,
                                                          timeout=5)
                if httpx_response.status_code != int(self.response.status):
                    logger.error("QueryAnalyzer failed!!!! with method:%s in %s", self.request.method, self.request.url)
                else:
                    logger.info("QueryAnalyzer worked in url: %s", self.request.url)
        except Exception:
            logger.exception("QueryAnalyzer fail in %s with method %s", self.request.url, self.request.method)
