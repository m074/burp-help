import logging

import httpx
from analyzers.common import Analyzer, handle_async_exception
from config.settings import get_settings

logger = logging.getLogger(__name__)

TOKEN_HEADERS = {"X-Csrf-Token",
                 "X-App"}

settings = get_settings()


class CsrfTokenAnalyzer(Analyzer):

    @handle_async_exception
    async def analyze(self):
        if self.request.method != "POST":
            logger.debug("Ignoring not POST method in CSRF Analyzer")
            return

        token_headers = TOKEN_HEADERS.intersection(self.request.headers.keys())

        if not token_headers:
            logger.debug("Not csrf token in request")
            return

        test_headers = self.request.headers.copy()
        for token_header in token_headers:
            test_headers.pop(token_header)

        async with httpx.AsyncClient() as client:
            if self.request.body:
                httpx_response = await client.request(self.request.method,
                                                      self.request.url,
                                                      headers=test_headers,
                                                      cookies=self.request.cookie,
                                                      content=self.request.body,
                                                      timeout=settings.http_timeout)
            if httpx_response.status_code != int(self.response.status):
                logger.error("QueryAnalyzer failed!!!! with method:%s in %s", self.request.method, self.request.url)
            else:
                logger.warning("CsrfTokenAnalyzer worked in url: %s", self.request.url)
                return "No CSRF token check!!"
