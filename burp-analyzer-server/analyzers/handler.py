import asyncio
import logging

from analyzers.csrf import CsrfTokenAnalyzer
from analyzers.dummy import QueryAnalyzer
from analyzers.regex import (BucketEndpointAnalyzer, EndpointAnalyzer,
                             IpsAnalyzer, RedirectAnalyzer, SqlErrorAnalyzer,
                             TakeoverAnalyzer)
from analyzers.subdomainizer import CloudEndpointAnalyzer, SecretAnalyzer
from analyzers.trufflehog import TruffleHogAnalyzer
from notifiers.telegram import TelegramNotifier

analyzers_list = [
    # QueryAnalyzer,
    # TruffleHogAnalyzer,
    TakeoverAnalyzer,
    EndpointAnalyzer,
    # BucketEndpointAnalyzer,
    RedirectAnalyzer,
    CloudEndpointAnalyzer,
    SecretAnalyzer,
    CsrfTokenAnalyzer,
    SqlErrorAnalyzer,
    # IpsAnalyzer
]

logger = logging.getLogger(__name__)


class AnalyzerHandler:
    def __init__(self, request, response, notifier=None):
        self.request = request
        self.response = response
        self.notifier = notifier
        if notifier is None:
            self.notifier = TelegramNotifier()

    async def run_analyzers(self):
        try:
            analyzers_results = await asyncio.gather(
                *[
                    analyzer(request=self.request, response=self.response).analyze()
                    for analyzer in analyzers_list
                ]
            )
            await self.notifier.send_messages(
                [message for message in analyzers_results if message], self.request.url
            )
            # for message in analyzers_results:
            #     if message:
            #         await self.notifier.notify(message, self.request.url)
        except Exception:
            logger.exception("Failed to run the analyzers...")
