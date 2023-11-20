import logging

from analyzers.content import TruffleHogAnalyzer
from analyzers.dummy import QueryAnalyzer
from analyzers.regex import TakeoverAnalyzer, EndpointAnalyzer, BucketEndpointAnalyzer, IpsAnalyzer

analyzers_list = [
    QueryAnalyzer,
    # TruffleHogAnalyzer,
    # TakeoverAnalyzer,
    # EndpointAnalyzer,
    # BucketEndpointAnalyzer,
    # IpsAnalyzer
]

logger = logging.getLogger(__name__)


class AnalyzerHandler:
    def __init__(self, request, response, notifiers):
        self.request = request
        self.response = response
        self.notifiers = notifiers

    async def run_analyzers(self):
        for analyzer in analyzers_list:
            try:
                analyzer_instance = analyzer(request=self.request, response=self.response)
                message = await analyzer_instance.analyze()
            except Exception:
                logger.exception("Failed to run the analyzer: %s", analyzer.__name__)
