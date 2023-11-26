import functools
import logging

from models.http import HttpRequestModel, HttpResponseModel

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, request: HttpRequestModel, response: HttpResponseModel):
        self.request: HttpRequestModel = request
        self.response: HttpResponseModel = response


def handle_async_exception(func):
    @functools.wraps(func)
    async def wrapped(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception:
            logger.exception("Failed to run the analyzer")
    return wrapped
