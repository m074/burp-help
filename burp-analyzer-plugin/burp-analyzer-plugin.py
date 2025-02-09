import json
import time
from threading import Thread

import urllib2
from burp import (IBurpExtender, IExtensionStateListener, IHttpListener,
                  IProxyListener, IScannerListener)
from java.io import PrintWriter

registered_request_urls = set()
registered_response_urls = set()

ONLY_SCOPE = False
ANALYZER_ENDPOINT = "http://127.0.0.1:5000/analyze"


class ThreadManager:
    def __init__(self):
        self.__thread_pool = []

    def add_thread(self, thread):
        if len(self.__thread_pool) > 10:
            time.sleep(0.05)
        self.__thread_pool.append(thread)

    def remove_completed_threads(self):
        if len(self.__thread_pool) < 10:
            return
        for t in self.__thread_pool:
            if not t.is_alive():
                # get results from thread
                t.handled = True
            else:
                t.handled = False
        self.__thread_pool = [t for t in self.__thread_pool if not t.handled]


thread_manager = ThreadManager()


def send_request(url, data):
    req = urllib2.Request(url)
    req.add_header("Content-Type", "application/json")
    response = urllib2.urlopen(req, json.dumps(data), timeout=10)


class BurpExtender(
    IBurpExtender,
    IHttpListener,
    IProxyListener,
    IScannerListener,
    IExtensionStateListener,
):
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # set our extension name
        callbacks.setExtensionName("Burp-analyzer")
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)
        # register ourselves as a Scanner listener
        callbacks.registerScannerListener(self)
        self._helpers = callbacks.getHelpers()
        print("Analyzer started!")

    def _process(self, messageInfo):
        url = self._helpers.analyzeRequest(messageInfo).getUrl()

        request = self._helpers.analyzeRequest(messageInfo)
        response = self._helpers.analyzeResponse(messageInfo.getResponse())
        request_string = messageInfo.getRequest()
        response_string = messageInfo.getResponse()

        request_headers = request.getHeaders()
        response_headers = response.getHeaders()
        request_body_offset = request.getBodyOffset()
        response_body_offset = response.getBodyOffset()
        request_body = request_string[request_body_offset:]
        response_body = response_string[response_body_offset:]

        is_get_request = False
        if request.getMethod() == "GET":
            is_get_request = True
        if url not in registered_response_urls or not is_get_request:
            if is_get_request:
                registered_response_urls.add(url)
            if self._callbacks.isInScope(url) or not ONLY_SCOPE:
                data = {
                    "url": str(url),
                    "content": response_string.tostring().encode(encoding="utf-8"),
                    "requestContent": request_string.tostring().encode(encoding="utf-8"),
                    "requestHeaders": [str(request_header) for request_header in request_headers],
                    "responseHeaders": [str(header) for header in response_headers],
                    "requestBodyOffset": request_body_offset,
                    "responseBodyOffset": response_body_offset,
                    "requestBody": request_body.tostring().encode(encoding="utf-8"),
                    "responseBody": response_body.tostring().encode(encoding="utf-8")
                }

                thread = Thread(target=send_request, args=(ANALYZER_ENDPOINT, data))                 # send_request(ANALYZER_ENDPOINT, data)
                thread_manager.remove_completed_threads()
                thread.start()
                thread_manager.add_thread(thread)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        return

    def processProxyMessage(self, messageIsRequest, message):
        messageInfo = message.getMessageInfo()
        if messageIsRequest:
            pass
        else:
            self._process(messageInfo)
