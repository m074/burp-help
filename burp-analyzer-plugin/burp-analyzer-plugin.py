from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from java.io import PrintWriter
from threading import Thread
import json
import urllib2

registered_request_urls = set()
registered_response_urls = set()

ONLY_SCOPE = False
ANALYZER_ENDPOINT = 'http://127.0.0.1:5000/analyze-content'


class ThreadManager:
    def __init__(self):
        self.__thread_pool = []
        self._remove_calls = 0

    def add_thread(self, thread):
        self.__thread_pool.append(thread)

    def remove_completed_threads(self):
        if self._remove_calls < 10:
            self._remove_calls += 1
            return
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

    def _process_response(self, messageInfo):
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        request = messageInfo.getRequest().tostring()
        is_get_request = False
        if request.startswith("GET"):
            is_get_request = True
        if url not in registered_response_urls or not is_get_request:
            if is_get_request:
                registered_response_urls.add(url)
            if self._callbacks.isInScope(url) or not ONLY_SCOPE:
                response = messageInfo.getResponse().tostring()
                data = {
                    "url": str(url),
                    "content": response.encode(encoding="utf-8"),
                    "request_content": request.encode(encoding="utf-8"),
                }
                thread = Thread(target=send_request, args=(ANALYZER_ENDPOINT, data))
                # thread_manager.remove_completed_threads()
                thread.start()
                # thread_manager.add_thread(thread)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        return

    def processProxyMessage(self, messageIsRequest, message):
        messageInfo = message.getMessageInfo()
        if messageIsRequest:
            pass
        else:
            self._process_response(messageInfo)
