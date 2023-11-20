import logging
import re

from analyzers.common import Analyzer
from config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

TAKEOVER_STRING_LIST = [
    "There is no app configured at that hostname",
    "NoSuchBucket",
    "No Such Account",
    "You're Almost There",
    "a GitHub Pages site here",
    "There's nothing here",
    "project not found",
    "Your CNAME settings",
    "InvalidBucketName",
    "PermanentRedirect",
    "The specified bucket does not exist",
    "Repository not found",
    "Sorry, We Couldn't Find That Page",
    "The feed has not been found.",
    "The thing you were looking for is no longer here, or never was",
    "Please renew your subscription",
    "There isn't a Github Pages site here.",
    "We could not find what you're looking for.",
    "No settings were found for this company:",
    "No such app",
    "is not a registered InCloud YouTrack",
    "Unrecognized domain",
    "project not found",
    "This UserVoice subdomain is currently available!",
    "Do you want to register",
    "Help Center Closed",
]

S3_REGEX_LIST = [
    "[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
    "[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
    "[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
    "//s3\\.amazonaws\\.com/[a-z0-9._-]+",
    "//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
]

IP_REGEX = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"


class TakeoverAnalyzer(Analyzer):
    async def analyze(self):
        takeover_message = ""
        is_takeoverable = False
        for takeover_string in TAKEOVER_STRING_LIST:
            if takeover_string in self.response.body:
                is_takeoverable = True
                takeover_message += takeover_string
        if is_takeoverable:
            print("Takeover %s".format(takeover_message))


class EndpointAnalyzer(Analyzer):
    async def analyze(self):
        possible_endpoints = re.findall(
            pattern="[\"|']\/[a-zA-Z0-9_?&=\/\-\#\.]*[\"|']",
            string=self.response.raw,
        )
        parsed = []
        for x in possible_endpoints:
            x = x.strip("\"'")
            if len(x) > 2:
                parsed.append(x)
        endpoints = list(set(parsed))
        if endpoints:
            endpoints_text = "\n".join(endpoints)
            print("Endpoins %s in %s" % (endpoints_text, self.request.url))


class BucketEndpointAnalyzer(Analyzer):
    async def analyze(self):

        s3_set = set()
        for s3_regex in S3_REGEX_LIST:
            posible_buckets = re.findall(
                pattern=s3_regex,
                string=self.response.body,
            )
            for pb in posible_buckets:
                s3_set.add(pb)
        if s3_set:
            bucket_text = "\n".join(s3_set)
            print("Buckers: %s" % bucket_text)


class IpsAnalyzer(Analyzer):
    async def analyze(self):
        posible_ips = re.findall(
            pattern=IP_REGEX,
            string=self.response.raw + self.request.raw,
        )
        ips_set = set(posible_ips)
        if ips_set:
            ips_text = "\n".join(ips_set)
            print("IPs: %s" % ips_text)
