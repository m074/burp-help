import logging
import re

from analyzers.common import Analyzer, handle_async_exception
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
    # https://github.com/projectdiscovery/nuclei-templates/blob/master/takeovers/heroku-takeover.yaml
    "<title>No such app</title>",
    # https://github.com/projectdiscovery/nuclei-templates/blob/master/takeovers/cargo-takeover.yaml
    "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.",
    # https://github.com/projectdiscovery/nuclei-templates/blob/master/takeovers/zendesk-takeover.yaml
    "this help center no longer exists", "Help Center Closed"
]

S3_REGEX_LIST = [
    "[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
    "[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
    "[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
    "//s3\\.amazonaws\\.com/[a-z0-9._-]+",
    "//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
]

SQL_ERRORS = {
    "MySQL": (
        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.", r"MySQL Query fail.*",
        r"SQL syntax.*MariaDB server.*", r"SQL ERROR.*"),
    "PostgreSQL": (
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\.", r"Warning.*PostgreSQL"),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
                             r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
                             r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                             r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\.",
                             r"Msg \d+, Level \d+, State \d+", r"Unclosed quotation mark after the character string",
                             r"Microsoft OLE DB Provider for ODBC Drivers"),
    "Microsoft Access": (r"Microsoft Access Driver", r"Microsoft JET Database Engine", r"Access Database Engine"),
    "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Microsoft OLE DB Provider for Oracle",
        r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception",
               r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Informix": (r"Warning.*ibase_.*", r"com.informix.jdbc"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*")
}

IP_REGEX = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

# copypasta from https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py
ENDPOINT_REGEX = r"""

  (?:"|')                               # Start newline delimiter

  (
    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path

    |

    ((?:/|\.\./|\./)                    # Start with /,../,./
    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    [^"'><,;|()]{1,})                   # Rest of the characters can't be

    |

    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    [a-zA-Z0-9_\-/]{1,}                 # Resource name
    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

    |

    ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
    [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

    |

    ([a-zA-Z0-9_\-]{1,}                 # filename
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)        # . + extension
    (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

  )

  (?:"|')                               # End newline delimiter

"""


class TakeoverAnalyzer(Analyzer):
    @handle_async_exception
    async def analyze(self):
        takeover_message = ""
        is_takeoverable = False
        for takeover_string in TAKEOVER_STRING_LIST:
            if takeover_string in self.response.body:
                is_takeoverable = True
                takeover_message += takeover_string
        if is_takeoverable:
            return "Takeover: %s".format(takeover_message)


class EndpointAnalyzer(Analyzer):
    @handle_async_exception
    async def analyze(self):
        plausible_endpoints = re.findall(re.compile(ENDPOINT_REGEX, re.VERBOSE), self.response.body)
        parsed = set()
        ignored_extensions = ["jpg", "png", "svg", "eot", "woff", "ttf"]
        for endpoints in plausible_endpoints:
            for endpoint in endpoints:
                endpoint = endpoint.strip(" \"'\r\n")
                if len(endpoint) > 2:
                    for ignored_extension in ignored_extensions:
                        if endpoint.endswith(ignored_extension):
                            continue
                    parsed.add(endpoint)
        endpoints = re.findall(
            pattern="[\"|']\/[a-zA-Z0-9_?&=\/\-\#\.]*[\"|']",
            string=self.response.raw,
        )
        for endpoint in endpoints:
            if len(endpoint) > 2:
                parsed.add(endpoint)
        endpoints = list(set(parsed))
        if endpoints:
            endpoints_text = "\n".join(endpoints)
            return "Endpoints: %s" % endpoints_text


class BucketEndpointAnalyzer(Analyzer):
    @handle_async_exception
    async def analyze(self):
        buckets = set()
        for s3_regex in S3_REGEX_LIST:
            plausible_buckets = re.findall(
                pattern=s3_regex,
                string=self.response.body,
            )
            for pb in plausible_buckets:
                buckets.add(pb)
        if buckets:
            bucket_text = "\n".join(buckets)
            return "Buckets: %s" % bucket_text


class IpsAnalyzer(Analyzer):
    @handle_async_exception
    async def analyze(self):
        plausible_ips = re.findall(
            pattern=IP_REGEX,
            string=self.response.raw + self.request.raw,
        )
        if plausible_ips:
            ips_text = "\n".join(set(plausible_ips))
            return "IPs: %s" % ips_text


class RedirectAnalyzer(Analyzer):
    @handle_async_exception
    async def analyze(self):
        if "ref=" in self.request.url:
            return
        if self.request.method == "GET" and "=http" in self.request.url or "=/" in self.request.url:
            return "PlausibleOpenRedirect:"


class SqlErrorAnalyzer(Analyzer):
    @handle_async_exception
    async def analyze(self):
        for db_name, errs in SQL_ERRORS.items():
            for err in errs:
                sql_error = re.compile(err).search(str(self.response.raw))
                if sql_error is not None:
                    return f"PlausibleSQLError: {db_name}"
