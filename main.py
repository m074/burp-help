import logging
import os
import re
import string
import random
import subprocess
import requests
import json
import os

from flask import Flask, request
from urllib.parse import unquote, quote


log_format = "%(asctime)s %(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=log_format, datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger()

app = Flask(__name__)

TEMP_FOLDER = "/tmp/"
if os.name == 'nt':
    TEMP_FOLDER = "D:\\"

S3_REGEX_LIST = [
    "[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
    "[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
    "[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
    "//s3\\.amazonaws\\.com/[a-z0-9._-]+",
    "//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+"
]

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
        "Help Center Closed"
    ]

IP_REGEX = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"

known_ips = set()
known_buckets = set()

def send_message(bot_message: str):
    bot_token = '5972530336:AAGHoS6AlWLm1imW49qT7Ri104y868PnaNA'
    bot_chatID = '325968545'
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID  + '&parse_mode=Markdown'
    response = requests.post(send_text, data={"text": bot_message})
    response.raise_for_status()


@app.route("/analyze-content", methods=["POST"])
def analyze_content():

    record = json.loads(request.data)
    url = record["url"]
    content = record["content"]
    # print(content)
    logger.info("Analyzing content of %s", url)
    temp_filename = (
        "".join(random.choices(string.ascii_uppercase, k=10)) + "reimu_temp.txt"
    )
    tempfile_path = TEMP_FOLDER + temp_filename
    # ENDPOINTS
    if url.split("?")[0].endswith(".js"):
        posible_endpoints = re.findall(
            pattern="[\"|']\/[a-zA-Z0-9_?&=\/\-\#\.]*[\"|']",
            string=content,
        )
        resul = []
        for x in posible_endpoints:
            x = x.strip("\"'")
            if len(x) > 2:
                resul.append(x)
        endpoints = list(set(resul))
        if endpoints:
            endpoints_text = "\n".join(endpoints)
            send_message("Endpoins ```%s``` in ```%s```" % (endpoints_text, url))
    #URLS
    # posible_urls = re.findall(
    #     pattern="https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
    #     string=content,
    # )
    #BUCKETS
    s3_set = set()
    for s3_regex in S3_REGEX_LIST:
        posible_buckets = re.findall(
            pattern=s3_regex,
            string=content,
        )
        for pb in posible_buckets:
            if pb not in known_buckets:
                known_buckets.add(pb)
                s3_set.add(pb)
    if s3_set:
        bucket_text = "\n".join(s3_set)
        send_message("Buckets ```%s``` in ```%s```" % (bucket_text, url))
    #IPS
    # posible_ips = re.findall(
    #     pattern=IP_REGEX,
    #     string=content,
    # )
    # ips_set = set(posible_ips)
    # logger.warning(ips_set)
    # if ips_set:
    #     ips_text = "\n".join(list(ips_set))
    #     send_message("IPs: ```%s``` in ```%s```" % (ips_text, url))
    #TAKEOVER
    is_takeoverable = False
    for takeover_string in TAKEOVER_STRING_LIST:
        if takeover_string in content:
            is_takeoverable = True
            break
    if is_takeoverable:
        send_message("Posible takeover in ```%s```" % (url))
    # TRUFFLEHOG
    if os.name != 'nt': # linux
        with open(tempfile_path, "w", encoding="utf-8") as tempfile:
            tempfile.write(content)
        proc = subprocess.Popen(
            "/home/vaati/go/bin/trufflehog filesystem "+tempfile_path+" -j --no-verification",
            stdout=subprocess.PIPE,
            shell=True,
        )
        out, _ = proc.communicate()
        logger.info("salida de hog: %s",out)
        if out:
            send_message("**Hog hog** ```%s``` in ```%s```" % (str(out), url))
        os.remove(tempfile_path)
    return json.dumps({"status": "OK"})


@app.route("/analyze-url", methods=["POST"])
def analyze_url():
    record = json.loads(request.data)
    url = record["url"]
    print(url)
    if "=http" in url:
        send_message("Potential Redirect/SSRF in this [URL](%s)" % url)
    if "=/" in url:
        send_message("Maybe Redirect/SSRF in this [URL](%s)" % url)
    return json.dumps({"status": "OK"})


#app.run(host="0.0.0.0")
