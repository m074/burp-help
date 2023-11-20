import logging
import re

from analyzers.common import Analyzer
from config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class CloudEndpointAnalyzer(Analyzer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pre_compiled_cloud_regex()

    def _pre_compiled_cloud_regex(self):
        """
        Copypasted from https://github.com/nsonaniya2010/SubDomainizer/blob/master/SubDomainizer.py
        """
        cfreg = re.compile(r'([\w]+\.cloudfront\.net)', re.MULTILINE | re.IGNORECASE)
        gbureg = re.compile(r'([\w\-.]+\.appspot\.com)', re.MULTILINE | re.IGNORECASE)
        s3bucketreg = re.compile(r'(s3[\w\-.]*\.?amazonaws\.com/?[\w\-.]+)', re.MULTILINE | re.IGNORECASE)
        s3bucketreg2 = re.compile(r'([\w\-]+.s3[\w\-.]*\.?amazonaws\.com/?)', re.MULTILINE | re.IGNORECASE)
        doreg = re.compile(r'([\w\-.]*\.?digitaloceanspaces\.com/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        gsreg1 = re.compile(r'(storage\.cloud\.google\.com/[\w\-.]+)', re.MULTILINE | re.IGNORECASE)
        gsreg2 = re.compile(r'([\w\-.]*\.?storage.googleapis.com/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        gsreg3 = re.compile(r'([\w\-.]*\.?storage-download.googleapis.com/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        gsreg4 = re.compile(r'([\w\-.]*\.?content-storage-upload.googleapis.com/?[\w\-.]*)',
                            re.MULTILINE | re.IGNORECASE)
        gsreg5 = re.compile(r'([\w\-.]*\.?content-storage-download.googleapis.com/?[\w\-.]*)',
                            re.MULTILINE | re.IGNORECASE)
        azureg1 = re.compile(r'([\w\-.]*\.?1drv\.com/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        azureg2 = re.compile(r'(onedrive.live.com/[\w.\-]+)', re.MULTILINE | re.IGNORECASE)
        azureg3 = re.compile(r'([\w\-.]*\.?blob\.core\.windows\.net/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        rackcdnreg = re.compile(r'([\w\-.]*\.?rackcdn.com/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        dreamhostreg1 = re.compile(r'([\w\-.]*\.?objects\.cdn\.dream\.io/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        dreamhostreg2 = re.compile(r'([\w\-.]*\.?objects-us-west-1.dream.io/?[\w\-.]*)', re.MULTILINE | re.IGNORECASE)
        firebase = re.compile(r'([\w\-.]+\.firebaseio\.com)', re.MULTILINE | re.IGNORECASE)

        cloudlist = [cfreg, s3bucketreg, doreg, gsreg1, gsreg2, gsreg3, gsreg4, gsreg5,
                     azureg1, azureg2, azureg3, rackcdnreg, dreamhostreg1, dreamhostreg2, firebase, gbureg,
                     s3bucketreg2]

        self._regex_cloudlist = cloudlist

    async def analyze(self):

        cloud_set = set()

        for cloud in self._regex_cloudlist:
            for item in cloud.findall(str(self.response.raw.replace('\n', ' '))):
                cloud_set.add(item)
        if cloud_set:
            bucket_text = "\n".join(cloud_set)
            return "CloudEndpoints: %s" % bucket_text


class SecretAnalyzer(Analyzer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pre_compiled_secret_regex()

    def _pre_compiled_secret_regex(self):
        """
        Copypasted from https://github.com/nsonaniya2010/SubDomainizer/blob/master/SubDomainizer.py
        """
        seclst = set(['secret', 'secret[_-]?key', 'token', 'secret[_-]?token', 'password',
                      'aws[_-]?access[_-]?key[_-]?id', 'aws[_-]?secret[_-]?access[_-]?key', 'auth[-_]?token',
                      'access[-_]?token',
                      'auth[-_]?key', 'client[-_]?secret', 'email', 'access[-_]?key',
                      'id_dsa', 'encryption[-_]?key', 'passwd', 'authorization', 'bearer', 'GITHUB[_-]?TOKEN',
                      'api[_-]?key', 'api[-_]?secret', 'client[_-]?key', 'client[_-]?id', 'ssh[-_]?key',
                      'ssh[-_]?key', 'irc_pass', 'xoxa-2', 'xoxr', 'private[_-]?key', 'consumer[_-]?key',
                      'consumer[_-]?secret',
                      'SLACK_BOT_TOKEN', 'api[-_]?token', 'session[_-]?token', 'session[_-]?key',
                      'session[_-]?secret', 'slack[_-]?token'])
        equal = ['=', ':', '=>', '=:', '==']

        blacklist_secrets = set(['proptypes.', 'process.', 'this.', 'config.', 'key.'])
        regex = r'(["\']?[\\w\-]*(?:' + '|'.join(seclst) + ')[\\w\\-]*[\\s]*["\']?[\\s]*(?:' + '|'.join(
            equal) + ')[\\s]*["\']?((?!.*' + '|'.join(blacklist_secrets) + '.*)[\\w\\-/~!@#$%^*+.]+=*)["\']?)'

        self._secret_regex_list = re.compile(regex, re.MULTILINE | re.IGNORECASE)

    async def analyze(self):

        secret_set = set()

        matches = self._secret_regex_list.finditer(
            str(self.response.raw.replace('\n', ' ')))
        for match in matches:
            print(match)
            if len(match.group()) > 3:
                secret_set.add(match.group())

        if secret_set:
            bucket_text = "\n".join(secret_set)
            return "PotentialSecrets: %s" % bucket_text
