import json
import logging
import os
import string
import subprocess
import random
from starlette.concurrency import run_in_threadpool

from analyzers.common import Analyzer
from config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class TruffleHogAnalyzer(Analyzer):

    async def analyze(self):
        return await run_in_threadpool(self._analyze)

    def _analyze(self):
        try:
            temp_filename = (
                    "".join(random.choices(string.ascii_uppercase, k=10)) + "trufflehog_content.txt"
            )
            tempfile_path = settings.temp_dir + temp_filename
            with open(tempfile_path, "w", encoding="utf-8") as tempfile:
                tempfile.write(self.response.raw)
                tempfile.write("\r\n")
                tempfile.write(self.request.raw)
                tempfile.write("\r\n")
            proc = subprocess.Popen(
                settings.trufflehog_path
                + " filesystem "
                + tempfile_path
                + " -j --no-verification"
                + " --no-update",
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
            out, _ = proc.communicate()
            os.remove(tempfile_path)
            if out:
                try:
                    json_result = json.loads(out)
                    dict_result = dict(
                        (k, json_result.get(k)) for k in ('DetectorName', 'Raw', "ExtraData", "StructuredData"))
                    return "TruffleHog: %s" % dict_result
                except json.JSONDecodeError:
                    return "TruffleHog: %s" % out
        except Exception:
            logger.exception("TruffleHog fail.")
