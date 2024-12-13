import logging

import uvicorn
from analyzers.handler import AnalyzerHandler
from fastapi import FastAPI, HTTPException
from models.burp import BurpContent
from parsers.http import http_request_parser, http_response_parser

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
app = FastAPI()


@app.post(
    "/analyze",
    description="Burp-Analyzer plugin endpoint",
    responses={
        400: {"description": "Parsing error"},
        500: {"description": "Analyzer Handling error"},
    },
)
async def analyze_burp(burp_content: BurpContent):
    try:
        http_request = http_request_parser(burp_content.requestContent)
        logger.debug(http_request.url)
        http_response = http_response_parser(burp_content.content)
        logger.debug(http_response.status)

    except Exception:
        logger.exception("Failed to parse the HTTP")
        raise HTTPException(status_code=400, detail="Failed to parse")

    try:
        analyzer_handler = AnalyzerHandler(http_request, http_response, None)
        await analyzer_handler.run_analyzers()

    except Exception:
        logger.exception("Failed to run the analyzers")
        raise HTTPException(status_code=500, detail="Failed to run the analyzers")

    return {"detail": "Success"}


if __name__ == "__main__":
    logger.info("Starting the app...")
    uvicorn.run(
        "main:app", host="0.0.0.0", port=5000, log_level=logging.WARNING, workers=6
    )
