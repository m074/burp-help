import logging

import uvicorn
from fastapi import FastAPI
from models.burp import BurpContent
from parsers.http import http_request_parser, http_response_parser

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
app = FastAPI()


@app.get("/")
async def test():
    return {"message": "Hello World"}


@app.post("/analyze-content")
async def analyze_burp(burp_content: BurpContent):
    try:
        http_request = http_request_parser(burp_content.request_content)
        logger.debug(http_request.url)
        http_response = http_response_parser(burp_content.content)
        logger.debug(http_response.status)
    except Exception:
        logger.exception("Fallo el parser")
    return {"message": "Hello World"}


if __name__ == "__main__":
    uvicorn.run("main:app", host='0.0.0.0', port=5000, reload=True)
