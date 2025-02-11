from pydantic import BaseModel


class BurpContent(BaseModel):
    url: str | None
    content: str | None
    requestContent: str | None
    requestHeaders: list[str]
    responseHeaders: list[str]
    requestBody: str | None
    responseBody: str | None
