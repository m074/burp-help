from pydantic import BaseModel


class BurpContent(BaseModel):
    url: str | bytes | None
    content: str | bytes | None
    request_content: str | bytes | None
