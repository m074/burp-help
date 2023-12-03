from pydantic import BaseModel


class BurpContent(BaseModel):
    url: str | None
    content: str | None
    request_content: str | None
