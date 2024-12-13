from pydantic import BaseModel


class BurpContent(BaseModel):
    url: str | None
    content: str | None
    requestContent: str | None
