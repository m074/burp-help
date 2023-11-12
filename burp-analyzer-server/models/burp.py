from pydantic import BaseModel


class BurpContent(BaseModel):
    url: str
    content: str
    request_content: str
