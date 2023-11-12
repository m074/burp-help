from pydantic import BaseModel


class HttpRequestModel(BaseModel):
    url: str
    method: str
    cookie: dict
    headers: dict
