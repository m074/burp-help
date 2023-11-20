from pydantic import BaseModel


class HttpRequestModel(BaseModel):
    url: str
    method: str
    cookie: dict
    headers: dict
    body: str
    raw: str


class HttpResponseModel(BaseModel):
    status: str
    body: str
    headers: dict
    raw: str
