from models.http import HttpRequestModel, HttpResponseModel


class Analyzer:
    def __init__(self, request: HttpRequestModel, response: HttpResponseModel):
        self.request: HttpRequestModel = request
        self.response: HttpResponseModel = response
