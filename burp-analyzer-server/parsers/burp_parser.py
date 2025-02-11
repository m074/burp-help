from models.burp import BurpContent
from models.http import HttpResponseModel, HttpRequestModel


def parse_burp(burp_content: BurpContent) -> (HttpRequestModel, HttpResponseModel):
    request_first_line = True
    method = "NONE"
    cookie = {}
    uri = ""
    url = ""
    headers = dict()
    for line in burp_content.requestHeaders:
        if request_first_line:
            request_first_line = False
            method, uri, _ = line.split()
            continue
        else:
            if line.startswith("Content-Length:"):
                continue
            header_name, header_value = line.split(": ", 1)
            if line.startswith("Cookie:"):
                for cookie_element in header_value.split(";"):
                    cookie_key, *v = cookie_element.split("=")
                    cookie[cookie_key.strip()] = "=".join(v).strip(" ;")
            elif line.startswith("Host:"):
                hostname = header_value.strip(" ")
                url = "https://" + hostname + uri
            else:
                headers[header_name] = header_value

    burp_http_request = HttpRequestModel(
        url=url,
        method=method,
        cookie=cookie,
        headers=headers,
        body=burp_content.requestBody,
        raw=burp_content.requestContent,
    )

    response_first_line = True
    status = 200
    headers = dict()
    for line in burp_content.responseHeaders:
        if response_first_line:
            response_first_line = False
            protocol, status, *_ = line.split()
            continue
        header_name, header_value = line.split(": ", 1)
        headers[header_name] = header_value

    burp_http_response = HttpResponseModel(
        status=status,
        headers=headers,
        body=burp_content.responseBody,
        raw=burp_content.content,
    )

    return burp_http_request, burp_http_response
