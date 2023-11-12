from models.http import HttpRequestModel


def http_request_parser(http_request: str):
    request_body = ""
    is_body = False
    is_first_line = True
    method = "GET"
    cookie = {}
    uri = ""
    url = ""
    headers = dict()
    for line in http_request.split("\r\n"):
        line = line.strip("\r\n")
        if is_first_line:
            is_first_line = False
            method, uri, _ = line.split()
            continue
        if not line:
            is_body = True
        if is_body:
            request_body += line + "\r\n"
        else:
            if line.startswith("Content-Length:"):
                continue
            header_name, *header_values = line.strip("\r\n").split(":")
            if line.startswith("Cookie:"):
                cookie_var = ":".join(header_values)
                for ck in cookie_var.split(";"):
                    k, *v = ck.split("=")
                    cookie[k.strip()] = "=".join(v).strip(" ;")
            if line.startswith("Host:"):
                hostname = ":".join(header_values).strip(" ")
                url = "https://" + hostname + uri
            else:
                headers[header_name.strip(" ")] = ":".join(header_values)

    return HttpRequestModel(
        url=url,
        method=method,
        cookie=cookie,
        headers=headers
    )
