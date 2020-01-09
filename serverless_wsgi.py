#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module converts an AWS API Gateway proxied request to a WSGI request.

Inspired by: https://github.com/miserlou/zappa

Author: Logan Raarup <logan@logan.dk>
"""
import base64
import os
import sys
import logging
from werkzeug.datastructures import Headers, MultiDict
from werkzeug.wrappers import Response
from werkzeug.urls import url_encode, url_unquote
from werkzeug.http import HTTP_STATUS_CODES
from werkzeug._compat import BytesIO, string_types, to_bytes, wsgi_encoding_dance

LOGGER = logging.getLogger(__name__)

# List of MIME types that should not be base64 encoded. MIME types within `text/*`
# are included by default.
TEXT_MIME_TYPES = [
    "application/json",
    "application/javascript",
    "application/xml",
    "application/vnd.api+json",
    "image/svg+xml",
]


def all_casings(input_string):
    """
    Permute all casings of a given string.
    A pretty algoritm, via @Amber
    http://stackoverflow.com/questions/6792803/finding-all-possible-case-permutations-in-python
    """
    if not input_string:
        yield ""
    else:
        first = input_string[:1]
        if first.lower() == first.upper():
            for sub_casing in all_casings(input_string[1:]):
                yield first + sub_casing
        else:
            for sub_casing in all_casings(input_string[1:]):
                yield first.lower() + sub_casing
                yield first.upper() + sub_casing


def split_headers(headers):
    """
    If there are multiple occurrences of headers, create case-mutated variations
    in order to pass them through APIGW. This is a hack that's currently
    needed. See: https://github.com/logandk/serverless-wsgi/issues/11
    Source: https://github.com/Miserlou/Zappa/blob/master/zappa/middleware.py
    """
    new_headers = {}

    for key in headers.keys():
        values = headers.get_all(key)
        if len(values) > 1:
            for value, casing in zip(values, all_casings(key)):
                new_headers[casing] = value
        elif len(values) == 1:
            new_headers[key] = values[0]

    return new_headers


def group_headers(headers):
    new_headers = {}

    for key in headers.keys():
        new_headers[key] = headers.get_all(key)

    return new_headers


def encode_query_string(event):
    multi = event.get(u"multiValueQueryStringParameters")
    if multi:
        return url_encode(MultiDict((i, j) for i in multi for j in multi[i]))
    else:
        return url_encode(event.get(u"queryStringParameters") or {})


def handle_request(app, event, context):
    if event.get("source") in ["aws.events", "serverless-plugin-warmup"]:
        LOGGER.debug("Lambda warming event received, skipping handler")
        return {}

    if u"multiValueHeaders" in event:
        headers = Headers(event[u"multiValueHeaders"])
    else:
        headers = Headers(event[u"headers"])

    strip_stage_path = os.environ.get("STRIP_STAGE_PATH", "").lower().strip() in [
        "yes",
        "y",
        "true",
        "t",
        "1",
    ]

    event_request_context = event['requestContext']
    resource_path = event_request_context['resourcePath']

    proxy_index = resource_path.find('{')
    #Get string index if you find a bracket for {proxy +} 
    #otherwise return -1 the end of the string

    resource_path_no_proxy = resource_path[:proxy_index]

    #Start with index 1 to prevent \ {proxy+} to clean all path
    resource_start_index = event_request_context['path'].find(resource_path_no_proxy, 1)

    script_name = event_request_context['path'][:resource_start_index]

    path_info = event[u"path"]
  

    body = event[u"body"] or ""
    if event.get("isBase64Encoded", False):
        body = base64.b64decode(body)
    if isinstance(body, string_types):
        body = to_bytes(body, charset="utf-8")

    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": headers.get(u"Content-Type", ""),
        "PATH_INFO": url_unquote(path_info),
        "QUERY_STRING": encode_query_string(event),
        "REMOTE_ADDR": event[u"requestContext"]
        .get(u"identity", {})
        .get(u"sourceIp", ""),
        "REMOTE_USER": event[u"requestContext"]
        .get(u"authorizer", {})
        .get(u"principalId", ""),
        "REQUEST_METHOD": event[u"httpMethod"],
        "SCRIPT_NAME": script_name,
        "SERVER_NAME": headers.get(u"Host", "lambda"),
        "SERVER_PORT": headers.get(u"X-Forwarded-Port", "80"),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.errors": sys.stderr,
        "wsgi.input": BytesIO(body),
        "wsgi.multiprocess": False,
        "wsgi.multithread": False,
        "wsgi.run_once": False,
        "wsgi.url_scheme": headers.get(u"X-Forwarded-Proto", "http"),
        "wsgi.version": (1, 0),
        "serverless.authorizer": event[u"requestContext"].get(u"authorizer"),
        "serverless.event": event,
        "serverless.context": context,
        # TODO: Deprecate the following entries, as they do not comply with the WSGI
        # spec. For custom variables, the spec says:
        #
        #   Finally, the environ dictionary may also contain server-defined variables.
        #   These variables should be named using only lower-case letters, numbers, dots,
        #   and underscores, and should be prefixed with a name that is unique to the
        #   defining server or gateway.
        "API_GATEWAY_AUTHORIZER": event[u"requestContext"].get(u"authorizer"),
        "event": event,
        "context": context,
    }

    for key, value in environ.items():
        if isinstance(value, string_types):
            environ[key] = wsgi_encoding_dance(value)

    for key, value in headers.items():
        key = "HTTP_" + key.upper().replace("-", "_")
        if key not in ("HTTP_CONTENT_TYPE", "HTTP_CONTENT_LENGTH"):
            environ[key] = value

    #Não sei o que faz o werkzeug.wrapper.response.from_app 
    #saber o que o environ é necessario
    #como é utilizado o script_name
    response = Response.from_app(app, environ)

    print(f"Response: \n{response}")
    returndict = {u"statusCode": response.status_code}

    if u"multiValueHeaders" in event:
        returndict[u"multiValueHeaders"] = group_headers(response.headers)
    else:
        returndict[u"headers"] = split_headers(response.headers)

    if event.get("requestContext").get("elb"):
        # If the request comes from ALB we need to add a status description
        returndict["statusDescription"] = u"%d %s" % (
            response.status_code,
            HTTP_STATUS_CODES[response.status_code],
        )

    if response.data:
        mimetype = response.mimetype or "text/plain"
        if (
            mimetype.startswith("text/") or mimetype in TEXT_MIME_TYPES
        ) and not response.headers.get("Content-Encoding", ""):
            returndict["body"] = response.get_data(as_text=True)
            returndict["isBase64Encoded"] = False
        else:
            returndict["body"] = base64.b64encode(response.data).decode("utf-8")
            returndict["isBase64Encoded"] = True
    print(f"ReturnDict: {returndict}")
    return returndict
