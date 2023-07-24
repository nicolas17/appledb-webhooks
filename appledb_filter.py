# Copyright © 2023 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: MIT

import configparser
import hmac, hashlib
import traceback

from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import (
    NotFound,
    MethodNotAllowed,
    Forbidden,
    GatewayTimeout,
    BadGateway,
    HTTPException
)

import requests

def parse_config(filename):
    parser = configparser.ConfigParser()
    parser.read(filename)

class App:
    def __init__(self, config=None):
        self.config = configparser.ConfigParser()
        if config is None:
            self.config.read("config.ini")
        else:
            self.config.read_dict(config)
        self.token = self.config["github-filter"]["token"].encode('utf8')
        self.target_uri = self.config["github-filter"]["target-uri"]

    def dispatch_request(self, request):
        if request.path != self.config["github-filter"]["uri"]: return NotFound()
        if request.method != 'POST': return MethodNotAllowed()

        try:
            return self.handle_webhook_request(request)
        except HTTPException as e:
            return e

    def do_sig_check(self, request):
        header_sig = request.headers.get("x-hub-signature-256", "missing")
        hash_object = hmac.new(self.token, request.data, digestmod=hashlib.sha256)
        calculated_sig = "sha256=" + hash_object.hexdigest()
        return hmac.compare_digest(header_sig, calculated_sig)

    def handle_webhook_request(self, request):
        if not self.do_sig_check(request):
            raise Forbidden()

        json = request.json

        delivery_id = None
        if "x-github-delivery" in request.headers:
            delivery_id = request.headers["x-github-delivery"]
            if all(x in '0123456789abcdef-' for x in delivery_id):
                with open(f"logs/{delivery_id}.json", "wb") as f:
                    f.write(request.data)
                with open(f"logs/{delivery_id}.req", "w") as f:
                    for k,v in request.headers.items():
                        f.write(f"{k}: {v}\n")

        if (request.headers.get('x-github-event') == 'push' and
            json.get('ref') == 'refs/heads/gh-pages' and
            json.get('sender',{}).get('login') == 'github-actions[bot]' and
            json.get('pusher',{}).get('name') == 'github-actions[bot]' and
            json.get('forced') == True):
            if delivery_id:
                with open(f"logs/{delivery_id}.req", "a") as f:
                    f.write(f"Skipping this webhook, github-actions force-push to gh-pages branch\n")
            return Response("Skipping this webhook event")

        if (request.headers.get('x-github-event') == 'push' and
            json.get('repository',{}).get('organization') == 'cfw-guide' and
            json.get('sender',{}).get('login') == 'emiyl' and
            json.get('head_commit',{}).get('author',{}).get('username') == 'actions-user' and
            json.get('head_commit',{}).get('committer',{}).get('username') == 'actions-user' and
            json.get('head_commit',{}).get('message','') == 'Update AppleDB submodule'):
            if delivery_id:
                with open(f"logs/{delivery_id}.req", "a") as f:
                    f.write(f"Skipping this webhook, submodule update on guide repo\n")
            return Response("Skipping this webhook event")

        FORWARDED_HEADERS = [
            "Accept",
            "X-GitHub-Delivery",
            "X-GitHub-Event",
            "X-GitHub-Hook-ID",
            "X-GitHub-Hook-Installation-Target-ID",
            "X-GitHub-Hook-Installation-Target-Type",
            "X-Hub-Signature",
            "X-Hub-Signature-256",
            "Content-Type"
        ]
        headers = {}
        for header_name in FORWARDED_HEADERS:
            if header_name in request.headers:
                headers[header_name] = request.headers[header_name]

        try:
            resp = requests.post(self.target_uri, headers=headers, data=request.data)
        except requests.exceptions.ConnectTimeout as e:
            raise GatewayTimeout()
        except requests.exceptions.ConnectionError as e:
            raise BadGateway()

        return Response("data: " + repr(request.data))

    def __call__(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = App()
    run_simple('127.0.0.1', 5000, app, use_debugger=False, use_reloader=True)
