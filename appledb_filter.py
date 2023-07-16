# Copyright © 2023 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: MIT

import configparser
import hmac, hashlib

from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import NotFound, MethodNotAllowed, Forbidden, HTTPException

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

        return Response("data: " + repr(request.data))

    def __call__(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = App()
    run_simple('127.0.0.1', 5000, app, use_debugger=False, use_reloader=True)
