# Copyright © 2023 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: MIT

import unittest
import hmac, hashlib
from werkzeug.test import Client

import appledb_filter

class TestApp(unittest.TestCase):
    def setUp(self):
        self.app = appledb_filter.App({"github-filter": {
            "uri": "/webhook",
            "token": "12345678"
        }})
        self.client = Client(self.app)

    def test_notfound(self):
        response = self.client.get("/asd")
        self.assertEqual(response.status_code, 404)

    def test_rejects_get(self):
        response = self.client.get("/webhook")
        self.assertEqual(response.status_code, 405)

    def do_signed_post(self, data, key=b'12345678'):
        sig_sha1 = hmac.new(key, msg=data, digestmod=hashlib.sha1)
        sig_sha256 = hmac.new(key, msg=data, digestmod=hashlib.sha256)
        return self.client.post(
            "/webhook",
            data=data,
            headers={
                "x-hub-signature":      f"sha1={sig_sha1.hexdigest()}",
                "x-hub-signature-256":  f"sha256={sig_sha256.hexdigest()}"
            }
        )

    def test_bad_signature(self):
        data = '{"payload": 42}'.encode('utf8')
        response = self.do_signed_post(data, key=b'differentkey')
        self.assertEqual(response.status_code, 403)

    def test_good_signature(self):
        data = '{"payload": 42}'.encode('utf8')
        response = self.do_signed_post(data)
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
