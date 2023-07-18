# SPDX-FileCopyrightText: 2023 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: CC0-1.0

from werkzeug.middleware.proxy_fix import ProxyFix
import appledb_filter

app = appledb_filter.App()

app = ProxyFix(
    app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)
