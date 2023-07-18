#!/bin/bash

# SPDX-FileCopyrightText: 2023 Nicolás Alvarez <nicolas.alvarez@gmail.com>
#
# SPDX-License-Identifier: CC0-1.0

set -e

install -C -v -o0 -g0 -m0644 -t /etc/systemd/system/ appledb-filter.service appledb-filter.socket
systemctl daemon-reload
