#!/bin/sh
#
# Copyright 2021 The HAProxy Ingress Controller Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# A script to help with haproxy reloads. Needs sudo if haproxy uses :80 / :443.
#
# ./haproxy-reload.sh <strategy> <cfg>
#
# <strategy>: `native`
#    Uses native HAProxy soft restart. Running it for the first time starts
#    HAProxy, each subsequent invocation will perform a soft-reload.
# <strategy>: `reusesocket` or any other string != `native`
#    Pass the listening sockets to the new HAProxy process instead of
#    rebinding them, allowing hitless reloads.
#
# <cfg>: configuration file or directory
#
# HAProxy options:
#  -f config file
#  -p pid file
#  -D run as daemon
#  -sf soft reload, wait for pids to finish handling requests
#      send pids a resume signal if reload of new config fails
#  -x get the listening sockets from the old HAProxy process
#

set -e

PARAM_STRATEGY="$1"
PARAM_CFG="$2"

HAPROXY_SOCKET=/var/run/haproxy/admin.sock
HAPROXY_STATE=/var/lib/haproxy/state-global
HAPROXY_PID=/var/run/haproxy/haproxy.pid
OLD_PID=$(cat "$HAPROXY_PID" 2>/dev/null || :)

if [ -S "$HAPROXY_SOCKET" ]; then
    echo "show servers state" | socat "$HAPROXY_SOCKET" - > /tmp/state && mv /tmp/state "$HAPROXY_STATE"
fi
if [ ! -s "$HAPROXY_STATE" ]; then
    echo "#" > "$HAPROXY_STATE"
fi

# Any strategy != `native` means `reusesocket` or `multibinder`
# If there isn't a unix socket (eg first start) fallback to native
if [ "$PARAM_STRATEGY" != "native" ] && [ -S "$HAPROXY_SOCKET" ]; then
    haproxy -f "$PARAM_CFG" -p "$HAPROXY_PID" -D -sf $OLD_PID -x "$HAPROXY_SOCKET"
else
    haproxy -f "$PARAM_CFG" -p "$HAPROXY_PID" -D -sf $OLD_PID
fi
