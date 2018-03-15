#!/bin/sh
#
# Copyright 2017 The Kubernetes Authors. All rights reserved.
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

# A script to help with haproxy reloads. Needs sudo for :80.
#
# Receives the reload strategy as the first parameter:
#  native <.cfg>
#    Uses native HAProxy soft restart. Running it for the first time starts
#    HAProxy, each subsequent invocation will perform a soft-reload.
#  reusesocket <.cfg>
#    Pass the listening sockets to the new HAProxy process instead of
#    rebinding them, allowing hitless reloads.
#  multibinder <.cfg.erb>
#    Used on multibinder deployment. Send USR2 to the
#    multibinder-haproxy-wrapper process.
#
# HAProxy options:
#  -f config file
#  -p pid file
#  -D run as daemon
#  -sf soft reload, wait for pids to finish handling requests
#      send pids a resume signal if reload of new config fails
#  -x get the listening sockets from the old HAProxy process

set -e

HAPROXY_SOCKET=/var/run/haproxy-stats.sock
HAPROXY_STATE=/var/lib/haproxy/state-global
mkdir -p /var/lib/haproxy
if [ -S $HAPROXY_SOCKET ]; then
    echo "show servers state" | socat $HAPROXY_SOCKET - > $HAPROXY_STATE
else
    echo "#" > $HAPROXY_STATE
fi
case "$1" in
    native)
        CONFIG="$2"
        HAPROXY_PID=/var/run/haproxy.pid
        haproxy -f "$CONFIG" -p "$HAPROXY_PID" -D -sf $(pidof haproxy 2>/dev/null || :)
        ;;
    reusesocket)
        CONFIG="$2"
        HAPROXY_PID=/var/run/haproxy.pid
        OLD_PID=$(pidof haproxy 2>/dev/null || :)
        if [ -S "$HAPROXY_SOCKET" ]; then
            haproxy -f "$CONFIG" -p "$HAPROXY_PID" -sf $OLD_PID -x "$HAPROXY_SOCKET"
        else
            haproxy -f "$CONFIG" -p "$HAPROXY_PID" -sf $OLD_PID
        fi
        ;;
    multibinder)
        HAPROXY=/usr/local/sbin/haproxy
        CONFIG="$2"
        WRAPPER_PID=/var/run/wrapper.pid
        kill -USR2 $(cat "$WRAPPER_PID")
        ;;
    *)
        echo "Unsupported reload strategy: $1"
        exit 1
        ;;
esac
