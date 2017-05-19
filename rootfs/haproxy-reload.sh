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

set -e

case "$1" in
    native)
        CONFIG="$2"
        HAPROXY_PID=/var/run/haproxy.pid
        haproxy -f "$CONFIG" -p "$HAPROXY_PID" -D -sf $(cat "$HAPROXY_PID" 2>/dev/null || :)
        ;;
    multibinder)
        HAPROXY=/usr/local/sbin/haproxy
        CONFIG="$2"
        WRAPPER_PID=/var/run/wrapper.pid
        multibinder-haproxy-erb "$HAPROXY" -f "$CONFIG" -c -q
        kill -USR2 $(cat "$WRAPPER_PID")
        ;;
    *)
        echo "Unsupported reload strategy: $1"
        exit 1
        ;;
esac
