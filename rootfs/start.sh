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

set -e

init() {
    if [ $# -gt 0 ] && [ "$(echo $1 | cut -b1-2)" != "--" ]; then
        exec "$@"
        exit 0
    fi
    reloadStrategy=$(
        echo "$*" | sed -nr 's/.*--reload-strategy[ =]([^ ]+).*/\1/p'
    )
    reloadStrategy="${reloadStrategy:-native}"
    case "$reloadStrategy" in
        native)
            ;;
        multibinder)
            HAPROXY=/usr/local/sbin/haproxy
            TEMPLATE=/etc/haproxy/template/haproxy.tmpl
            CONFIG=/etc/haproxy/haproxy.cfg.erb
            WRAPPER_PID=/var/run/wrapper.pid
            HAPROXY_PID=/var/run/haproxy.pid
            create_erb
            start_multibinder
            ;;
        *)
            echo "Unsupported reload strategy: $reloadStrategy"
            exit 1
            ;;
    esac
    echo "Reload strategy: $reloadStrategy"
    exec /haproxy-ingress-controller "$@"
}

create_erb() {
    # Create a minimal valid starting configuration file
    cat > "$CONFIG" <<EOF
global
    daemon
listen main
    bind unix@/var/run/haproxy-tmp.sock
    timeout client 1s
    timeout connect 1s
    timeout server 1s
EOF

    # Add erb code to a new template file
    # - [0-9]* will match actual ports, for example 443 in bind *:443
    # - {{[^}]*}} will match when the port is templatized, for example {{ $cfg.StatsPort }} in bind *:{{ $cfg.StatsPort }}
    sed "/^    bind \+\*\?:/s/\*\?:\(\([0-9]*\)\|\({{[^}]*}}\)\)/<%= bind_tcp('0.0.0.0', \1) %>/" \
        "$TEMPLATE" > "${CONFIG}.tmpl"
}

start_multibinder() {
    # Start multibinder
    export MULTIBINDER_SOCK=/run/multibinder.sock
    multibinder "$MULTIBINDER_SOCK" &
    multibinder_pid=$!

    # Wait for socket
    while [ ! -S "$MULTIBINDER_SOCK" ]; do
        sleep 1
    done

    # Create initial config
    multibinder-haproxy-erb "$HAPROXY" -f "$CONFIG" -c -q

    # Start HAProxy
    multibinder-haproxy-wrapper "$HAPROXY" -Ds -f "$CONFIG" -p "$HAPROXY_PID" &
    wrapper_pid=$!
    echo $wrapper_pid > "$WRAPPER_PID"
}

init "$@"
