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

FROM haproxy:2.2.3-alpine
RUN apk --no-cache add socat openssl lua5.3 lua-socket dumb-init

COPY . /

RUN addgroup -g 1001 haproxy\
 && adduser -u 1001 -G haproxy -D -s /bin/false haproxy\
 && mkdir -p /var/empty /etc/haproxy /var/lib/haproxy /var/run/haproxy\
 && chown -R haproxy:haproxy /etc/haproxy /var/lib/haproxy /var/run/haproxy\
 && chmod 0 /var/empty

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/start.sh"]
