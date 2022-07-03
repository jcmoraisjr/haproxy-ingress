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

FROM golang:1.17.11-alpine AS builder

ARG GIT_TAG
WORKDIR /src
RUN apk --no-cache add git

COPY . .

RUN GIT_TAG=${GIT_TAG:-latest}\
 && GIT_COMMIT=git-$(git rev-parse --short HEAD)\
 && GIT_REPO=$(git config --get remote.origin.url)\
 && VERSION_PKG=github.com/jcmoraisjr/haproxy-ingress/pkg/version\
 && CGO_ENABLED=0 go build\
    -ldflags "-s -w -X ${VERSION_PKG}.RELEASE=${GIT_TAG} -X ${VERSION_PKG}.COMMIT=${GIT_COMMIT} -X ${VERSION_PKG}.REPO=${GIT_REPO}"\
    -o haproxy-ingress pkg/main.go

FROM haproxy:2.4.17-alpine

USER root

RUN apk --no-cache add socat openssl lua5.3 lua-json4 dumb-init

COPY rootfs/ /
COPY --from=builder /src/haproxy-ingress /haproxy-ingress-controller

RUN deluser haproxy\
 && addgroup -g 1001 haproxy\
 && adduser -u 1001 -G haproxy -D -s /bin/false haproxy\
 && mkdir -p /var/empty /etc/haproxy /var/lib/haproxy /var/run/haproxy\
 && chown -R haproxy:haproxy /etc/haproxy /var/lib/haproxy /var/run/haproxy\
 && chmod 0 /var/empty

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/start.sh"]
