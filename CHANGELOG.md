# CHANGELOG

## v0.4-beta.2

Fixes and improvements since `v0.4-beta.1`

* Fix global `maxconn` configuration
* Add `X-Forwarded-Proto: https` header on ssl/tls connections

## v0.4-beta.1

Fixes and improvements since `v0.3`

* Add dynamic scaling - [doc](https://github.com/jcmoraisjr/haproxy-ingress#dynamic-scaling)
* Add monitoring URI - [doc](https://github.com/jcmoraisjr/haproxy-ingress#healthz-port)
* Add [PROXY](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) protocol configmap options - [doc](https://github.com/jcmoraisjr/haproxy-ingress#use-proxy-protocol)
  * `UseProxyProtocol`
  * `StatsProxyProtocol`
* Add log format configmap options - [doc](https://github.com/jcmoraisjr/haproxy-ingress#log-format)
  * `HTTPLogFormat`
  * `TCPLogFormat`
* Add stick session ingress annotations - [doc](https://github.com/jcmoraisjr/haproxy-ingress#affinity)
  * `ingress.kubernetes.io/affinity`
  * `ingress.kubernetes.io/session-cookie-name`
* Support for wildcard hostnames
* Better and faster synchronization after resource updates
* Support `k`, `m` and `g` suffix on `proxy-body-size` annotation and configmap option - [doc](https://github.com/jcmoraisjr/haproxy-ingress#proxy-body-size)
* HTTP 495 and 496 error pages on auth TLS errors
* Add TLS error page ingress annotation
  * `ingress.kubernetes.io/auth-tls-error-page`
* Add support to SSL/TLS offload outside HAProxy on a configmap option - [doc](https://github.com/jcmoraisjr/haproxy-ingress#https-to-http-port)
  * `https-to-http-port`
* Add support to host alias on ingress annotation - [doc](https://github.com/jcmoraisjr/haproxy-ingress#server-alias)
  * `ingress.kubernetes.io/server-alias`
* Fix multibinder goes zombie [#51](https://github.com/jcmoraisjr/haproxy-ingress/issues/51) updating to multibinder 0.0.5
* Add `X-SSL` headers on client authentication with TLS
  * `X-SSL-Client-SHA1`
  * `X-SSL-Client-DN`
  * `X-SSL-Client-CN`

## v0.3

Fixes and improvements since `v0.2.1`

* [v0.3-beta.1](#v03-beta1) changelog - see notes about backward compatibility
* [v0.3-beta.2](#v03-beta2) changelog

## v0.3-beta.2

Fixes and improvements since `v0.3-beta.1`

* Add `haproxy` as the default value of `--ingress-class` parameter
* Fix create/remove ingress based on ingress-class annotation

## v0.3-beta.1

Fixes and improvements since `v0.2.1`

Breaking backward compatibility:

* Move template to `/etc/haproxy/template/haproxy.tmpl`
* Now `ingress.kubernetes.io/app-root` only applies on ingress with root path `/`

Other changes and improvements:

* Reload strategy with `native` and `multibinder` options
* Ingress Controller check for update every 2 seconds (was every 10 seconds)
* New ingress resource annotations
  * `ingress.kubernetes.io/proxy-body-size`
  * `ingress.kubernetes.io/secure-backends`
  * `ingress.kubernetes.io/secure-verify-ca-secret`
  * `ingress.kubernetes.io/ssl-passthrough`
* New configmap options
  * `balance-algorithm`
  * `backend-check-interval`
  * `forwardfor`
  * `hsts`
  * `hsts-include-subdomains`
  * `hsts-max-age`
  * `hsts-preload`
  * `max-connections`
  * `proxy-body-size`
  * `ssl-ciphers`
  * `ssl-dh-default-max-size`
  * `ssl-dh-param`
  * `ssl-options`
  * `stats-auth`
  * `stats-port`
  * `timeout-client`
  * `timeout-client-fin`
  * `timeout-connect`
  * `timeout-http-request`
  * `timeout-keep-alive`
  * `timeout-server`
  * `timeout-server-fin`
  * `timeout-tunnel`

## v0.2.1

Fixes and improvements since `v0.2`

* Fixes [#14](https://github.com/jcmoraisjr/haproxy-ingress/issues/14) (Incorrect `X-Forwarded-For` handling)

## v0.2

Fixes and improvements since `v0.1`

* White list source IP range
* Optionally force TLS connection
* Basic (user/passwd) authentication
* Client certificate authentication
* Root context redirect

## v0.1

Initial version with basic functionality

* rules.hosts with paths from Ingress resource
* default and per host certificate
* 302 redirect from http to https if TLS (default or per host) is provided
* syslog-endpoint from configmap
