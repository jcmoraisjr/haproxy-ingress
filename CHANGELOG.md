# CHANGELOG

## Current snapshot tag

Breaking backward compatibility from `v0.5`:

* Usage of header `Host` to match https requests instead of using just sni extension, deprecating `use-host-on-https` - [#130](https://github.com/jcmoraisjr/haproxy-ingress/pull/130)
* Multibinder is deprecated, use `reusesocket` reload strategy instead - [#139](https://github.com/jcmoraisjr/haproxy-ingress/pull/139)

Fixes and improvements since `v0.5`

* HAProxy 1.8
* Dynamic cookies on cookie based server affinity
* HTTP/2 support - [#129](https://github.com/jcmoraisjr/haproxy-ingress/pull/129)
* Share http/s connections on the same frontend/socket - [#130](https://github.com/jcmoraisjr/haproxy-ingress/pull/130)
* Add clear userlist on misconfigured basic auth - [#71](https://github.com/jcmoraisjr/haproxy-ingress/issues/71)
* Fix copy endpoints to fullslots - [#84](https://github.com/jcmoraisjr/haproxy-ingress/issues/84)
* Equality improvement on dynamic scaling  - [#138](https://github.com/jcmoraisjr/haproxy-ingress/issues/138) and [#140](https://github.com/jcmoraisjr/haproxy-ingress/issues/140)
* New annotations:
  * Cookie persistence strategy [#89](https://github.com/jcmoraisjr/haproxy-ingress/pull/89) - [doc](/README.md#affinity)
    * `ingress.kubernetes.io/session-cookie-strategy`
  * Blue/green deployment [#125](https://github.com/jcmoraisjr/haproxy-ingress/pull/125) - [doc](/README.md#blue-green)
    * `ingress.kubernetes.io/blue-green-deploy`
  * Load balancing algorithm [#144](https://github.com/jcmoraisjr/haproxy-ingress/pull/144)
    * `ingress.kubernetes.io/balance-algorithm`
* New configmap options:
  * Drain support for NotReady pods on cookie affinity backends [#95](https://github.com/jcmoraisjr/haproxy-ingress/pull/95) - [doc](/README.md#drain-support)
    * `drain-support`
* New command-line options:
  * Maximum timestamped config files [#123](https://github.com/jcmoraisjr/haproxy-ingress/pull/123) - [doc](/README.md#max-old-config-files)
    * `--max-old-config-files`

## v0.5-beta.3

Fixes and improvements since `v0.5-beta.2`

* Fix sync of excluded secrets - [#102](https://github.com/jcmoraisjr/haproxy-ingress/issues/102)
* Fix config with long fqdn - [#112](https://github.com/jcmoraisjr/haproxy-ingress/issues/112)
* Fix non ssl redirect on default backend - [#120](https://github.com/jcmoraisjr/haproxy-ingress/issues/120)

## v0.5-beta.2

Fixes and improvements since `v0.5-beta.1`

* Fix reading of txn.path on http-request keywords - [#102](https://github.com/jcmoraisjr/haproxy-ingress/issues/102)

## v0.5-beta.1

Breaking backward compatibility from `v0.4`:

* TLS certificate validation using only SAN extension - common Name (CN) isn't used anymore. Add `--verify-hostname=false` command-line option to bypass hostname verification
* `ingress.kubernetes.io/auth-tls-secret` annotation cannot reference another namespace without `--allow-cross-namespace` command-line option
* `tcp-log-format` configmap option now customizes log of TCP proxies, use `https-log-format` instead to configure log of SNI inspection (https/tcp frontend)

Fixes and improvements since `v0.4`

* Change from Go 1.8.1 to 1.9.2
* Implement full config of default backend - [#73](https://github.com/jcmoraisjr/haproxy-ingress/issues/73)
* Fix removal of TLS if failing to read the secretName - [#78](https://github.com/jcmoraisjr/haproxy-ingress/issues/78)
* New annotations:
  * Rewrite path support - [doc](/README.md#rewrite-target)
    * `ingress.kubernetes.io/rewrite-target`
  * Rate limit support - [doc](/README.md#limit)
    * `ingress.kubernetes.io/limit-connections`
    * `ingress.kubernetes.io/limit-rps`
    * `ingress.kubernetes.io/limit-whitelist`
  * Option to include the X509 certificate on requests with client certificate - [doc](/README.md#auth-tls)
    * `ingress.kubernetes.io/auth-tls-cert-header`
  * HSTS support per host and location - [doc](/README.md#hsts)
    * `ingress.kubernetes.io/hsts`
    * `ingress.kubernetes.io/hsts-include-subdomains`
    * `ingress.kubernetes.io/hsts-max-age`
    * `ingress.kubernetes.io/hsts-preload`
* New configmap options:
  * Option to add and customize log of SNI inspection - https/tcp frontend - [doc](/README.md#log-format)
    * `https-log-format`
  * Option to load the server state between HAProxy reloads - [doc](/README.md#load-server-state)
    * `load-server-state`
  * Custom prefix of client certificate headers - [doc](/README.md#ssl-headers-prefix)
    * `ssl-headers-prefix`
  * Support of `Host` header on TLS requests without SNI extension - [doc](/README.md#use-host-on-https)
    * `use-host-on-https`
* New command-line options:
  * Custom rate limit of HAProxy reloads - [doc](/README.md#rate-limit-update)
    * `--rate-limit-update`
  * Support of loading secrets between another namespaces - [doc](/README.md#allow-cross-namespace)
    * `--allow-cross-namespace`
  * TCP services - [doc](/README.md#tcp-services-configmap)
    * `--tcp-services-configmap`
  * Option to skip X509 certificate verification of the hostname - [doc](/README.md#verify-hostname)
    * `--verify-hostname`

## v0.4

Fixes and improvements since `v0.3`

* [v0.4-beta.1](#v04-beta1) changelog
* [v0.4-beta.2](#v04-beta2) changelog

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
