# CHANGELOG

## v0.3

Changes and improvements since `v0.2.1`

* [v0.3-beta.1](#v03-beta1) changelog - see notes about backward compatibility
* [v0.3-beta.2](#v03-beta2) changelog

## v0.3-beta.2

Changes and improvements since `v0.3-beta.1`

* Add `haproxy` as the default value of `--ingress-class` parameter
* Fix create/remove ingress based on ingress-class annotation

## v0.3-beta.1

Changes and improvements since `v0.2.1`

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

Changes and improvements since `v0.2`

* Fixes [#14](https://github.com/jcmoraisjr/haproxy-ingress/issues/14) (Incorrect `X-Forwarded-For` handling)

## v0.2

Changes and improvements since `v0.1`

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
