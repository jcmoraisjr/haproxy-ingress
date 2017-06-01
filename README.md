# HAProxy Ingress controller

[Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) controller
implementation for [HAProxy](http://www.haproxy.org/) loadbalancer.

[![Build Status](https://travis-ci.org/jcmoraisjr/haproxy-ingress.svg?branch=master)](https://travis-ci.org/jcmoraisjr/haproxy-ingress) [![Docker Repository on Quay](https://quay.io/repository/jcmoraisjr/haproxy-ingress/status "Docker Repository on Quay")](https://quay.io/repository/jcmoraisjr/haproxy-ingress)

# Releases

HAProxy Ingress images are built by [Travis CI](https://travis-ci.org/jcmoraisjr/haproxy-ingress) and the
image is deployed from Travis CI to [Quay.io](https://quay.io/repository/jcmoraisjr/haproxy-ingress?tag=latest&tab=tags)
whenever a tag is applied. The `latest` tag will always point to the latest stable version while
`canary` tag will always point to the latest deployed version.

# Usage

Usage docs are maintained on Ingress repository:

* Start with [deployment](https://github.com/kubernetes/ingress/tree/master/examples/deployment/haproxy) instructions
* See [TLS termination](https://github.com/kubernetes/ingress/tree/master/examples/tls-termination/haproxy) on how to enable `https`

# Reload strategy

The `--reload-strategy` command-line argument is used to select which reload strategy
HAProxy should use. The following options are available:

Note: at this moment this implementation is only on the `canary` tag.

* `native`: Uses native HAProxy reload option `-sf`. This is the default option.
* `multibinder`: Uses GitHub's [multibinder](https://github.com/github/multibinder). This [link](https://githubengineering.com/glb-part-2-haproxy-zero-downtime-zero-delay-reloads-with-multibinder/)
describes how it works.

# Configuration

HAProxy Ingress can be configured per ingress resource using annotations, or globally
using ConfigMap. It is also possible to change the default template mounting a new
template file at `/usr/local/etc/haproxy/haproxy.tmpl` (changing to
`/etc/haproxy/template/haproxy.tmpl` on 0.3 - current `canary` version).

## Annotations

The following annotations are supported:

`[0]` only on `canary` tag

||Name|Data|Usage|
|---|---|---|:---:|
||`ingress.kubernetes.io/auth-type`|"basic"|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/basic/haproxy)|
||`ingress.kubernetes.io/auth-secret`|secret name|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/basic/haproxy)|
||`ingress.kubernetes.io/auth-realm`|realm string|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/basic/haproxy)|
||`ingress.kubernetes.io/auth-tls-secret`|namespace/secret name|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/client-certs/haproxy)|
|`[0]`|`ingress.kubernetes.io/proxy-body-size`|size (bytes)|-|
|`[0]`|`ingress.kubernetes.io/secure-backends`|[true\|false]|-|
|`[0]`|`ingress.kubernetes.io/secure-verify-ca-secret`|secret name|-|
|`[0]`|`ingress.kubernetes.io/ssl-passthrough`|[true\|false]|-|
||`ingress.kubernetes.io/ssl-redirect`|[true\|false]|[doc](https://github.com/kubernetes/ingress/tree/master/examples/rewrite/haproxy)|
||`ingress.kubernetes.io/app-root`|/url|[doc](https://github.com/kubernetes/ingress/tree/master/examples/rewrite/haproxy)|
||`ingress.kubernetes.io/whitelist-source-range`|CIDR|-|

## ConfigMap

If using ConfigMap to configure HAProxy Ingress, use
`--configmap=<namespace>/<configmap-name>` argument on HAProxy Ingress deployment.
A ConfigMap can be created with `kubectl create configmap`.

The following parameters are supported:

`[0]` only on `canary` tag

||Name|Type|Default|
|---|---|---|---|
|`[0]`|[`balance-algorithm`](#balance-algorithm)|algorithm name|`roundrobin`|
|`[0]`|[`backend-check-interval`](#backend-check-interval)|time with suffix|`2s`|
|`[0]`|[`forwardfor`](#forwardfor)|[add\|ignore\|ifmissing]|`add`|
|`[0]`|[`hsts`](#hsts)|[true\|false]|`true`|
|`[0]`|[`hsts-include-subdomains`](#hsts)|[true\|false]|`false`|
|`[0]`|[`hsts-max-age`](#hsts)|number of seconds|`15768000`|
|`[0]`|[`hsts-preload`](#hsts)|[true\|false]|`false`|
|`[0]`|[`max-connections`](#max-connections)|number|`2000`|
|`[0]`|[`proxy-body-size`](#proxy-body-size)|number of bytes|unlimited|
|`[0]`|[`ssl-ciphers`](#ssl-ciphers)|colon-separated list|[link to code](https://github.com/jcmoraisjr/haproxy-ingress/blob/master/pkg/controller/config.go#L33)|
|`[0]`|[`ssl-dh-default-max-size`](#ssl-dh-default-max-size)|number|`1024`|
|`[0]`|[`ssl-dh-param`](#ssl-dh-param)|namespace/secret name|no custom DH param|
|`[0]`|[`ssl-options`](#ssl-options)|space-separated list|`no-sslv3` `no-tls-tickets`|
||[`ssl-redirect`](#ssl-redirect)|[true\|false]|`true`|
|`[0]`|[`stats-auth`](#stats)|user:passwd|no auth|
|`[0]`|[`stats-port`](#stats)|port number|`1936`|
||[`syslog-endpoint`](#syslog-endpoint)|IP:port (udp)|do not log|
|`[0]`|[`timeout-client`](#timeout)|time with suffix|`50s`|
|`[0]`|[`timeout-client-fin`](#timeout)|time with suffix|`50s`|
|`[0]`|[`timeout-connect`](#timeout)|time with suffix|`5s`|
|`[0]`|[`timeout-http-request`](#timeout)|time with suffix|`5s`|
|`[0]`|[`timeout-keep-alive`](#timeout)|time with suffix|`1m`|
|`[0]`|[`timeout-server`](#timeout)|time with suffix|`50s`|
|`[0]`|[`timeout-server-fin`](#timeout)|time with suffix|`50s`|
|`[0]`|[`timeout-tunnel`](#timeout)|time with suffix|`1h`|

### balance-algorithm

Define a load balancing algorithm.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#4-balance

### backend-check-interval

Define the interval between TCP health checks to the backend using `inter` option.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#5.2-inter

### forwardfor

Define if `X-Forwarded-For` header should be added always, added if missing or
ignored from incomming requests. Default is `add` which means HAProxy will itself
generate a `X-Forwarded-For` header with client's IP address and remove this same
header from incomming requests.

Use `ignore` to skip any check. `ifmissing` should be used to add
`X-Forwarded-For` with client's IP address only if this header is not defined.
Only use `ignore` or `ifmissing` on trusted networks.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#4-option%20forwardfor

### hsts

Configure HSTS - HTTP Strict Transport Security.

* `hsts`: `true` if HSTS response header should be added
* `hsts-include-subdomains`: `true` if it should apply to subdomains as well
* `hsts-max-age`: time in seconds the browser should remember this configuration
* `hsts-preload`: `true` if the browser should include the domain to [HSTS preload list](https://hstspreload.org/)

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

### max-connections

Define the maximum number of concurrent connections. Defaults to `2000` connections,
which is also the HAProxy default configuration.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#5.2-maxconn

### proxy-body-size

Define the maximum number of bytes HAProxy will allow on the body of requests. Default is
to not check, which means requests of unlimited size. This limit can be changed per ingress
resource.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#7.3.6-req.body_size

### ssl-ciphers

Set the list of cipher algorithms used during the SSL/TLS handshake.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#3.1-ssl-default-bind-ciphers

### ssl-dh-default-max-size

Define the maximum size of a temporary DH parameters used for key exchange.
Only used if `ssl-dh-param` isn't provided.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#tune.ssl.default-dh-param

### ssl-dh-param

Define DH parameters file used on ephemeral Diffie-Hellman key exchange during
the SSL/TLS handshake.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#3.1-ssl-dh-param-file

### ssl-options

Define a space-separated list of options on SSL/TLS connections:

* `force-sslv3`: Enforces use of SSLv3 only
* `force-tlsv10`: Enforces use of TLSv1.0 only
* `force-tlsv11`: Enforces use of TLSv1.1 only
* `force-tlsv12`: Enforces use of TLSv1.2 only
* `no-sslv3`: Disables support for SSLv3
* `no-tls-tickets`: Enforces the use of stateful session resumption
* `no-tlsv10`: Disables support for TLSv1.0
* `no-tlsv11`: Disables support for TLSv1.1
* `no-tlsv12`: Disables support for TLSv1.2

### ssl-redirect

A global configuration of SSL redirect used as default value if ingress resource
doesn't use `ssl-redirect` annotation. If true HAProxy Ingress sends a `302 redirect`
to https if TLS is [configured](https://github.com/kubernetes/ingress/tree/master/examples/tls-termination/haproxy).

### stats

Configurations of the HAProxy status page:

* `stats-auth`: Enable basic authentication with clear-text password - `<user>:<passwd>`
* `stats-port`: Change the port HAProxy should listen to requests

### syslog-endpoint

Configure the UDP syslog endpoint where HAProxy should send access logs.

### timeout

Define timeout configurations:

* `timeout-client`: Maximum inactivity time on the client side
* `timeout-client-fin`: Maximum inactivity time on the client side for half-closed connections - FIN_WAIT state
* `timeout-connect`: Maximum time to wait for a connection to a backend
* `timeout-http-request`: Maximum time to wait for a complete HTTP request
* `timeout-keep-alive`: Maximum time to wait for a new HTTP request on keep-alive connections
* `timeout-server`: Maximum inactivity time on the backend side
* `timeout-server-fin`: Maximum inactivity time on the backend side for half-closed connections - FIN_WAIT state
* `timeout-tunnel`: Maximum inactivity time on the client and backend side for tunnels
