# HAProxy Ingress controller

[Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) controller
implementation for [HAProxy](http://www.haproxy.org/) loadbalancer.

[![Build Status](https://travis-ci.org/jcmoraisjr/haproxy-ingress.svg?branch=master)](https://travis-ci.org/jcmoraisjr/haproxy-ingress) [![Docker Repository on Quay](https://quay.io/repository/jcmoraisjr/haproxy-ingress/status "Docker Repository on Quay")](https://quay.io/repository/jcmoraisjr/haproxy-ingress)

# Releases

HAProxy Ingress images are built by [Travis CI](https://travis-ci.org/jcmoraisjr/haproxy-ingress) and the
image is deployed from Travis CI to [Quay.io](https://quay.io/repository/jcmoraisjr/haproxy-ingress?tag=latest&tab=tags)
whenever a tag is applied. The `latest` tag will always point to the latest stable version while
`canary` tag will always point to the latest beta-quality and release-candidate versions.

Before the beta-quality releases, the source code could also be tagged and images deployed.
The `snapshot` tag will always point to the latest tagged version, which could be a release,
a beta-quality or a development version.

# Usage

Usage docs are maintained on Ingress repository:

* Start with [deployment](https://github.com/kubernetes/ingress/tree/master/examples/deployment/haproxy) instructions
* See [TLS termination](https://github.com/kubernetes/ingress/tree/master/examples/tls-termination/haproxy) on how to enable `https`

# Reload strategy

The `--reload-strategy` command-line argument is used to select which reload strategy
HAProxy should use. The following options are available:

* `native`: Uses native HAProxy reload option `-sf`. This is the default option.
* `multibinder`: Uses GitHub's [multibinder](https://github.com/github/multibinder). This [link](https://githubengineering.com/glb-part-2-haproxy-zero-downtime-zero-delay-reloads-with-multibinder/)
describes how it works.

# Configuration

HAProxy Ingress can be configured per ingress resource using annotations, or globally
using ConfigMap. It is also possible to change the default template mounting a new
template file at `/etc/haproxy/template/haproxy.tmpl`.

## Annotations

The following annotations are supported:

* `[0]` only in `canary` tag
* `[1]` only in `snapshot` tag

||Name|Data|Usage|
|---|---|---|:---:|
|`[0]`|[`ingress.kubernetes.io/affinity`](#affinity)|affinity type|-|
||`ingress.kubernetes.io/auth-type`|"basic"|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/basic/haproxy)|
||`ingress.kubernetes.io/auth-secret`|secret name|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/basic/haproxy)|
||`ingress.kubernetes.io/auth-realm`|realm string|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/basic/haproxy)|
|`[0]`|`ingress.kubernetes.io/auth-tls-error-page`|url|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/client-certs/haproxy)|
||`ingress.kubernetes.io/auth-tls-secret`|namespace/secret name|[doc](https://github.com/kubernetes/ingress/tree/master/examples/auth/client-certs/haproxy)|
|`[1]`|[`ingress.kubernetes.io/limit-connections`](#limit)|qty|-|
|`[1]`|[`ingress.kubernetes.io/limit-rps`](#limit)|rate per second|-|
|`[1]`|[`ingress.kubernetes.io/limit-whitelist`](#limit)|cidr list|-|
||[`ingress.kubernetes.io/proxy-body-size`](#proxy-body-size)|size (bytes)|-|
||`ingress.kubernetes.io/secure-backends`|[true\|false]|-|
||`ingress.kubernetes.io/secure-verify-ca-secret`|secret name|-|
|`[0]`|[`ingress.kubernetes.io/session-cookie-name`](#affinity)|cookie name|-|
||`ingress.kubernetes.io/ssl-passthrough`|[true\|false]|-|
||`ingress.kubernetes.io/ssl-redirect`|[true\|false]|[doc](https://github.com/kubernetes/ingress/tree/master/examples/rewrite/haproxy)|
||`ingress.kubernetes.io/app-root`|/url|[doc](https://github.com/kubernetes/ingress/tree/master/examples/rewrite/haproxy)|
||`ingress.kubernetes.io/whitelist-source-range`|CIDR|-|
|`[1]`|[`ingress.kubernetes.io/rewrite-target`](#rewrite-target)|path string|-|
|`[0]`|[`ingress.kubernetes.io/server-alias`](#server-alias)|domain name or regex|-|

### Affinity

Configure if HAProxy should maintain client requests to the same backend server.

* `ingress.kubernetes.io/affinity`: the only supported option is `cookie`. If declared, clients will receive a cookie with a hash of the server it should be fidelized to.
* `ingress.kubernetes.io/session-cookie-name`: the name of the cookie. `INGRESSCOOKIE` is the default value if not declared.

Note for `dynamic-scaling` users only: the hash of the server is built based on it's name.
When the slots are scaled down, the remaining servers might change it's server name on
HAProxy configuration. In order to circumvent this, always configure the slot increment at
least as much as the number of replicas of the deployment that need to use affinity. This
limitation will be removed when HAProxy version is updated to `1.8`.

* http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#4-cookie
* http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#5.2-cookie
* https://www.haproxy.com/blog/load-balancing-affinity-persistence-sticky-sessions-what-you-need-to-know/

### Limit

Configure rate limit and concurrent connections per client IP address in order to mitigate DDoS attack.
If several users are hidden behind the same IP (NAT or proxy), this configuration may have a negative
impact for them. Whitelist can be used to these IPs.

The following annotations are supported:

* `ingress.kubernetes.io/limit-connections`: Maximum number os concurrent connections per client IP
* `ingress.kubernetes.io/limit-rps`: Maximum number of connections per second of the same IP
* `ingress.kubernetes.io/limit-whitelist`: Comma separated list of CIDRs that should be removed from the rate limit and concurrent connections check

### Server Alias

Creates an alias of the server that annotation belongs to.
It'll be using the same backend but different ACL.
Alias rules will be checked at the very end of list or rules.
It is allowed to be a regex.

Note: `^` and `$` cannot be used because they are already included in ACL.

### Rewrite Target

Supported rewrite annotations:

* `/`
* `/path1`
* `/path1/path2`

Trailing slashes on rewrite target annotations are not supported.

## ConfigMap

If using ConfigMap to configure HAProxy Ingress, use
`--configmap=<namespace>/<configmap-name>` argument on HAProxy Ingress deployment.
A ConfigMap can be created with `kubectl create configmap`.

The following parameters are supported:

* `[0]` only in `canary` tag

||Name|Type|Default|
|---|---|---|---|
||[`balance-algorithm`](#balance-algorithm)|algorithm name|`roundrobin`|
||[`backend-check-interval`](#backend-check-interval)|time with suffix|`2s`|
|`[0]`|[`backend-server-slots-increment`](#dynamic-scaling)|number of slots|`32`|
|`[0]`|[`dynamic-scaling`](#dynamic-scaling)|[true\|false]|`false`|
||[`forwardfor`](#forwardfor)|[add\|ignore\|ifmissing]|`add`|
|`[0]`|[`healthz-port`](#healthz-port)|port number|`10253`|
||[`hsts`](#hsts)|[true\|false]|`true`|
||[`hsts-include-subdomains`](#hsts)|[true\|false]|`false`|
||[`hsts-max-age`](#hsts)|number of seconds|`15768000`|
||[`hsts-preload`](#hsts)|[true\|false]|`false`|
|`[0]`|[`http-log-format`](#log-format)|http log format|HAProxy default log format|
|`[0]`|[`https-to-http-port`](#https-to-http-port)|port number|0 (do not listen)|
||[`max-connections`](#max-connections)|number|`2000`|
||[`proxy-body-size`](#proxy-body-size)|number of bytes|unlimited|
||[`ssl-ciphers`](#ssl-ciphers)|colon-separated list|[link to code](https://github.com/jcmoraisjr/haproxy-ingress/blob/master/pkg/controller/config.go#L34)|
||[`ssl-dh-default-max-size`](#ssl-dh-default-max-size)|number|`1024`|
||[`ssl-dh-param`](#ssl-dh-param)|namespace/secret name|no custom DH param|
||[`ssl-options`](#ssl-options)|space-separated list|`no-sslv3` `no-tls-tickets`|
||[`ssl-redirect`](#ssl-redirect)|[true\|false]|`true`|
||[`stats-auth`](#stats)|user:passwd|no auth|
||[`stats-port`](#stats)|port number|`1936`|
|`[0]`|[`stats-proxy-protocol`](#stats)|[true\|false]|`false`|
||[`syslog-endpoint`](#syslog-endpoint)|IP:port (udp)|do not log|
|`[0]`|[`tcp-log-format`](#log-format)|tcp log format|HAProxy default log format|
||[`timeout-client`](#timeout)|time with suffix|`50s`|
||[`timeout-client-fin`](#timeout)|time with suffix|`50s`|
||[`timeout-connect`](#timeout)|time with suffix|`5s`|
||[`timeout-http-request`](#timeout)|time with suffix|`5s`|
||[`timeout-keep-alive`](#timeout)|time with suffix|`1m`|
||[`timeout-server`](#timeout)|time with suffix|`50s`|
||[`timeout-server-fin`](#timeout)|time with suffix|`50s`|
||[`timeout-tunnel`](#timeout)|time with suffix|`1h`|
|`[0]`|[`use-proxy-protocol`](#use-proxy-protocol)|[true\|false]|`false`|

### balance-algorithm

Define a load balancing algorithm.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#4-balance

### backend-check-interval

Define the interval between TCP health checks to the backend using `inter` option.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#5.2-inter

### dynamic-scaling

The `dynamic-scaling` option defines if backend updates should be made starting a
new HAProxy instance that will read the new config file (`false`), or updating the
running HAProxy via a Unix socket (`true`). Despite the configuration, the config
file will stay in sync with in memory config.

If `true` HAProxy Ingress will create at least `backend-server-slots-increment`
servers on each backend and update them via a Unix socket without reloading HAProxy.
Unused servers will stay in a disabled state.

* `dynamic-scaling`: Define if dynamic scaling should be used whenever possible
* `backend-server-slots-increment`: Configures the minimum number of servers, the size of the increment when growing and the size of the decrement when shrinking of each HAProxy backend

http://cbonte.github.io/haproxy-dconv/1.7/management.html#9.3

### forwardfor

Define if `X-Forwarded-For` header should be added always, added if missing or
ignored from incomming requests. Default is `add` which means HAProxy will itself
generate a `X-Forwarded-For` header with client's IP address and remove this same
header from incomming requests.

Use `ignore` to skip any check. `ifmissing` should be used to add
`X-Forwarded-For` with client's IP address only if this header is not defined.
Only use `ignore` or `ifmissing` on trusted networks.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#4-option%20forwardfor

### healthz-port

Define the port number HAProxy should listen to in order to answer for health checking
requests. Use `/healthz` as the request path.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#4-monitor-uri

### hsts

Configure HSTS - HTTP Strict Transport Security.

* `hsts`: `true` if HSTS response header should be added
* `hsts-include-subdomains`: `true` if it should apply to subdomains as well
* `hsts-max-age`: time in seconds the browser should remember this configuration
* `hsts-preload`: `true` if the browser should include the domain to [HSTS preload list](https://hstspreload.org/)

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

### https-to-http-port

A port number to listen http requests from another load balancer that does the ssl offload.

How it works: HAProxy will define if the request came from a HTTPS connection reading the
`X-Forwarded-Proto` HTTP header or the port number the client used to connect. If the
header is `https` or the port number matches `https-to-http-port`, HAProxy will behave
just like itself did the ssl offload: HSTS header will be provided if configured and no
https redirect will be done. There is only one exception: if `https-to-http-port` is `80`,
only the header will be checked.

The `X-Forwarded-Proto` header is optional in the following conditions:

* The `https-to-http-port` should not match HTTP port `80`; and
* The load balancer should connect to the same `https-to-http-port` number, eg cannot
have any proxy like Kubernetes' `NodePort` between the load balancer and HAProxy

### log-format

Customize the http/tcp log format using log format variables. Default to the HAProxy default log format.

* `http-log-format`
* `tcp-log-format`

https://cbonte.github.io/haproxy-dconv/1.7/configuration.html#8.2.4

### max-connections

Define the maximum number of concurrent connections on all proxies.
Defaults to `2000` connections, which is also the HAProxy default configuration.

http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#3.2-maxconn

### proxy-body-size

Define the maximum number of bytes HAProxy will allow on the body of requests. Default is
to not check, which means requests of unlimited size. This limit can be changed per ingress
resource.

Since 0.4 (currently canary/beta) a suffix can be added to the size, so `10m` means
`10 * 1024 * 1024` bytes. Supported suffix are: `k`, `m` and `g`.

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
* `stats-proxy-protocol`: Define if the stats endpoint should enforce the PROXY protocol

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

### use-proxy-protocol

Define if HAProxy is behind another proxy that use the PROXY protocol. If `true`, ports
`80` and `443` will enforce the PROXY protocol.

The stats endpoint (defaults to port `1936`) has it's own [`stats-proxy-protocol`](#stats)
configuration.

* http://cbonte.github.io/haproxy-dconv/1.7/configuration.html#5.1-accept-proxy
* http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
