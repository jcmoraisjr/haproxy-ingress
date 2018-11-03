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

# Installation

## The five minutes deployment

Follow the detailed instructions [here](/examples/setup-cluster.md#five-minutes-deployment) or, in short:

```
kubectl create -f https://raw.githubusercontent.com/jcmoraisjr/haproxy-ingress/master/docs/haproxy-ingress.yaml
kubectl label node <node-name> role=ingress-controller
```

## Deployment from examples

* Start with [deployment](/examples/deployment) instructions
* See [TLS termination](/examples/tls-termination) on how to enable `https`

# Configuration

HAProxy Ingress has two types of dynamic configurations: per ingress resource using
[annotations](#annotations), or globally using a [ConfigMap](#configmap) resource.
The controller has also static [command-line](#command-line) arguments.

It's also possible to change the default templates mounting a new template file using
a configmap:

|Mounting directory|Configmap keys (filenames)|Source (choose a proper tag)|
|---|---|---|
|`/etc/haproxy/template`|`haproxy.tmpl`|[haproxy.tmpl](/rootfs/etc/haproxy/template/haproxy.tmpl)|
|`/etc/haproxy/modsecurity`|`spoe-modsecurity.tmpl`|[spoe-modsecurity.tmpl](/rootfs/etc/haproxy/modsecurity/spoe-modsecurity.tmpl)|

All templates support [Sprig](http://masterminds.github.io/sprig/) template library. 
This library provides a group of commonly used template functions to work with dictionaries, 
lists, math etc.

## Annotations

The following annotations are supported:

* `[0]` only in `canary` tag
* `[1]` only in `snapshot` tag

||Name|Data|Usage|
|---|---|---|:---:|
||[`ingress.kubernetes.io/affinity`](#affinity)|affinity type|-|
||`ingress.kubernetes.io/auth-type`|"basic"|[doc](/examples/auth/basic)|
||`ingress.kubernetes.io/auth-secret`|secret name|[doc](/examples/auth/basic)|
||`ingress.kubernetes.io/auth-realm`|realm string|[doc](/examples/auth/basic)|
||[`ingress.kubernetes.io/auth-tls-cert-header`](#auth-tls)|[true\|false]|[doc](/examples/auth/client-certs)|
||[`ingress.kubernetes.io/auth-tls-error-page`](#auth-tls)|url|[doc](/examples/auth/client-certs)|
||[`ingress.kubernetes.io/auth-tls-secret`](#auth-tls)|namespace/secret name|[doc](/examples/auth/client-certs)|
|`[0]`|[`ingress.kubernetes.io/balance-algorithm`](#balance-algorithm)|algorithm name|-|
|`[0]`|[`ingress.kubernetes.io/blue-green-deploy`](#blue-green)|label=value=weight,...|[doc](/examples/blue-green)|
|`[1]`|[`ingress.kubernetes.io/blue-green-balance`](#blue-green)|label=value=weight,...|[doc](/examples/blue-green)|
|`[1]`|[`ingress.kubernetes.io/blue-green-mode`](#blue-green)|[pod\|deploy]|[doc](/examples/blue-green)|
|`[0]`|[`ingress.kubernetes.io/config-backend`](#configuration-snippet)|multiline HAProxy backend config|-|
|`[0]`|[`ingress.kubernetes.io/cors-allow-origin`](#cors)|URL|-|
|`[0]`|[`ingress.kubernetes.io/cors-allow-methods`](#cors)|methods list|-|
|`[0]`|[`ingress.kubernetes.io/cors-allow-headers`](#cors)|headers list|-|
|`[0]`|[`ingress.kubernetes.io/cors-allow-credentials`](#cors)|[true\|false]|-|
|`[0]`|[`ingress.kubernetes.io/cors-enable`](#cors)|[true\|false]|-|
|`[0]`|[`ingress.kubernetes.io/cors-max-age`](#cors)|time (seconds)|-|
||[`ingress.kubernetes.io/hsts`](#hsts)|[true\|false]|-|
||[`ingress.kubernetes.io/hsts-include-subdomains`](#hsts)|[true\|false]|-|
||[`ingress.kubernetes.io/hsts-max-age`](#hsts)|qty of seconds|-|
||[`ingress.kubernetes.io/hsts-preload`](#hsts)|[true\|false]|-|
||[`ingress.kubernetes.io/limit-connections`](#limit)|qty|-|
||[`ingress.kubernetes.io/limit-rps`](#limit)|rate per second|-|
||[`ingress.kubernetes.io/limit-whitelist`](#limit)|cidr list|-|
|`[0]`|[`ingress.kubernetes.io/maxconn-server`](#connection)|qty|-|
|`[0]`|[`ingress.kubernetes.io/maxqueue-server`](#connection)|qty|-|
|`[1]`|[`ingress.kubernetes.io/oauth`](#oauth)|"oauth2_proxy"|[doc](/examples/auth/oauth)|
|`[1]`|[`ingress.kubernetes.io/oauth-uri-prefix`](#oauth)|URI prefix|[doc](/examples/auth/oauth)|
|`[1]`|[`ingress.kubernetes.io/oauth-headers`](#oauth)|`<header>:<var>,...`|[doc](/examples/auth/oauth)|
|`[1]`|[`ingress.kubernetes.io/proxy-protocol`](#proxy-protocol)|[v1\|v2\|v2-ssl\|v2-ssl-cn]|-|
|`[0]`|[`ingress.kubernetes.io/slots-increment`](#dynamic-scaling)|qty|-|
|`[0]`|[`ingress.kubernetes.io/timeout-queue`](#connection)|qty|-|
||[`ingress.kubernetes.io/proxy-body-size`](#proxy-body-size)|size (bytes)|-|
||[`ingress.kubernetes.io/secure-backends`](#secure-backend)|[true\|false]|-|
||[`ingress.kubernetes.io/secure-crt-secret`](#secure-backend)|secret name|-|
||[`ingress.kubernetes.io/secure-verify-ca-secret`](#secure-backend)|secret name|-|
||[`ingress.kubernetes.io/session-cookie-name`](#affinity)|cookie name|-|
|`[0]`|[`ingress.kubernetes.io/session-cookie-strategy`](#affinity)|[insert\|prefix\|rewrite]|-|
||[`ingress.kubernetes.io/ssl-passthrough`](#ssl-passthrough)|[true\|false]|-|
|`[1]`|[`ingress.kubernetes.io/ssl-passthrough-http-port`](#ssl-passthrough)|backend port|-|
||`ingress.kubernetes.io/ssl-redirect`|[true\|false]|[doc](/examples/rewrite)|
||`ingress.kubernetes.io/app-root`|/url|[doc](/examples/rewrite)|
||`ingress.kubernetes.io/whitelist-source-range`|CIDR|-|
||[`ingress.kubernetes.io/rewrite-target`](#rewrite-target)|path string|-|
||[`ingress.kubernetes.io/server-alias`](#server-alias)|domain name or regex|-|
|`[1]`|[`ingress.kubernetes.io/use-resolver`](#dns-resolvers)|resolver name]|[doc](/examples/dns-service-discovery)|
|`[1]`|[`ingress.kubernetes.io/waf`](#waf)|"modsecurity"|[doc](/examples/modsecurity)|

### Affinity

Configure if HAProxy should maintain client requests to the same backend server.

* `ingress.kubernetes.io/affinity`: the only supported option is `cookie`. If declared, clients will receive a cookie with a hash of the server it should be fidelized to.
* `ingress.kubernetes.io/session-cookie-name`: the name of the cookie. `INGRESSCOOKIE` is the default value if not declared.
* `ingress.kubernetes.io/session-cookie-strategy`: the cookie strategy to use (insert, rewrite, prefix). `insert` is the default value if not declared.

Note for `dynamic-scaling` users only: the hash of the server is built based on it's name.
When the slots are scaled down, the remaining servers might change it's server name on
HAProxy configuration. In order to circumvent this, always configure the slot increment at
least as much as the number of replicas of the deployment that need to use affinity. This
limitation was removed on v0.6.

* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-cookie
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-cookie
* https://www.haproxy.com/blog/load-balancing-affinity-persistence-sticky-sessions-what-you-need-to-know/

### Auth TLS

Configure client authentication with X509 certificate. The following headers are added to the request:

* `X-SSL-Client-SHA1`: Hex encoding of the SHA-1 fingerprint of the X509 certificate
* `X-SSL-Client-DN`: Distinguished name of the certificate
* `X-SSL-Client-CN`: Common name of the certificate

The prefix of the header name can be configured with [`ssl-headers-prefix`](#ssl-headers-prefix) configmap option, which defaults to `X-SSL`.

The following annotations are supported:

* `ingress.kubernetes.io/auth-tls-cert-header`: if true HAProxy will add `X-SSL-Client-Cert` http header with a base64 encoding of the X509 certificate provided by the client. Default is to not provide the client certificate.
* `ingress.kubernetes.io/auth-tls-error-page`: optional URL of the page to redirect the user if he doesn't provide a certificate or the certificate is invalid.
* `ingress.kubernetes.io/auth-tls-secret`: mandatory secret name with `ca.crt` key providing all certificate authority bundles used to validate client certificates.

See also client cert [sample](/examples/auth/client-certs).

### Blue-green

Configure weight of a blue/green deployment. The annotation accepts a comma separated list of label
name/value pair and a numeric weight. Concatenate label name, label value and weight with an equal
sign, without spaces. The label name/value pair will be used to match corresponding pods or deploys.
There is no limit to the number of label/weight balance configurations.

The endpoints of a single backend are selected using service selectors, which also uses labels.
Because of that, in order to use blue/green deployment, the deployment, daemon set or replication
controller template should have at least two label name/value pairs - one that matches the service
selector and another that matches the blue/green selector.

* `ingress.kubernetes.io/blue-green-balance`: comma separated list of labels and weights
* `ingress.kubernetes.io/blue-green-deploy`: deprecated on v0.7, this is an alias to `ingress.kubernetes.io/blue-green-balance`.
* `ingress.kubernetes.io/blue-green-mode`: defaults to `deploy` on v0.7, defines how to apply the weights, might be `pod` or `deploy`

The following configuration `group=blue=1,group=green=4` will redirect 20% of the load to the
`group=blue` group and 80% of the load to `group=green` group.

Applying the weights depends on the blue/green mode. v0.6 has only `pod` mode which means that
every single pod receives the same weight as configured on blue/green balance. This means that
a balance configuration with 50% to each group will redirect twice as much requests to a backend
that has the double of replicas. v0.7 has also `deploy` mode which rebalance the weights based
on the number of replicas of each deployment.

In short, regarding blue/green mode: use `pod` if you want to redirect more requests to a
deployment updating the number of replicas; use `deploy` if you want to control the load
of each side updating the blue/green balance annotation.

Value of `0` (zero) can also be used as weight. This will let the endpoint configured in the
backend accepting persistent connections - see [affinity](#affinity) - but will not participate
in the load balancing. The maximum weight value is `256`.

See also the [example](/examples/blue-green) page.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-weight

### CORS

Add CORS headers on OPTIONS http command (preflight) and reponses.

* `ingress.kubernetes.io/cors-enable`: Enable CORS if defined as `true`.
* `ingress.kubernetes.io/cors-allow-origin`: Optional, configures `Access-Control-Allow-Origin` header which defines the URL that may access the resource. Defaults to `*`.
* `ingress.kubernetes.io/cors-allow-methods`: Optional, configures `Access-Control-Allow-Methods` header which defines the allowed methods. See defaults [here](/pkg/common/ingress/annotations/cors/main.go#L34).
* `ingress.kubernetes.io/cors-allow-headers`: Optional, configures `Access-Control-Allow-Headers` header which defines the allowed headers. See defaults [here](/pkg/common/ingress/annotations/cors/main.go#L34).
* `ingress.kubernetes.io/cors-allow-credentials`: Optional, configures `Access-Control-Allow-Credentials` header which defines whether or not credentials (cookies, authorization headers or client certificates) should be exposed. Defaults to `true`.
* `ingress.kubernetes.io/cors-max-age`: Optional, configures `Access-Control-Max-Age` header which defines the time in seconds the result should be cached. Defaults to `86400` (1 day).

https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

### Limit

Configure rate limit and concurrent connections per client IP address in order to mitigate DDoS attack.
If several users are hidden behind the same IP (NAT or proxy), this configuration may have a negative
impact for them. Whitelist can be used to these IPs.

The following annotations are supported:

* `ingress.kubernetes.io/limit-connections`: Maximum number os concurrent connections per client IP
* `ingress.kubernetes.io/limit-rps`: Maximum number of connections per second of the same IP
* `ingress.kubernetes.io/limit-whitelist`: Comma separated list of CIDRs that should be removed from the rate limit and concurrent connections check

### Connection

Configurations of connection limit and timeout.

* `ingress.kubernetes.io/maxconn-server`: Defines the maximum concurrent connections each server of a backend should receive. If not specified or a value lesser than or equal zero is used, an unlimited number of connections will be allowed. When the limit is reached, new connections will wait on a queue.
* `ingress.kubernetes.io/maxqueue-server`: Defines the maximum number of connections should wait in the queue of a server. When this number is reached, new requests will be redispached to another server, breaking sticky session if configured. The queue will be unlimited if the annotation is not specified or a value lesser than or equal zero is used.
* `ingress.kubernetes.io/timeout-queue`: Defines how much time a connection should wait on a queue before a 503 error is returned to the client. The unit defaults to milliseconds if missing, change the unit with `s`, `m`, `h`, ... suffix. The configmap `timeout-queue` option is used as the default value.

* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-maxconn
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-maxqueue
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-timeout%20queue
* Time suffix: http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#2.4

### OAuth

Configure OAuth2 via Bitly's `oauth2_proxy`.

* `ingress.kubernetes.io/oauth`: Defines the oauth implementation. The only supported option is `oauth2_proxy`.
* `ingress.kubernetes.io/oauth-uri-prefix`: Defines the URI prefix of the oauth service. The default value is `/oauth2`. There should be a backend with this path in the ingress resource.
* `ingress.kubernetes.io/oauth-headers`: Defines an optional comma-separated list of `<header>:<haproxy-var>` used to configure request headers to the upstream backends. The default value is `X-Auth-Request-Email:auth_response_email` which means configuring a header `X-Auth-Request-Email` with the value of the var `auth_response_email`. New variables can be added overwriting the default `auth-request.lua` script.

The `oauth2_proxy` implementation expects Bitly's [oauth2_proxy](https://github.com/bitly/oauth2_proxy)
running as a backend of the same domain that should be protected. `oauth2_proxy` has support
to GitHub, Google, Facebook, OIDC and many others.

All paths of a domain will have the same oauth configurations, despite if the path is configured
on an ingress resource without oauth annotations. In other words, if two ingress resources share
the same domain but only one has oauth annotations - the one that has at least the `oauth2_proxy`
service - all paths from that domain will be protected.

See also the [example](/examples/auth/oauth) page.

### Proxy Protocol

Define if the upstream backends support proxy protocol and what version of the protocol should be used.

* `ingress.kubernetes.io/proxy-protocol`: The proxy protocol version the backend expect. Supported values are `v1`, `v2`, `v2-ssl`, `v2-ssl-cn` or `no`. The default behavior if not declared is that the protocol is not supported by the backends and should not be used.

* http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-send-proxy
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-send-proxy-v2
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-send-proxy-v2-ssl
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-send-proxy-v2-ssl-cn

### Secure Backend

Configure secure (TLS) connection to the backends.

* `ingress.kubernetes.io/secure-backends`: Define as true if the backend provide a TLS connection.
* `ingress.kubernetes.io/secure-crt-secret`: Optional secret name of client certificate and key. This cert/key pair must be provided if the backend requests a client certificate. Expected secret keys are `tls.crt` and `tls.key`, the same used if secret is built with `kubectl create secret tls <name>`.
* `ingress.kubernetes.io/secure-verify-ca-secret`: Optional secret name with certificate authority bundle used to validate server certificate, preventing man-in-the-middle attacks. Expected secret key is `ca.crt`.

### Server Alias

Creates an alias of the server that annotation belongs to.
It'll be using the same backend but different ACL.
Alias rules will be checked at the very end of list or rules.
It is allowed to be a regex.

Note: `^` and `$` cannot be used because they are already included in ACL.

### Rewrite Target

Configures how URI of the requests should be rewritten before send the request to the backend.
The following table shows some examples:

|ingress path|request path|rewrite target|output|
|---|---|---|---|
|/abc|/abc|/|/|
|/abc|/abc/|/|/|
|/abc|/abc/x|/|/x|
|/abc|/abc|/y|/y|
|/abc|/abc/|/y|/y/|
|/abc|/abc/x|/y|/y/x|
|/abc/|/abc|/|**404**|
|/abc/|/abc/|/|/|
|/abc/|/abc/x|/|/x|

### SSL passthrough

Defines if HAProxy should work in TCP proxy mode and leave the SSL offload to the backend.
SSL passthrough is a per domain configuration, which means that other domains can be
configured to SSL offload on HAProxy.

If using SSL passthrough, only root `/` path is supported.

* `ingress.kubernetes.io/ssl-passthrough`: Enable ssl passthrough if defined as `True` and the backend is expected to SSL offload the incoming traffic. The default value is `False`, which means HAProxy should do the SSL handshake.
* `ingress.kubernetes.io/ssl-passthrough-http-port`: Since v0.7. Optional HTTP port number of the backend. If defined, connections to the HAProxy HTTP port, default `80`, is sent to that port which expects to speak plain HTTP. If not defined, connections to the HTTP port will redirect connections to the HTTPS one.

### WAF

Defines which web application firewall (WAF) implementation should be used
to validate requests. Currently the only supported value is `modsecurity`.
See also [modsecurity-endpoints](#modsecurity-endpoints) configmap option.

This annotation has no effect if the target web application firewall isn't
configured.

## ConfigMap

If using ConfigMap to configure HAProxy Ingress, use
`--configmap=<namespace>/<configmap-name>` argument on HAProxy Ingress deployment.
A ConfigMap can be created with `kubectl create configmap`.

The following parameters are supported:

* `[0]` only in `canary` tag
* `[1]` only in `snapshot` tag

||Name|Type|Default|
|---|---|---|---|
||[`backend-check-interval`](#backend-check-interval)|time with suffix|`2s`|
||[`backend-server-slots-increment`](#dynamic-scaling)|number of slots|`32`|
||[`balance-algorithm`](#balance-algorithm)|algorithm name|`roundrobin`|
|`[0]`|[`bind-ip-addr-healthz`](#bind-ip-addr)|IP address|`*`|
|`[0]`|[`bind-ip-addr-http`](#bind-ip-addr)|IP address|`*`|
|`[0]`|[`bind-ip-addr-stats`](#bind-ip-addr)|IP address|`*`|
|`[0]`|[`bind-ip-addr-tcp`](#bind-ip-addr)|IP address|`*`|
|`[1]`|[`config-frontend`](#configuration-snippet)|multiline HAProxy frontend config||
|`[0]`|[`cookie-key`](#cookie-key)|secret key|`Ingress`|
|`[1]`|[`dns-accepted-payload-size`](#dns-resolvers)|number|`8192`|
|`[1]`|[`dns-cluster-domain`](#dns-resolvers)|cluster name|`cluster.local`|
|`[1]`|[`dns-hold-obsolete`](#dns-resolvers)|time with suffix|`0s`|
|`[1]`|[`dns-hold-valid`](#dns-resolvers)|time with suffix|`1s`|
|`[1]`|[`dns-resolvers`](#dns-resolvers)|multiline resolver=ip[:port]|``|
|`[1]`|[`dns-timeout-retry`](#dns-resolvers)|time with suffix|`1s`|
|`[0]`|[`drain-support`](#drain-support)|[true\|false]|`false`|
||[`dynamic-scaling`](#dynamic-scaling)|[true\|false]|`false`|
||[`forwardfor`](#forwardfor)|[add\|ignore\|ifmissing]|`add`|
||[`healthz-port`](#healthz-port)|port number|`10253`|
||[`hsts`](#hsts)|[true\|false]|`true`|
||[`hsts-include-subdomains`](#hsts)|[true\|false]|`false`|
||[`hsts-max-age`](#hsts)|number of seconds|`15768000`|
||[`hsts-preload`](#hsts)|[true\|false]|`false`|
||[`http-log-format`](#log-format)|http log format|HAProxy default log format|
|`[1]`|[`http-port`](#bind-ip-addr)|port number|`80`|
||[`https-log-format`](#log-format)|https(tcp) log format\|`default`|do not log|
|`[1]`|[`https-port`](#bind-ip-addr)|port number|`443`|
||[`https-to-http-port`](#https-to-http-port)|port number|0 (do not listen)|
||[`load-server-state`](#load-server-state) (experimental)|[true\|false]|`false`|
||[`max-connections`](#max-connections)|number|`2000`|
|`[1]`|[`modsecurity-endpoints`](#modsecurity-endpoints)|comma-separated list of IP:port (spoa)|no waf config|
|`[1]`|[`modsecurity-timeout-hello`](#modsecurity)|time with suffix|`100ms`|
|`[1]`|[`modsecurity-timeout-idle`](#modsecurity)|time with suffix|`30s`|
|`[1]`|[`modsecurity-timeout-processing`](#modsecurity)|time with suffix|`1s`|
|`[1]`|[`nbproc-ssl`](#nbproc)|number of process|`0`|
|`[1]`|[`nbthread`](#nbthread)|number of threads|`1`|
|`[0]`|[`no-tls-redirect-locations`](#no-tls-redirect-locations)|comma-separated list of url|`/.well-known/acme-challenge`|
||[`proxy-body-size`](#proxy-body-size)|number of bytes|unlimited|
||[`ssl-ciphers`](#ssl-ciphers)|colon-separated list|[link to code](https://github.com/jcmoraisjr/haproxy-ingress/blob/v0.4/pkg/controller/config.go#L35)|
||[`ssl-dh-default-max-size`](#ssl-dh-default-max-size)|number|`1024`|
||[`ssl-dh-param`](#ssl-dh-param)|namespace/secret name|no custom DH param|
||[`ssl-headers-prefix`](#ssl-headers-prefix)|prefix|`X-SSL`|
||[`ssl-options`](#ssl-options)|space-separated list|`no-sslv3` `no-tls-tickets`|
||[`ssl-redirect`](#ssl-redirect)|[true\|false]|`true`|
||[`stats-auth`](#stats)|user:passwd|no auth|
||[`stats-port`](#stats)|port number|`1936`|
||[`stats-proxy-protocol`](#stats)|[true\|false]|`false`|
|`[1]`|[`stats-ssl-cert`](#stats)|namespace/secret name|no ssl/plain http|
|`[1]`|[`strict-host`](#strict-host)|[true\|false]|`true`|
||[`syslog-endpoint`](#syslog-endpoint)|IP:port (udp)|do not log|
||[`tcp-log-format`](#log-format)|tcp log format|HAProxy default log format|
||[`timeout-client-fin`](#timeout)|time with suffix|`50s`|
||[`timeout-client`](#timeout)|time with suffix|`50s`|
||[`timeout-connect`](#timeout)|time with suffix|`5s`|
||[`timeout-http-request`](#timeout)|time with suffix|`5s`|
||[`timeout-keep-alive`](#timeout)|time with suffix|`1m`|
||[`timeout-queue`](#timeout)|time with suffix|`5s`|
||[`timeout-server-fin`](#timeout)|time with suffix|`50s`|
||[`timeout-server`](#timeout)|time with suffix|`50s`|
|`[0]`|[`timeout-stop`](#timeout)|time with suffix|no timeout|
||[`timeout-tunnel`](#timeout)|time with suffix|`1h`|
||[`use-host-on-https`](#use-host-on-https)|[true\|false]|`false`|
||[`use-proxy-protocol`](#use-proxy-protocol)|[true\|false]|`false`|

### balance-algorithm

Define a load balancing algorithm. Use a configmap option to define a default value,
and an ingress annotation to define a per backend configuration.

Global configmap option:

* `balance-algorithm`: algorithm name, default value is `roundrobin`

Annotation on ingress resources:

* `ingress.kubernetes.io/balance-algorithm`

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-balance

### backend-check-interval

Define the interval between TCP health checks to the backend using `inter` option.

Default value is `2s` - two seconds between two consecutive checks. Configure an
empty string to disable health checks.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-inter

### bind-ip-addr

Define listening IPv4/IPv6 address on several HAProxy frontends. All IP addresses defaults to IPv4 `*` if not declared.

`bind-ip-addr-tcp`: IP address of all TCP services declared on [`tcp-services`](#tcp-services-configmap) configmap option.
`bind-ip-addr-http`: IP address of all HTTP/s frontends, port `:80` and `:443`, and also [`https-to-http-port`](#https-to-http-port) if declared.
`bind-ip-addr-healthz`: IP address of the health check URL. See also [`healthz-port`](#healthz-port).
`bind-ip-addr-stats`: IP address of the statistics page. See also [`stats-port`](#stats).

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-bind

### Configuration snippet

Add HAProxy configuration snippet to the configuration file. Use multiline content to add more than one
line of configuration.

Examples - configmap:

```yaml
    config-frontend: |
      capture request header X-User-Id len 32
```

Ingress annotation:

```yaml
    annotations:
      ingress.kubernetes.io/config-backend: |
        acl bar-url path /bar
        http-request deny if bar-url
```

Global configmap option:

* `config-frontend`: Add configuration snippet to all frontend sections.

Annotation option:

* `ingress.kubernetes.io/config-backend`: Add configuration snippet to the HAProxy backend section.

### cookie-key

Define a secret key used with the IP address and port number of a backend server
to dynamically create a cookie to that server. Only useful on cookie based
server affinity. See also [affinity](#affinity) annotations.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#dynamic-cookie-key

### dns-resolvers

Configure dynamic backend server update using DNS service discovery.

Global configmap options:

* `dns-resolvers`: Multiline list of DNS resolvers in `resolvername=ip:port` format
* `dns-accepted-payload-size`: Maximum payload size announced to the name servers
* `dns-timeout-retry`: Time between two consecutive queries when no valid response was received, defaults to `1s`
* `dns-hold-valid`: Time a resolution is considered valid. Keep in sync with DNS cache timeout. Defaults to `1s`
* `dns-hold-obsolete`: Time to keep valid a missing IP from a new DNS query, defaults to `0s`
* `dns-cluster-domain`: K8s cluster domain, defaults to `cluster.local`

Annotations on ingress resources:

* `ingress.kubernetes.io/use-resolver`: Name of the resolver that the backend should use

Important advices!

* Use resolver with **headless** services, see [k8s doc](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services), otherwise HAProxy will reference the service IP instead of the endpoints.
* Beware of DNS cache, eg kube-dns has `--max-ttl` and `--max-cache-ttl` to change its default cache of `30s`.

See also the [example](/examples/dns-service-discovery) page.

Reference:

* https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.3.2
* https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-resolvers
* https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
* https://kubernetes.io/docs/concepts/services-networking/service/#headless-services

### dynamic-scaling

The `dynamic-scaling` option defines if backend updates should be made starting a
new HAProxy instance that will read the new config file (`false`), or updating the
running HAProxy via a Unix socket (`true`). Despite the configuration, the config
file will stay in sync with in memory config.

If `true` HAProxy Ingress will create at least `backend-server-slots-increment`
servers on each backend and update them via a Unix socket without reloading HAProxy.
Unused servers will stay in a disabled state.

Starting on v0.6, `dynamic-scaling` config will only force a reloading of HAProxy if
the number of servers on a backend need to be increased. Before v0.6 a reload will
also happen when the number of servers could be reduced.

Global configmap options:

* `dynamic-scaling`: Define if dynamic scaling should be used whenever possible
* `backend-server-slots-increment`: Configures the minimum number of servers, the size of the increment when growing and the size of the decrement when shrinking of each HAProxy backend

Annotations on ingress resources:

* `ingress.kubernetes.io/slots-increment`: A per backend slot increment

http://cbonte.github.io/haproxy-dconv/1.8/management.html#9.3

### forwardfor

Define if `X-Forwarded-For` header should be added always, added if missing or
ignored from incoming requests. Default is `add` which means HAProxy will itself
generate a `X-Forwarded-For` header with client's IP address and remove this same
header from incoming requests.

Use `ignore` to skip any check. `ifmissing` should be used to add
`X-Forwarded-For` with client's IP address only if this header is not defined.
Only use `ignore` or `ifmissing` on trusted networks.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-option%20forwardfor

### healthz-port

Define the port number HAProxy should listen to in order to answer for health checking
requests. Use `/healthz` as the request path.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-monitor-uri

### hsts

Configure global (configmap) or per host or location (annotation) HSTS - HTTP Strict Transport Security. Annotations has precedence over global configuration.

Global configmap options:

* `hsts`: `true` if HSTS response header should be added
* `hsts-include-subdomains`: `true` if it should apply to subdomains as well
* `hsts-max-age`: time in seconds the browser should remember this configuration
* `hsts-preload`: `true` if the browser should include the domain to [HSTS preload list](https://hstspreload.org/)

Annotations on ingress resources:

* `ingress.kubernetes.io/hsts`
* `ingress.kubernetes.io/hsts-include-subdomains`
* `ingress.kubernetes.io/hsts-max-age`
* `ingress.kubernetes.io/hsts-preload`

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

### https-to-http-port

A port number to listen http requests from another load balancer that does the ssl offload.

How it works: HAProxy will define if the request came from a HTTPS connection reading the
`X-Forwarded-Proto` HTTP header or the port number the client used to connect. If the
header is `https` or the port number matches `https-to-http-port`, HAProxy will behave
just like itself did the ssl offload: HSTS header will be provided if configured and no
https redirect will be done. There is only one exception: if `https-to-http-port` is `80`,
only the header will be checked.

The `X-Forwarded-Proto` header is optional in the following condition:

* The `https-to-http-port` should not match HTTP port `80`; and
* The load balancer should connect to the same `https-to-http-port` number, eg cannot
have any proxy like Kubernetes' `NodePort` between the load balancer and HAProxy

### load-server-state

Define if HAProxy should save and reload it's current state between server reloads, like
uptime of backends, qty of requests and so on.

This is an experimental feature and has currently some issues if using with `dynamic-scaling`:
an old state with disabled servers will disable them in the new configuration.

* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-server-state-file
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-load-server-state-from-file

### log-format

Customize the tcp, http or https log format using log format variables. Only used if
[syslog-endpoint](#syslog-endpoint) is also configured.

* `tcp-log-format`: log format of TCP proxies, defaults to HAProxy default TCP log format. See also [TCP services configmap](#tcp-services-configmap) command-line option.
* `http-log-format`: log format of all HTTP proxies, defaults to HAProxy default HTTP log format.
* `https-log-format`: log format of TCP proxy used to inspect SNI extention. Use `default` to configure default TCP log format, defaults to not log.

https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#8.2.4

### max-connections

Define the maximum number of concurrent connections on all proxies.
Defaults to `2000` connections, which is also the HAProxy default configuration.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.2-maxconn

### modsecurity-endpoints

Configure a comma-separated list of `IP:port` of HAProxy agents (SPOA) for ModSecurity.
The default configuration expects the `contrib/modsecurity` implementation from HAProxy source code.

Currently all http requests will be parsed by the ModSecurity agent, even if the ingress resource
wasn't configured to deny requests based on ModSecurity response.

See also:

* [modsecurity](#modsecurity) config options
* [`ingress.kubernetes.io/waf`](#waf) annotation
* [example](/examples/modsecurity) page

Reference:

* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#9.3
* https://www.haproxy.org/download/1.8/doc/SPOE.txt
* https://github.com/jcmoraisjr/modsecurity-spoa

### modsecurity

Configure modsecurity agent. These options only have effect if ModSecurity is configured.
See also [`modsecurity-endpoints`](#modsecurity-endpoints) configmap option and
[`ingress.kubernetes.io/waf`](#waf) annotation.

Global configmap options:

* `modsecurity-timeout-hello`: Defines the maximum time to wait for the AGENT-HELLO frame from the agent. Default value is `100ms`.
* `modsecurity-timeout-idle`: Defines the maximum time to wait before close an idle connection. Default value is `30s`.
* `modsecurity-timeout-processing`: Defines the maximum time to wait for the whole ModSecurity processing. Default value is `1s`.

* https://www.haproxy.org/download/1.8/doc/SPOE.txt

### nbproc

Define the number of dedicated HAProxy process to the SSL/TLS handshake and
offloading. The default value is 0 (zero) which means HAProxy should process all
the SSL/TLS offloading, as well as the header inspection and load balancing
within the same HAProxy process.

The recommended value depends on how much CPU a single HAProxy process is
spending. Use 0 (zero) if the amount of processing has low CPU usage. This will
avoid a more complex topology and an inter-process communication. Use the number
of cores of a dedicated host minus 1 (one) to distribute the SSL/TLS offloading
process. Leave one core dedicated to header inspection and load balancing.

If splitting HAProxy into two or more process and the number of threads is one,
`cpu-map` is used to bind each process on its own CPU core.

See also [nbthread](#nbthread).

* `nbproc-ssl`: number of dedicated process to SSL/TLS offloading

Referece:

* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-nbproc
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-bind-process
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-cpu-map

### nbthread

Define the number of threads a single HAProxy process should use to all its
processing. If using with [nbproc](#nbproc), every single HAProxy process will
share this same configuration.

If using two or more threads on a single HAProxy process, `cpu-map` is used to
bind each thread on its own CPU core.

Note that multithreaded process is a HAProxy experimental feature!

Reference:

* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-nbthread
* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-cpu-map

### no-tls-redirect-locations

Define a comma-separated list of URLs that should be removed from the TLS redirect.
Requests to `:80` http port and starting with one of the URLs from the list will
not be redirected to https despite of the TLS redirect configuration.

This option defaults to `/.well-known/acme-challenge`, used by ACME protocol.

### proxy-body-size

Define the maximum number of bytes HAProxy will allow on the body of requests. Default is
to not check, which means requests of unlimited size. This limit can be changed per ingress
resource.

Since 0.4 a suffix can be added to the size, so `10m` means
`10 * 1024 * 1024` bytes. Supported suffix are: `k`, `m` and `g`.

Since 0.7 `unlimited` can be used to overwrite any global body size limit.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#7.3.6-req.body_size

### ssl-ciphers

Set the list of cipher algorithms used during the SSL/TLS handshake.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-ssl-default-bind-ciphers

### ssl-dh-default-max-size

Define the maximum size of a temporary DH parameters used for key exchange.
Only used if `ssl-dh-param` isn't provided.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#tune.ssl.default-dh-param

### ssl-dh-param

Define DH parameters file used on ephemeral Diffie-Hellman key exchange during
the SSL/TLS handshake.

When stored locally, the DH secret may look like:

```
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAg9dDI+Z1dk7A0ctnFqPuS2cq8lIQLc36nvaLE5zcbI5IfiyxmxNh
...
-----END DH PARAMETERS-----
```

To create your secret you can define the secret with a template and a base64
encoded copy of the DH parameter, or you can generate the secret with:

```
kubectl create secret generic ingress-dh-param --from-file dhparam.pem
```

Then, in the haproxy ingress configuration, `ssl-dh-param` should reference the
resulting secret.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-ssl-dh-param-file

### ssl-headers-prefix

Define the http header prefix that should be used with certificate parameters such as
DN and SHA1 on client cert authentication. The default value is `X-SSL` which
will create a `X-SSL-Client-DN` header with the DN of the certificate.

Since [RFC 6648](http://tools.ietf.org/html/rfc6648) `X-` prefix on unstandardized
headers changed from a convention to deprecation. This configuration allows to
select which pattern should be used on SSL/TLS headers.

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
to https if TLS is [configured](/examples/tls-termination).

### stats

Configurations of the HAProxy statistics page:

* `stats-auth`: Enable basic authentication with clear-text password - `<user>:<passwd>`
* `stats-port`: Change the port HAProxy should listen to requests
* `stats-proxy-protocol`: Define if the stats endpoint should enforce the PROXY protocol
* `stats-ssl-cert`: Optional namespace/secret-name of `tls.crt` and `tls.key` pair used to enable SSL on stats page. Plain http will be used if not provided, the secret wasn't found or the secret doesn't have a crt/key pair.

### strict-host

Defines whether the path of another matching host/FQDN should be used to try
to serve a request. The default value is `true`, which means a strict
configuration and the `default-backend` should be used if a path couldn't be
matched. If `false`, all matching wildcard hosts will be visited in order to
try to match the path.

Using the following configuration:

```
  spec:
    rules:
    - host: my.domain.com
      http:
        paths:
        - path: /a
          backend:
            serviceName: svc1
            servicePort: 8080
    - host: *.domain.com
      http:
        paths:
        - path: /
          backend:
            serviceName: svc2
            servicePort: 8080
```

A request to `my.domain.com/b` would serve:

* `default-backend` if `strict-host` is true, the default value
* `svc2` if `strict-host` is false

### syslog-endpoint

Configure the UDP syslog endpoint where HAProxy should send access logs.

### timeout

Define timeout configurations:

* `timeout-client`: Maximum inactivity time on the client side
* `timeout-client-fin`: Maximum inactivity time on the client side for half-closed connections - FIN_WAIT state
* `timeout-connect`: Maximum time to wait for a connection to a backend
* `timeout-http-request`: Maximum time to wait for a complete HTTP request
* `timeout-keep-alive`: Maximum time to wait for a new HTTP request on keep-alive connections
* `timeout-queue`: Maximum time a connection should wait on a server queue before return a 503 error to the client
* `timeout-server`: Maximum inactivity time on the backend side
* `timeout-server-fin`: Maximum inactivity time on the backend side for half-closed connections - FIN_WAIT state
* `timeout-stop`: Maximum time to wait for long lived connections to finish, eg websocket, before hard-stop a HAProxy process due to a reload
* `timeout-tunnel`: Maximum inactivity time on the client and backend side for tunnels

Reference:

* `timeout-stop` - http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#3.1-hard-stop-after

### use-host-on-https

On TLS connections HAProxy will choose the backend based on the TLS's SNI extension. If SNI
wasn't provided or the hostname provided wasn't found, the default behavior is to use the
default backend. The default TLS certificate is used.

If `use-host-on-https` confimap option is declared as `true`, HAProxy will use the `Host` header
provided in the request. In this case the default backend will only be used if the hostname provided
by the `Host` header wasn't found. Note that the TLS handshake is finished before HAProxy is aware of
the hostname, because of that only the default X509 certificate can be used.

### use-proxy-protocol

Define if HAProxy is behind another proxy that use the PROXY protocol. If `true`, ports
`80` and `443` will enforce the PROXY protocol.

The stats endpoint (defaults to port `1936`) has it's own [`stats-proxy-protocol`](#stats)
configuration.

* http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.1-accept-proxy
* http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

### drain-support

Set to true if you wish to use HAProxy's drain support for pods that are NotReady (e.g., failing a
k8s readiness check) or are in the process of terminating. This option only makes sense with
cookie affinity configured as it allows persistent traffic to be directed to pods that are in a
not ready or terminating state.

## Command-line

The following command-line arguments are supported:

* `[0]` only in `canary` tag
* `[1]` only in `snapshot` tag

||Name|Type|Default|
|---|---|---|---|
||[`allow-cross-namespace`](#allow-cross-namespace)|[true\|false]|`false`|
||[`default-backend-service`](#default-backend-service)|namespace/servicename|(mandatory)|
||[`default-ssl-certificate`](#default-ssl-certificate)|namespace/secretname|(mandatory)|
||[`ingress-class`](#ingress-class)|name|`haproxy`|
||[`kubeconfig`](#kubeconfig)|/path/to/kubeconfig|in cluster config|
|`[0]`|[`max-old-config-files`](#max-old-config-files)|num of files|`0`|
||[`publish-service`](#publish-service)|namespace/servicename|``|
||[`rate-limit-update`](#rate-limit-update)|uploads per second (float)|`0.5`|
||[`reload-strategy`](#reload-strategy)|[native\|reusesocket]|`native`|
||[`sort-backends`](#sort-backends)|[true\|false]|`false`|
||[`tcp-services-configmap`](#tcp-services-configmap)|namespace/configmapname|no tcp svc|
||[`verify-hostname`](#verify-hostname)|[true\|false]|`true`|
|`[1]`|[`watch-namespace`](#watch-namespace)|namespace|all namespaces|

### allow-cross-namespace

`--allow-cross-namespace` argument, if added, will allow reading secrets from one namespace to an
ingress resource of another namespace. The default behavior is to deny such cross namespace reading.
This adds a breaking change from `v0.4` to `v0.5` on `ingress.kubernetes.io/auth-tls-secret`
annotation, where cross namespace reading were allowed without any configuration.

### default-backend-service

Defines the `namespace/servicename` that should be used if the incoming request doesn't match any
hostname, or the requested path doesn't match any location within the desired hostname.

This is a mandatory argument used in the [deployment](/examples/deployment) example page.

### default-ssl-certificate

Defines the `namespace/secretname` of the default certificate that should be used if ingress
resources using TLS configuration doesn't provide it's own certificate.

This is a mandatory argument used in the [deployment](/examples/deployment) and
[TLS termination](/examples/tls-termination) example pages.

### ingress-class

More than one ingress controller is supported per Kubernetes cluster. The `--ingress-class`
argument allow to override the class name of ingress resources that this instance of the
controller should listen to. Class names that match will be used in the HAProxy configuration.
Other classes will be ignored.

The ingress resource must use the `kubernetes.io/ingress.class` annotation to name it's
ingress class.

### kubeconfig

Ingress controller will try to connect to the Kubernetes master using environment variables and a
service account. This behavior can be changed using `--kubeconfig` argument that reference a
kubeconfig file with master endpoint and credentials. This is a mandatory argument if the controller
is deployed outside of the Kubernetes cluster.

### max-old-config-files

Everytime a configuration change need to update HAProxy, a configuration file is rewritten even if
dynamic update is used. By default the same file is recreated and the old configuration is lost.
Use `--max-old-config-files` to configure after how much files Ingress controller should start to
remove old configuration files. If `0`, the default value, a single `haproxy.cfg` is used.

### publish-service

Some infrastructure tools like `external-DNS` relay in the ingress status to created access routes to the services exposed with ingress object.
```
apiVersion: extensions/v1beta1
kind: Ingress
...
status:
  loadBalancer:
    ingress:
    - hostname: <ingressControllerLoadbalancerFQDN>
```
Use `--publish-service=namespace/servicename` to indicate the services fronting the ingress controller. The controller mirrors the address of this service's endpoints to the load-balancer status of all Ingress objects it satisfies.

### rate-limit-update

Use `--rate-limit-update` to change how much time to wait between HAProxy reloads. Note that the first
update is always immediate, the delay will only prevent two or more updates in the same time frame.
Moreover reloads will only occur if the cluster configuration has changed, otherwise no reload will
occur despite of the rate limit configuration.

This argument receives the allowed reloads per second. The default value is `0.5` which means no more
than one reload will occur within `2` seconds. The lower limit is `0.05` which means one reload within
`20` seconds. The highest one is `10` which will allow ingress controller to reload HAProxy up to 10
times per second.

### reload-strategy

The `--reload-strategy` command-line argument is used to select which reload strategy
HAProxy should use. The following options are available:

* `native`: Uses native HAProxy reload option `-sf`. This is the default option.
* `reusesocket`: (starting on v0.6) Uses HAProxy `-x` command-line option to pass the listening sockets between old and new HAProxy process, allowing hitless reloads.
* `multibinder`: (deprecated on v0.6) Uses GitHub's [multibinder](https://github.com/github/multibinder). This [link](https://githubengineering.com/glb-part-2-haproxy-zero-downtime-zero-delay-reloads-with-multibinder/)
describes how it works.

### sort-backends

Ingress will randomly shuffle backends and server endpoints on each reload in order to avoid
requesting always the same backends just after reloads, depending on the balancing algorithm.
Use `--sort-backends` to avoid this behavior and always declare backends and upstream servers
in the same order.

### tcp-services-configmap

Configure `--tcp-services-configmap` argument with `namespace/configmapname` resource with TCP
services and ports that HAProxy should listen to. Use the HAProxy's port number as the key of the
configmap.

The value of the configmap entry is a colon separated list of the following items:

1. `<namespace>/<service-name>`, mandatory, is the well known notation of the service that will receive incoming connections.
2. `<portnumber>`, mandatory, is the port number the upstream service is listening - this is not related to the listening port of HAProxy.
3. `<in-proxy>`, optional, should be defined as `PROXY` if HAProxy should expect requests using the [PROXY](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) protocol. Leave empty to not use PROXY protocol. This is usually used only if there is another load balancer in front of HAProxy which supports the PROXY protocol. PROXY protocol v1 and v2 are supported.
4. `<out-proxy>`, optional, should be defined as `PROXY` or `PROXY-V2` if the upstream service expect connections using the PROXY protocol v2. Use `PROXY-V1` instead if the upstream service only support v1 protocol. Leave empty to connect without using the PROXY protocol.
5. `<namespace/secret-name>`, optional, used to configure SSL/TLS over the TCP connection. Secret should have `tls.crt` and `tls.key` pair used on TLS handshake. Leave empty to not use ssl-offload.

Optional fields should be skipped using two consecutive colons.

In the example below:

```
...
data:
  "5432": "default/pgsql:5432"
  "8000": "system-prod/http:8000::PROXY-V1"
  "9900": "system-prod/admin:9900:PROXY::system-prod/tcp-9900"
  "9990": "system-prod/admin:9999::PROXY-V2"
  "9999": "system-prod/admin:9999:PROXY:PROXY"
```

HAProxy will listen 5 new ports:

* `5432` will proxy to a `pgsql` service on `default` namespace.
* `8000` will proxy to `http` service, port `8000`, on the `system-prod` namespace. The upstream service will expect connections using the PROXY protocol but it only supports v1.
* `9900` will proxy to `admin` service, port `9900`, on the `system-prod` namespace. Clients should connect using the PROXY protocol v1 or v2. Upcoming connections should be encrypted, HAProxy will ssl-offload data using crt/key provided by `system-prod/tcp-9900` secret.
* `9990` and `9999` will proxy to the same `admin` service and `9999` port and the upstream service will expect connections using the PROXY protocol v2. The HAProxy frontend, however, will only expect PROXY protocol v1 or v2 on it's port `9999`.

### verify-hostname

Ingress resources has `spec/tls[]/secretName` attribute to override the default X509 certificate.
As a default behavior the certificates are validated against the hostname in order to match the
SAN extension or CN (CN only up to `v0.4`). Invalid certificates, ie certificates which doesn't
match the hostname are discarded and a warning is logged into the ingress controller logging.

Use `--verify-hostname=false` argument to bypass this validation. If used, HAProxy will provide
the certificate declared in the `secretName` ignoring if the certificate is or is not valid.

### watch-namespace

By default the proxy will be configured using all namespaces from the Kubernetes cluster. Use
`--watch-namespace` with the name of a namespace to watch and build the configuration of a
single namespace.
