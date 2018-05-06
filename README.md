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

It is also possible to change the default template mounting a new template file at
`/etc/haproxy/template/haproxy.tmpl`. This is the only file in the directory, so create a
configmap with `haproxy.tmpl` key mounting into `/etc/haproxy/template` will work.

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
|`[0]`|[`ingress.kubernetes.io/auth-tls-cert-header`](#auth-tls)|[true\|false]|[doc](/examples/auth/client-certs)|
||[`ingress.kubernetes.io/auth-tls-error-page`](#auth-tls)|url|[doc](/examples/auth/client-certs)|
||[`ingress.kubernetes.io/auth-tls-secret`](#auth-tls)|namespace/secret name|[doc](/examples/auth/client-certs)|
|`[1]`|[`ingress.kubernetes.io/balance-algorithm`](#balance-algorithm)|algorithm name|-|
|`[1]`|[`ingress.kubernetes.io/blue-green-deploy`](#blue-green)|label=value=weight,...|[doc](/examples/blue-green)|
|`[0]`|[`ingress.kubernetes.io/hsts`](#hsts)|[true\|false]|-|
|`[0]`|[`ingress.kubernetes.io/hsts-include-subdomains`](#hsts)|[true\|false]|-|
|`[0]`|[`ingress.kubernetes.io/hsts-max-age`](#hsts)|qty of seconds|-|
|`[0]`|[`ingress.kubernetes.io/hsts-preload`](#hsts)|[true\|false]|-|
|`[0]`|[`ingress.kubernetes.io/limit-connections`](#limit)|qty|-|
|`[0]`|[`ingress.kubernetes.io/limit-rps`](#limit)|rate per second|-|
|`[0]`|[`ingress.kubernetes.io/limit-whitelist`](#limit)|cidr list|-|
||[`ingress.kubernetes.io/proxy-body-size`](#proxy-body-size)|size (bytes)|-|
||`ingress.kubernetes.io/secure-backends`|[true\|false]|-|
||`ingress.kubernetes.io/secure-verify-ca-secret`|secret name|-|
||[`ingress.kubernetes.io/session-cookie-name`](#affinity)|cookie name|-|
|`[1]`|[`ingress.kubernetes.io/session-cookie-strategy`](#affinity)|[insert\|prefix\|rewrite]|-|
||`ingress.kubernetes.io/ssl-passthrough`|[true\|false]|-|
||`ingress.kubernetes.io/ssl-redirect`|[true\|false]|[doc](/examples/rewrite)|
||`ingress.kubernetes.io/app-root`|/url|[doc](/examples/rewrite)|
||`ingress.kubernetes.io/whitelist-source-range`|CIDR|-|
|`[0]`|[`ingress.kubernetes.io/rewrite-target`](#rewrite-target)|path string|-|
||[`ingress.kubernetes.io/server-alias`](#server-alias)|domain name or regex|-|

### Affinity

Configure if HAProxy should maintain client requests to the same backend server.

* `ingress.kubernetes.io/affinity`: the only supported option is `cookie`. If declared, clients will receive a cookie with a hash of the server it should be fidelized to.
* `ingress.kubernetes.io/session-cookie-name`: the name of the cookie. `INGRESSCOOKIE` is the default value if not declared.
* `ingress.kubernetes.io/session-cookie-strategy`: the cookie strategy to use (insert, rewrite, prefix). `insert` is the default value if not declared.

Note for `dynamic-scaling` users only: the hash of the server is built based on it's name.
When the slots are scaled down, the remaining servers might change it's server name on
HAProxy configuration. In order to circumvent this, always configure the slot increment at
least as much as the number of replicas of the deployment that need to use affinity. This
limitation will be removed when HAProxy version is updated to `1.8`.

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
* `ingress.kubernetes.io/auth-tls-secret`: mandatory secret name with `ca` key providing all certificate authority bundles used to validate client certificates.

See also client cert [sample](/examples/auth/client-certs).

### Blue-green

Configure weight of a blue/green deployment. The annotation accepts a comma separated list of label
name/value pair and a numeric weight. Concatenate label name, label value and weight with an equal
sign, without spaces. The label name/value pair will be used to match corresponding pods.

The endpoints of a single backend are selected using service selectors, which also uses labels.
Because of that, in order to use blue/green deployment, the deployment, daemon set or replication
controller template should have at least two label name/value pairs - one that matches the service
selector and another that matches the blue/green selector.

The following configuration `group=blue=1,group=green=4` will redirect 20% of the load to the
`group=blue` pods and 80% of the load to the `group=green` if they have the same number of replicas.

Note that this configuration is related to every single pod. On the configuration above, if
`group=blue` has two replicas and `group=green` has just one, green would receive only the double
of the number of requests dedicated to blue. This can be adjusted using higher numbers - eg `10/40`
instead of `1/4` - and divided by the number of replicas of each deployment - eg `5/40` instead of
`10/40`.

Value of `0` (zero) can also be used. This will let the endpoint configured in the backend accepting
persistent connections - see [affinity](#affinity) - but will not participate in the load balancing.
The maximum weight value is `256`.

See also the [example](/examples/blue-green) page.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-weight

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

## ConfigMap

If using ConfigMap to configure HAProxy Ingress, use
`--configmap=<namespace>/<configmap-name>` argument on HAProxy Ingress deployment.
A ConfigMap can be created with `kubectl create configmap`.

The following parameters are supported:

* `[0]` only in `canary` tag
* `[1]` only in `snapshot` tag

||Name|Type|Default|
|---|---|---|---|
||[`balance-algorithm`](#balance-algorithm)|algorithm name|`roundrobin`|
||[`backend-check-interval`](#backend-check-interval)|time with suffix|`2s`|
||[`backend-server-slots-increment`](#dynamic-scaling)|number of slots|`32`|
|`[1]`|[`cookie-key`](#cookie-key)|secret key|`Ingress`|
||[`dynamic-scaling`](#dynamic-scaling)|[true\|false]|`false`|
||[`forwardfor`](#forwardfor)|[add\|ignore\|ifmissing]|`add`|
||[`healthz-port`](#healthz-port)|port number|`10253`|
||[`hsts`](#hsts)|[true\|false]|`true`|
||[`hsts-include-subdomains`](#hsts)|[true\|false]|`false`|
||[`hsts-max-age`](#hsts)|number of seconds|`15768000`|
||[`hsts-preload`](#hsts)|[true\|false]|`false`|
||[`http-log-format`](#log-format)|http log format|HAProxy default log format|
|`[0]`|[`https-log-format`](#log-format)|https(tcp) log format\|`default`|do not log|
||[`https-to-http-port`](#https-to-http-port)|port number|0 (do not listen)|
|`[0]`|[`load-server-state`](#load-server-state) (experimental)|[true\|false]|`false`|
||[`max-connections`](#max-connections)|number|`2000`|
||[`proxy-body-size`](#proxy-body-size)|number of bytes|unlimited|
||[`ssl-ciphers`](#ssl-ciphers)|colon-separated list|[link to code](https://github.com/jcmoraisjr/haproxy-ingress/blob/v0.4/pkg/controller/config.go#L35)|
||[`ssl-dh-default-max-size`](#ssl-dh-default-max-size)|number|`1024`|
||[`ssl-dh-param`](#ssl-dh-param)|namespace/secret name|no custom DH param|
|`[0]`|[`ssl-headers-prefix`](#ssl-headers-prefix)|prefix|`X-SSL`|
||[`ssl-options`](#ssl-options)|space-separated list|`no-sslv3` `no-tls-tickets`|
||[`ssl-redirect`](#ssl-redirect)|[true\|false]|`true`|
||[`stats-auth`](#stats)|user:passwd|no auth|
||[`stats-port`](#stats)|port number|`1936`|
||[`stats-proxy-protocol`](#stats)|[true\|false]|`false`|
||[`syslog-endpoint`](#syslog-endpoint)|IP:port (udp)|do not log|
||[`tcp-log-format`](#log-format)|tcp log format|HAProxy default log format|
||[`timeout-client`](#timeout)|time with suffix|`50s`|
||[`timeout-client-fin`](#timeout)|time with suffix|`50s`|
||[`timeout-connect`](#timeout)|time with suffix|`5s`|
||[`timeout-http-request`](#timeout)|time with suffix|`5s`|
||[`timeout-keep-alive`](#timeout)|time with suffix|`1m`|
||[`timeout-server`](#timeout)|time with suffix|`50s`|
||[`timeout-server-fin`](#timeout)|time with suffix|`50s`|
||[`timeout-tunnel`](#timeout)|time with suffix|`1h`|
|`[0]`|[`use-host-on-https`](#use-host-on-https)|[true\|false]|`false`|
||[`use-proxy-protocol`](#use-proxy-protocol)|[true\|false]|`false`|
|`[1]`|[`drain-support`](#drain-support)|[true\|false]|`false`|

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

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#5.2-inter

### cookie-key

Define a secret key used with the IP address and port number of a backend server
to dynamically create a cookie to that server. Only useful on cookie based
server affinity. See also [affinity](#affinity) annotations.

http://cbonte.github.io/haproxy-dconv/1.8/configuration.html#dynamic-cookie-key

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

* `dynamic-scaling`: Define if dynamic scaling should be used whenever possible
* `backend-server-slots-increment`: Configures the minimum number of servers, the size of the increment when growing and the size of the decrement when shrinking of each HAProxy backend

http://cbonte.github.io/haproxy-dconv/1.8/management.html#9.3

### forwardfor

Define if `X-Forwarded-For` header should be added always, added if missing or
ignored from incomming requests. Default is `add` which means HAProxy will itself
generate a `X-Forwarded-For` header with client's IP address and remove this same
header from incomming requests.

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

### proxy-body-size

Define the maximum number of bytes HAProxy will allow on the body of requests. Default is
to not check, which means requests of unlimited size. This limit can be changed per ingress
resource.

Since 0.4 a suffix can be added to the size, so `10m` means
`10 * 1024 * 1024` bytes. Supported suffix are: `k`, `m` and `g`.

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

||Name|Type|Default|
|---|---|---|---|
|`[0]`|[`allow-cross-namespace`](#allow-cross-namespace)|[true\|false]|`false`|
||[`default-backend-service`](#default-backend-service)|namespace/servicename|(mandatory)|
||[`default-ssl-certificate`](#default-ssl-certificate)|namespace/secretname|(mandatory)|
||[`ingress-class`](#ingress-class)|name|`haproxy`|
||[`kubeconfig`](#kubeconfig)|/path/to/kubeconfig|in cluster config|
|`[1]`|[`max-old-config-files`](#max-old-config-files)|num of files|`0`|
|`[0]`|[`rate-limit-update`](#rate-limit-update)|uploads per second (float)|`0.5`|
||[`reload-strategy`](#reload-strategy)|[native\|reusesocket]|`native`|
||[`sort-backends`](#sort-backends)|[true\|false]|`false`|
|`[0]`|[`tcp-services-configmap`](#tcp-services-configmap)|namespace/configmapname|no tcp svc|
|`[0]`|[`verify-hostname`](#verify-hostname)|[true\|false]|`true`|

### allow-cross-namespace

`--allow-cross-namespace` argument, if added, will allow reading secrets from one namespace to an
ingress resource of another namespace. The default behavior is to deny such cross namespace reading.
This adds a breaking change from `v0.4` to `v0.5` on `ingress.kubernetes.io/auth-tls-secret`
annotation, where cross namespace reading were allowed without any configuration.

### default-backend-service

Defines the `namespace/servicename` that should be used if the incomming request doesn't match any
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

The value of the configmap entry has the following syntax: `<namespace>/<servicename>:<portnumber>[:[<in-proxy][:<out-proxy]]`, where:

* `<namespace>/<servicename>` is the well known notation of the service that will receive incomming connections.
* `<portnumber>` is the port number the upstream service is listening - this is not related to the listening port of HAProxy.
* `<in-proxy>` should be defined as `PROXY` if HAProxy should expect requests using the [PROXY](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) protocol. This is usually true only if there is another load balancer in front of HAProxy which supports the PROXY protocol.
* `<out-proxy>` should be defined as `PROXY` if the upstream service expect connections using the PROXY protocol.

In the example below:

```
...
data:
  "5432": "default/pgsql:5432"
  "9900": "system-prod/admin:9900:PROXY"
  "9990": "system-prod/admin:9999::PROXY"
  "9999": "system-prod/admin:9999:PROXY:PROXY"
```

HAProxy will listen 4 new ports:

* `5432` will proxy to a `pgsql` service on `default` namespace.
* `9900` will proxy to `admin` service, port `9900`, on the `system-prod` namespace. Clients should connect using the PROXY protocol.
* `9990` and `9999` will proxy to the same `admin` service and `9990` port and the upstream service will expect connections using the PROXY protocol. The HAProxy frontend, however, will only expect PROXY protocol on it's port `9999`.

### verify-hostname

Ingress resources has `spec/tls[]/secretName` attribute to override the default X509 certificate.
As a default behavior the certificates are validated against the hostname in order to match the
SAN extension or CN (CN only up to `v0.4`). Invalid certificates, ie certificates which doesn't
match the hostname are discarded and a warning is logged into the ingress controller logging.

Use `--verify-hostname=false` argument to bypass this validation. If used, HAProxy will provide
the certificate declared in the `secretName` ignoring if the certificate is or is not valid.
