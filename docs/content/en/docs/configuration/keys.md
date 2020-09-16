---
title: "Configuration keys"
linkTitle: "Configuration keys"
weight: 1
description: >
  List of all ingress/service annotations and global ConfigMap options.
---

Most of HAProxy Ingress configurations are made using a ConfigMap object or annotating
the ingress or service object. Ingress or service annotations are used to make local
configurations, and the ConfigMap is used to make global configurations or change
default configuration values.

# ConfigMap

Global configurations and changing default values are made via a ConfigMap object.
ConfigMap declaration is optional but highly recommended. Create an empty ConfigMap
using `kubectl create configmap` and configures in the haproxy-ingress deployment using
the command-line option `--configmap=<namespace>/<configmap-name>`.

Changes to any key in the ConfigMap object is applied on the fly, the haproxy instance
is restarted or dynamically updated if needed.

All configuration key names are supported as a ConfigMap keys. When declared, its value
is used as the default value if not overwritten elsewhere.

A configuration key is used verbatim as the ConfigMap key name, without any prefix.
The ConfigMap spec expects a string as the key value, so declare numbers and booleans
as strings, HAProxy Ingress will convert it when needed.

# Ingress and services

Local configurations are made using ingress v1 spec, eg hostname, path, backend, port,
secret name of the server certificate and key, and so on. Any other configuration
which is not supported by the v1 spec should be made in the ingress or service object
using annotations.

Changes to annotations in any ingress or service object is applied on the fly, the
haproxy instance is restarted or dynamically updated if needed.

Annotation key names need a prefix in front of the configuration key. The default
prefix is `ingress.kubernetes.io`, so eg the `ssl-redirect` configuration key should
be declared as `ingress.kubernetes.io/ssl-redirect` with value `"true"` or `"false"`.
The annotation value spec expects a string as the key, so declare numbers and
booleans as strings, HAProxy Ingress will convert it when needed. The default
annotation prefix can be changed using the `--annotation-prefix` command-line
option.

An ingress object accepts configuration keys of scope `Host` or `Backend`. A
service object accepts configuration keys of scope `Backend` only. See
[Scope](#scope) below.

Configuration keys declared in services have the highest precedence, overwriting
configuration keys declared in the ConfigMap and ingress objects. Ingress object
overwrite the default value and the ConfigMap configuration.

# Scope

HAProxy Ingress configuration keys may be in one of three distinct scopes. A scope
defines where a configuration key can be declared and how it interacts with ingress
and service objects.

* Scope `Global`: Defines configuration keys that should be declared only in the
ConfigMap object. Configuration keys of the global scope declared as ingress or
service annotations are ignored. A configuration key of the global scope never
conflict.
* Scope `Host`: Defines configuration keys that binds to the hostname. Configuration
keys of the host scope can be declared in the ConfigMap as a default value, or in
an ingress object. A conflict warning will be logged if the same host configuration
key with distinct values are declared in distict ingress objects but to the same
hostname.
* Scope `Backend`: Defines configuration keys that binds to the service object, which
is converted to a HAProxy backend after the configuration parsing. Configuration keys
of the backend scope can be declared in the ConfigMap as a default value, in an ingress
object, or in a service object. A conflict warning will be logged if the same backend
configuration key with distinct values are declared in distict ingress objects but
to the same service or HAProxy backend. A backend configuration key declared in a
service object overwrites the same configuration in an ingress object without
conflicting.

In the case of a conflict, the value of the ingress object which was created first
will be used.

# Configuration keys

The table below describes all supported configuration keys.

| Configuration key                                    | Data type                               | Scope   | Default value      |
|------------------------------------------------------|-----------------------------------------|---------|--------------------|
| [`acme-emails`](#acme)                               | email1,email2,...                       | Global  |                    |
| [`acme-endpoint`](#acme)                             | v2-staging | v2 | endpoint              | Global  |                    |
| [`acme-expiring`](#acme)                             | number of days                          | Global  | `30`               |
| [`acme-shared`](#acme)                               | [true\|false]                           | Global  | `false`            |
| [`acme-terms-agreed`](#acme)                         | [true\|false]                           | Global  | `false`            |
| [`affinity`](#affinity)                              | affinity type                           | Backend |                    |
| [`agent-check-addr`](#agent-check)                   | address for agent checks                | Backend |                    |
| [`agent-check-interval`](#agent-check)               | time with suffix                        | Backend |                    |
| [`agent-check-port`](#agent-check)                   | backend agent listen port               | Backend |                    |
| [`agent-check-send`](#agent-check)                   | string to send upon agent connection    | Backend |                    |
| `app-root`                                           | /url                                    | Host    |                    |
| `auth-realm`                                         | realm string                            | Backend |                    |
| `auth-secret`                                        | secret name                             | Backend |                    |
| [`auth-tls-cert-header`](#auth-tls)                  | [true\|false]                           | Backend |                    |
| [`auth-tls-error-page`](#auth-tls)                   | url                                     | Host    |                    |
| [`auth-tls-secret`](#auth-tls)                       | namespace/secret name                   | Host    |                    |
| [`auth-tls-strict`](#auth-tls)                       | [true\|false]                           | Host    |                    |
| [`auth-tls-verify-client`](#auth-tls)                | [off\|optional\|on\|optional_no_ca]     | Host    |                    |
| `auth-type`                                          | "basic"                                 | Backend |                    |
| [`backend-check-interval`](#health-check)            | time with suffix                        | Backend | `2s`               |
| [`backend-protocol`](#backend-protocol)              | [h1\|h2\|h1-ssl\|h2-ssl]                | Backend | `h1`               |
| [`backend-server-naming`](#backend-server-naming)    | [sequence\|ip\|pod]                     | Backend | `sequence`         |
| [`backend-server-slots-increment`](#dynamic-scaling) | number of slots                         | Backend | `32`               |
| [`balance-algorithm`](#balance-algorithm)            | algorithm name                          | Backend | `roundrobin`       |
| [`bind-fronting-proxy`](#bind)                       | ip + port                               | Global  |                    |
| [`bind-http`](#bind)                                 | ip + port                               | Global  |                    |
| [`bind-https`](#bind)                                | ip + port                               | Global  |                    |
| [`bind-ip-addr-healthz`](#bind-ip-addr)              | IP address                              | Global  |                    |
| [`bind-ip-addr-http`](#bind-ip-addr)                 | IP address                              | Global  |                    |
| [`bind-ip-addr-prometheus`](#bind-ip-addr)           | IP address                              | Global  |                    |
| [`bind-ip-addr-stats`](#bind-ip-addr)                | IP address                              | Global  |                    |
| [`bind-ip-addr-tcp`](#bind-ip-addr)                  | IP address                              | Global  |                    |
| [`blue-green-balance`](#blue-green)                  | label=value=weight,...                  | Backend |                    |
| [`blue-green-cookie`](#blue-green)                   | `CookieName:LabelName` pair             | Backend |                    |
| [`blue-green-deploy`](#blue-green)                   | label=value=weight,...                  | Backend |                    |
| [`blue-green-header`](#blue-green)                   | `HeaderName:LabelName` pair             | Backend |                    |
| [`blue-green-mode`](#blue-green)                     | [pod\|deploy]                           | Backend |                    |
| [`cert-signer`](#acme)                               | "acme"                                  | Host    |                    |
| [`config-backend`](#configuration-snippet)           | multiline HAProxy backend config        | Backend |                    |
| [`config-defaults`](#configuration-snippet)          | multiline HAProxy config for the defaults section | Global |           |
| [`config-frontend`](#configuration-snippet)          | multiline HAProxy frontend config       | Global  |                    |
| [`config-global`](#configuration-snippet)            | multiline HAProxy global config         | Global  |                    |
| [`cookie-key`](#affinity)                            | secret key                              | Global  | `Ingress`          |
| [`cors-allow-credentials`](#cors)                    | [true\|false]                           | Backend |                    |
| [`cors-allow-headers`](#cors)                        | headers list                            | Backend |                    |
| [`cors-allow-methods`](#cors)                        | methods list                            | Backend |                    |
| [`cors-allow-origin`](#cors)                         | URL                                     | Backend |                    |
| [`cors-enable`](#cors)                               | [true\|false]                           | Backend |                    |
| [`cors-expose-headers`](#cors)                       | headers                                 | Backend |                    |
| [`cors-max-age`](#cors)                              | time (seconds)                          | Backend |                    |
| [`cpu-map`](#cpu-map)                                | haproxy CPU Map format                  | Global  |                    |
| [`dns-accepted-payload-size`](#dns-resolvers)        | number                                  | Global  | `8192`             |
| [`dns-cluster-domain`](#dns-resolvers)               | cluster name                            | Global  | `cluster.local`    |
| [`dns-hold-obsolete`](#dns-resolvers)                | time with suffix                        | Global  | `0s`               |
| [`dns-hold-valid`](#dns-resolvers)                   | time with suffix                        | Global  | `1s`               |
| [`dns-resolvers`](#dns-resolvers)                    | multiline resolver=ip[:port]            | Global  |                    |
| [`dns-timeout-retry`](#dns-resolvers)                | time with suffix                        | Global  | `1s`               |
| [`drain-support`](#drain-support)                    | [true\|false]                           | Global  | `false`            |
| [`drain-support-redispatch`](#drain-support)         | [true\|false]                           | Global  | `true`             |
| [`dynamic-scaling`](#dynamic-scaling)                | [true\|false]                           | Backend | `true`             |
| [`forwardfor`](#forwardfor)                          | [add\|ignore\|ifmissing]                | Global  | `add`              |
| [`fronting-proxy-port`](#fronting-proxy-port)        | port number                             | Global  | 0 (do not listen)  |
| [`headers`](#headers)                                | multiline header:value pair             | Backend |                    |
| [`health-check-addr`](#health-check)                 | address for health checks               | Backend |                    |
| [`health-check-fall-count`](#health-check)           | number of failures                      | Backend |                    |
| [`health-check-interval`](#health-check)             | time with suffix                        | Backend |                    |
| [`health-check-port`](#health-check)                 | port for health checks                  | Backend |                    |
| [`health-check-rise-count`](#health-check)           | number of successes                     | Backend |                    |
| [`health-check-uri`](#health-check)                  | uri for http health checks              | Backend |                    |
| [`healthz-port`](#bind-port)                         | port number                             | Global  | `10253`            |
| [`hsts`](#hsts)                                      | [true\|false]                           | Backend | `true`             |
| [`hsts-include-subdomains`](#hsts)                   | [true\|false]                           | Backend | `false`            |
| [`hsts-max-age`](#hsts)                              | number of seconds                       | Backend | `15768000`         |
| [`hsts-preload`](#hsts)                              | [true\|false]                           | Backend | `false`            |
| [`http-log-format`](#log-format)                     | http log format                         | Global  | HAProxy default log format |
| [`http-port`](#bind-port)                            | port number                             | Global  | `80`               |
| [`https-log-format`](#log-format)                    | https(tcp) log format\|`default`        | Global  | do not log         |
| [`https-port`](#bind-port)                           | port number                             | Global  | `443`              |
| [`https-to-http-port`](#fronting-proxy-port)         | port number                             | Global  | 0 (do not listen)  |
| [`initial-weight`](#initial-weight)                  | weight value                            | Backend | `1`                |
| [`limit-connections`](#limit)                        | qty                                     | Backend |                    |
| [`limit-rps`](#limit)                                | rate per second                         | Backend |                    |
| [`limit-whitelist`](#limit)                          | cidr list                               | Backend |                    |
| [`load-server-state`](#load-server-state) (experimental) |[true\|false]                        | Global  | `false`            |
| [`max-connections`](#connection)                     | number                                  | Global  | `2000`             |
| [`maxconn-server`](#connection)                      | qty                                     | Backend |                    |
| [`maxqueue-server`](#connection)                     | qty                                     | Backend |                    |
| [`modsecurity-endpoints`](#modsecurity)              | comma-separated list of IP:port (spoa)  | Global  | no waf config      |
| [`modsecurity-timeout-hello`](#modsecurity)          | time with suffix                        | Global  | `100ms`            |
| [`modsecurity-timeout-idle`](#modsecurity)           | time with suffix                        | Global  | `30s`              |
| [`modsecurity-timeout-processing`](#modsecurity)     | time with suffix                        | Global  | `1s`               |
| [`nbproc-ssl`](#nbproc)                              | number of process                       | Global  | `0`                |
| [`nbthread`](#nbthread)                              | number of threads                       | Global  | `2`                |
| [`no-tls-redirect-locations`](#ssl-redirect)         | comma-separated list of URIs            | Global  | `/.well-known/acme-challenge` |
| [`oauth`](#oauth)                                    | "oauth2_proxy"                          | Backend |                    |
| [`oauth-headers`](#oauth)                            | `<header>:<var>,...`                    | Backend |                    |
| [`oauth-uri-prefix`](#oauth)                         | URI prefix                              | Backend |                    |
| [`path-type`](#path-type)                            | path matching type                      | Host    | `begin`            |
| [`path-type-order`](#path-type)                      | comma-separated path type list          | Global  | `exact,prefix,begin,regex` |
| [`prometheus-port`](#bind-port)                      | port number                             | Global  |                    |
| [`proxy-body-size`](#proxy-body-size)                | size (bytes)                            | Backend | unlimited          |
| [`proxy-protocol`](#proxy-protocol)                  | [v1\|v2\|v2-ssl\|v2-ssl-cn]             | Backend |                    |
| [`rewrite-target`](#rewrite-target)                  | path string                             | Backend |                    |
| [`secure-backends`](#secure-backend)                 | [true\|false]                           | Backend |                    |
| [`secure-crt-secret`](#secure-backend)               | secret name                             | Backend |                    |
| [`secure-verify-ca-secret`](#secure-backend)         | secret name                             | Backend |                    |
| [`server-alias`](#server-alias)                      | domain name                             | Host    |                    |
| [`server-alias-regex`](#server-alias)                | regex                                   | Host    |                    |
| [`service-upstream`](#service-upstream)              | [true\|false]                           | Backend | `false`            |
| [`session-cookie-dynamic`](#affinity)                | [true\|false]                           | Backend |                    |
| [`session-cookie-keywords`](#affinity)               | cookie options                          | Backend | `indirect nocache httponly`     |
| [`session-cookie-name`](#affinity)                   | cookie name                             | Backend |                    |
| [`session-cookie-preserve`](#affinity)               | [true\|false]                           | Backend | `false`            |
| [`session-cookie-shared`](#affinity)                 | [true\|false]                           | Backend | `false`            |
| [`session-cookie-strategy`](#affinity)               | [insert\|prefix\|rewrite]               | Backend |                    |
| [`session-cookie-value-strategy`](#affinity)         | [server-name\|pod-uid]                  | Backend | `server-name`      |
| [`slots-min-free`](#dynamic-scaling)                 | minimum number of free slots            | Backend | `0`                |
| [`ssl-cipher-suites`](#ssl-ciphers)                  | colon-separated list                    | Host    | [see description](#ssl-ciphers) |
| [`ssl-cipher-suites-backend`](#ssl-ciphers)          | colon-separated list                    | Backend | [see description](#ssl-ciphers) |
| [`ssl-ciphers`](#ssl-ciphers)                        | colon-separated list                    | Host    | [see description](#ssl-ciphers) |
| [`ssl-ciphers-backend`](#ssl-ciphers)                | colon-separated list                    | Backend | [see description](#ssl-ciphers) |
| [`ssl-dh-default-max-size`](#ssl-dh)                 | number                                  | Global  | `1024`             |
| [`ssl-dh-param`](#ssl-dh)                            | namespace/secret name                   | Global  | no custom DH param |
| [`ssl-engine`](#ssl-engine)                          | OpenSSL engine name and parameters      | Global  | no engine set      |
| [`ssl-fingerprint-lower`](#auth-tls)                 | [true\|false]                           | Backend | `false`            |
| [`ssl-headers-prefix`](#auth-tls)                    | prefix                                  | Global  | `X-SSL`            |
| [`ssl-mode-async`](#ssl-engine)                      | [true\|false]                           | Global  | `false`            |
| [`ssl-options`](#ssl-options)                        | space-separated list                    | Global  | [see description](#ssl-options) |
| [`ssl-options-backend`](#ssl-options)                | space-separated list                    | Backend | [see description](#ssl-options) |
| [`ssl-options-host`](#ssl-options)                   | space-separated list                    | Host    | [see description](#ssl-options) |
| [`ssl-passthrough`](#ssl-passthrough)                | [true\|false]                           | Host    |                    |
| [`ssl-passthrough-http-port`](#ssl-passthrough)      | backend port                            | Host    |                    |
| [`ssl-redirect`](#ssl-redirect)                      | [true\|false]                           | Backend | `true`             |
| [`ssl-redirect-code`](#ssl-redirect)                 | http status code                        | Global  | `302`              |
| [`stats-auth`](#stats)                               | user:passwd                             | Global  | no auth            |
| [`stats-port`](#stats)                               | port number                             | Global  | `1936`             |
| [`stats-proxy-protocol`](#stats)                     | [true\|false]                           | Global  | `false`            |
| [`stats-ssl-cert`](#stats)                           | namespace/secret name                   | Global  | no ssl/plain http  |
| [`strict-host`](#strict-host)                        | [true\|false]                           | Global  | `false`            |
| [`syslog-endpoint`](#syslog)                         | IP:port (udp)                           | Global  | do not log         |
| [`syslog-format`](#syslog)                           | rfc5424\|rfc3164                        | Global  | `rfc5424`          |
| [`syslog-length`](#syslog)                           | maximum length                          | Global  | `1024`             |
| [`syslog-tag`](#syslog)                              | syslog tag field string                 | Global  | `ingress`          |
| [`tcp-log-format`](#log-format)                      | tcp log format                          | Global  | HAProxy default log format |
| [`timeout-client`](#timeout)                         | time with suffix                        | Global  | `50s`              |
| [`timeout-client-fin`](#timeout)                     | time with suffix                        | Global  | `50s`              |
| [`timeout-connect`](#timeout)                        | time with suffix                        | Backend | `5s`               |
| [`timeout-http-request`](#timeout)                   | time with suffix                        | Backend | `5s`               |
| [`timeout-keep-alive`](#timeout)                     | time with suffix                        | Backend | `1m`               |
| [`timeout-queue`](#timeout)                          | time with suffix                        | Backend | `5s`               |
| [`timeout-server`](#timeout)                         | time with suffix                        | Backend | `50s`              |
| [`timeout-server-fin`](#timeout)                     | time with suffix                        | Backend | `50s`              |
| [`timeout-stop`](#timeout)                           | time with suffix                        | Global  | no timeout         |
| [`timeout-tunnel`](#timeout)                         | time with suffix                        | Backend | `1h`               |
| [`tls-alpn`](#tls-alpn)                              | TLS ALPN advertisement                  | Host    | `h2,http/1.1`      |
| [`use-chroot`](#security)                            | [true\|false]                           | Global  | `false`            |
| [`use-cpu-map`](#cpu-map)                            | [true\|false]                           | Global  | `true`             |
| [`use-forwarded-proto`](#fronting-proxy-port)        | [true\|false]                           | Global  | `true`             |
| [`use-haproxy-user`](#security)                      | [true\|false]                           | Global  | `false`            |
| [`use-htx`](#use-htx)                                | [true\|false]                           | Global  | `false`            |
| [`use-proxy-protocol`](#proxy-protocol)              | [true\|false]                           | Global  | `false`            |
| [`use-resolver`](#dns-resolvers)                     | resolver name                           | Backend |                    |
| [`var-namespace`](#var-namespace)                    | [true\|false]                           | Host    | `false`            |
| [`waf`](#waf)                                        | "modsecurity"                           | Backend |                    |
| [`waf-mode`](#waf)                                   | [deny\|detect]                          | Backend | `deny` (if waf is set) |
| `whitelist-source-range`                             | CIDR                                    | Backend |                    |

---

## Acme

| Configuration key   | Scope    | Default | Since |
|---------------------|----------|---------|-------|
| `acme-emails`       | `Global` |         | v0.9  |
| `acme-endpoint`     | `Global` |         | v0.9  |
| `acme-expiring`     | `Global` | `30`    | v0.9  |
| `acme-shared`       | `Global` | `false` | v0.9  |
| `acme-terms-agreed` | `Global` | `false` | v0.9  |
| `cert-signer`       | `Host`   |         | v0.9  |

Configures dynamic options used to authorize and sign certificates against a server
which implements the acme protocol, version 2.

The popular [Let's Encrypt](https://letsencrypt.org) certificate authority implements
acme-v2.

Supported acme configuration keys:

* `acme-emails`: mandatory, a comma-separated list of emails used to configure the client account. The account will be updated if this option is changed.
* `acme-endpoint`: mandatory, endpoint of the acme environment. `v2-staging` and `v02-staging` are alias to `https://acme-staging-v02.api.letsencrypt.org`, while `v2` and `v02` are alias to `https://acme-v02.api.letsencrypt.org`.
* `acme-expiring`: how many days before expiring a certificate should be considered old and should be updated. Defaults to `30` days.
* `acme-shared`: defines if another certificate signer is running in the cluster. If `false`, the default value, any request to `/.well-known/acme-challenge/` is sent to the local acme server despite any ingress object configuration. Otherwise, if `true`, a configured ingress object would take precedence.
* `acme-terms-agreed`: mandatory, it should be defined as `true`, otherwise certificates won't be issued.
* `cert-signer`: defines the certificate signer that should be used to authorize and sign new certificates. The only supported value is `"acme"`. Add this config as an annotation in the ingress object that should have its certificate managed by haproxy-ingress and signed by the configured acme environment. The annotation `kubernetes.io/tls-acme: "true"` is also supported if the command-line option `--acme-track-tls-annotation` is used.

**Minimum setup**

The command-line option `--acme-server` need to be declared to start the local
server and the work queue used to authorize and sign new certificates. See other
command-line options [here]({{% relref "command-line/#acme" %}}).

The following configuration keys are mandatory: `acme-emails`, `acme-endpoint`,
`acme-terms-agreed`.

A cluster-wide permission to `create` and `update` the `secrets` resources should
also be made.

{{% alert title="Note" %}}
haproxy-ingress need cluster-wide permissions `create` and `update` on resource
`secrets` to store the client private key (new account) and the generated certificate
and its private key. The default clusterrole configuration doesn't provide these
permissions.
{{% /alert %}}

**How it works**

All haproxy-ingress instances should declare `--acme-server`
[command-line option]({{% relref "command-line/#acme" %}}), which will start a local
server to answer acme challenges, a work queue to enqueue the domain authorization
and certificate signing, and will also start a leader election to define which
haproxy-ingress instance should perform authorizations and certificate signing.

The haproxy-ingress leader tracks ingress objects that declares the annotation
`ingress.kubernetes.io/cert-signer` with value `acme` and a configured secret name for
TLS certificate. The annotation `kubernetes.io/tls-acme` with value `"true"` will also
be used if the command-line option `--acme-track-tls-annotation` is declared. The
secret does not need to exist. A new certificate will be issued if the certificate is
old, the secret does not exist or has an invalid certificate, or the domains of the
certificate doesn't cover all the domains configured in the ingress.

Every `24h` or the duration configured in the `--acme-check-period`, and also when the
leader changes, all the certificates from all the tracked ingress will be verified. The
certificate is also verified whenever the list of the domains or the secret name changes,
so the periodic check will, in fact, only issue new certificates when there is `30` days
or less to the certificate expires. This duration can be changed with `acme-expiring`
configuration key.

If an authorization fails, the certificate request is re-enqueued to be tried again after
`5m`. This duration can be changed with `--acme-fail-initial-duration` command-line
option. If the request fails again, it will be re-enqueued after the double of the time,
in this case, after `10m`. The duration will exponentially increase up to `8h` or the
duration defined by the command-line option `--acme-fail-max-duration`. The request will
continue in the work queue until it is successfully processed and stored, or when the
ingress object is untracked, either removing the annotation, removing the secret name or
removing the ingress object itself.

See also:

* [acme command-line options]({{% relref "command-line/#acme" %}}) doc.

---


## Affinity

| Configuration key               | Scope     | Default                     | Since |
|---------------------------------|-----------|-----------------------------|-------|
| `affinity`                      | `Backend` | `false`                     |       |
| `cookie-key`                    | `Global`  | `Ingress`                   |       |
| `session-cookie-dynamic`        | `Backend` | `true`                      |       |
| `session-cookie-keywords`       | `Backend` | `indirect nocache httponly` | v0.11 |
| `session-cookie-name`           | `Backend` | `INGRESSCOOKIE`             |       |
| `session-cookie-preserve`       | `Backend` | `false`                     | v0.12 |
| `session-cookie-shared`         | `Backend` | `false`                     | v0.8  |
| `session-cookie-strategy`       | `Backend` | `insert`                    |       |
| `session-cookie-value-strategy` | `Backend` | `server-name`               | v0.12 |

Configure if HAProxy should maintain client requests to the same backend server.

* `affinity`: the only supported option is `cookie`. If declared, clients will receive a cookie with a hash of the server it should be fidelized to.
* `cookie-key`: defines a secret key used with the IP address and port number of a backend server to dynamically create a cookie to that server. Defaults to `Ingress` if not provided.
* `session-cookie-dynamic`: indicates whether or not dynamic cookie value will be used. With the default of `true`, a cookie value will be generated by HAProxy using a hash of the server IP address, TCP port, and dynamic cookie secret key. When `false`, the server name will be used as the cookie name. Note that setting this to `false` will have no impact if [use-resolver](#dns-resolvers) is set.
* `session-cookie-keywords`: additional options to the `cookie` option like `nocache`, `httponly`. For the sake of backwards compatibility the default is `indirect nocache httponly` if not declared and `strategy` is `insert`.
* `session-cookie-name`: the name of the cookie. `INGRESSCOOKIE` is the default value if not declared.
* `session-cookie-preserve`: indicates whether the session cookie will be set to `preserve` mode. If this mode is enabled, haproxy will allow backend servers to use a `Set-Cookie` HTTP header to emit their own persistence cookie value, meaning the backend servers have knowledge of which cookie value should route to which server. Since the cookie value is tightly coupled with a particular backend server in this scenario, this mode will cause dynamic updating to understand that it must keep the same cookie value associated with the same backend server. If this is disabled, dynamic updating is free to assign servers in a way that can make their cookie value no longer matching.
* `session-cookie-shared`: defines if the persistence cookie should be shared between all domains that uses this backend. Defaults to `false`. If `true` the `Set-Cookie` response will declare all the domains that shares this backend, indicating to the HTTP agent that all of them should use the same backend server.
* `session-cookie-strategy`: the cookie strategy to use (insert, rewrite, prefix). `insert` is the default value if not declared.
* `session-cookie-value-strategy`: the strategy to use to calculate the cookie value of a server (`server-name`, `pod-uid`). `server-name` is the default if not declared, and indicates that the cookie will be set based on the name defined in `backend-server-naming`. `pod-uid` indicates that the cookie will be set to the `UID` of the pod running the target server.

Note for `dynamic-scaling` users only, v0.5 or older: the hash of the server is built based on it's name.
When the slots are scaled down, the remaining servers might change it's server name on
HAProxy configuration. In order to circumvent this, always configure the slot increment at
least as much as the number of replicas of the deployment that need to use affinity. This
limitation was removed on v0.6.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-cookie
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-cookie
* https://www.haproxy.com/blog/load-balancing-affinity-persistence-sticky-sessions-what-you-need-to-know/
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#dynamic-cookie-key

---

## Agent check

| Configuration key         | Scope     | Default | Since |
|---------------------------|-----------|---------|-------|
| `agent-check-addr`        | `Backend` |         | v0.8  |
| `agent-check-interval`    | `Backend` |         | v0.8  |
| `agent-check-port`        | `Backend` |         | v0.8  |
| `agent-check-send`        | `Backend` |         | v0.8  |

Allows HAProxy agent checks to be defined for a backend. This is an auxiliary
check that is run independently of a regular health check and can be used to
control the reported status of a server as well as the weight to be used for
load balancing.

{{% alert title="Note" %}}
* `agent-check-port` must be provided for any of the agent check options to be applied
* define [`initial-weight`](#initial-weight) if using `agent-check` to change the server weight
{{% /alert %}}

* `agent-check-port`: Defines the port on which the agent is listening. This
option is required in order to use an agent check.
* `agent-check-addr`: Defines the address for agent checks. If omitted, the
server address will be used.
* `agent-check-interval`: Defines the interval between agent checks. If omitted,
the default of 2 seconds will be used.
* `agent-check-send`: Defines a string to be sent to the agent upon connection.

The following limitations are known when using `agent-check` to change the weight
of a backend server:

* If using [`drain-support`](#drain-support), the backend server will have its
initial weight defined as `0` (zero) if the server is terminating when haproxy
is restarted, making the weight update useless
* Blue/green annotation might be dynamically applied, which will temporarily
overwrite the weight defined from the agent

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-agent-check
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-agent-port
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-agent-inter
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-agent-send

---

## Auth TLS

| Configuration key        | Scope     | Default | Since  |
|--------------------------|-----------|---------|--------|
| `auth-tls-cert-header`   | `Backend` | `false` |        |
| `auth-tls-error-page`    | `Host`    |         |        |
| `auth-tls-secret`        | `Host`    |         |        |
| `auth-tls-strict`        | `Host`    | `false` | v0.8.1 |
| `auth-tls-verify-client` | `Host`    |         |        |
| `ssl-fingerprint-lower`  | `Backend` | `false` | v0.10  |
| `ssl-headers-prefix`     | `Global`  | `X-SSL` |        |

Configure client authentication with X509 certificate. The following headers are
added to the request:

* `X-SSL-Client-SHA1`: Hex encoding of the SHA-1 fingerprint of the X509 certificate. The default output uses uppercase hexadecimal digits, configure `ssl-fingerprint-lower` to `true` to use lowercase digits instead.
* `X-SSL-Client-DN`: Distinguished name of the certificate
* `X-SSL-Client-CN`: Common name of the certificate

The prefix of the header names can be configured with `ssl-headers-prefix` key.
The default value is to `X-SSL`, which will create a `X-SSL-Client-DN` header with
the DN of the certificate.

The following keys are supported:

* `auth-tls-cert-header`: If `true` HAProxy will add `X-SSL-Client-Cert` http header with a base64 encoding of the X509 certificate provided by the client. Default is to not provide the client certificate.
* `auth-tls-error-page`: Optional URL of the page to redirect the user if he doesn't provide a certificate or the certificate is invalid.
* `auth-tls-secret`: Mandatory secret name with `ca.crt` key providing all certificate authority bundles used to validate client certificates. Since v0.9, an optional `ca.crl` key can also provide a CRL in PEM format for the server to verify against.
* `auth-tls-strict`: Defines if a wrong or incomplete configuration, eg missing secret with `ca.crt`, should forbid connection attempts. If `false`, the default value, a wrong or incomplete configuration will ignore the authentication config, allowing anonymous connection. If `true`, a strict configuration is used: all requests will be rejected with HTTP 495 or 496, or redirected to the error page if configured, until a proper `ca.crt` is provided. Strict configuration will only be used if `auth-tls-secret` has a secret name and `auth-tls-verify-client` is missing or is not configured as `off`.
* `auth-tls-verify-client`: Optional configuration of Client Verification behavior. Supported values are `off`, `on`, `optional` and `optional_no_ca`. The default value is `on` if a valid secret is provided, `off` otherwise.
* `ssl-fingerprint-lower`: Defines if the certificate fingerprint should be in lowercase hexadecimal digits. The default value is `false`, which uses uppercase digits.
* `ssl-headers-prefix`: Configures which prefix should be used on HTTP headers. Since [RFC 6648](https://tools.ietf.org/html/rfc6648) `X-` prefix on unstandardized headers changed from a convention to deprecation. This configuration allows to select which pattern should be used on header names.

See also:

* [example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/auth/client-certs) page.

---

## Backend protocol

| Configuration key  | Scope     | Default | Since |
|--------------------|-----------|---------|-------|
| `backend-protocol` | `Backend` | `h1`    | v0.9  |

Defines the HTTP protocol version of the backend. Note that HTTP/2 is only supported if HTX is enabled.
A case insensitive match is used, so either `h1` or `H1` configures HTTP/1 protocol. A non SSL/TLS
configuration does not overrides [secure-backends](#secure-backend), so `h1` and secure-backends `true`
will still configures SSL/TLS.

Options:

* `h1`: the default value, configures HTTP/1 protocol. `http` is an alias to `h1`.
* `h1-ssl`: configures HTTP/1 over SSL/TLS. `https` is an alias to `h1-ssl`.
* `h2`: configures HTTP/2 protocol. `grpc` is an alias to `h2`.
* `h2-ssl`: configures HTTP/2 over SSL/TLS. `grpcs` is an alias to `h2-ssl`.

See also:

* [use-htx](#use-htx) configuration key to enable HTTP/2 backends.
* [secure-backend](#secure-backend) configuration keys to configure optional client certificate and certificate authority bundle of SSL/TLS connections.
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-proto

---

## Backend server naming

| Configuration key       | Scope     | Default    | Since    |
|-------------------------|-----------|------------|----------|
| `backend-server-naming` | `Backend` | `sequence` | `v0.8.1` |

Configures how to name backend servers.

* `sequence`: Names backend servers with a prefixed number sequence: `srv001`, `srv002`, and so on. This is the default configuration and the preferred option if dynamic udpate is used. `seq` is an alias to `sequence`.
* `pod`: Uses the k8s pod name as the backend server name. This option doesn't work on backends whose [`service-upstream`](#service-upstream) is `true`, falling back to `sequence`.
* `ip`: Uses target's `<ip>:<port>` as the server name.

{{% alert title="Note" %}}
HAProxy Ingress won't refuse to change the default naming if dynamic update is `true`, this would however lead to undesired behaviour: empty slots would still be named as sequences, old-named backend servers will dynamically receive new workloads with new pod names or IP numbers which do not relate with the name anymore, making the naming useless, if not wrong. If you have [cookie affinity](#affinity) enabled, dynamic updating can cause the cookie values to get out of sync with the servers. This can be avoided by using `session-cookie-preserve` with a value of `true`.
{{% /alert %}}

---

## Balance algorithm

| Configuration key   | Scope     | Default      | Since |
|---------------------|-----------|--------------|-------|
| `balance-algorithm` | `Backend` | `roundrobin` |       |

Defines a valid HAProxy load balancing algorithm. The default value is `roundrobin`.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-balance

---

## Bind

| Configuration key      | Scope    | Default | Since |
|------------------------|----------|---------|-------|
| `bind-fronting-proxy`  | `Global` |         | v0.8  |
| `bind-http`            | `Global` |         | v0.8  |
| `bind-https`           | `Global` |         | v0.8  |

Configures listening IP and port for HTTP/s incoming requests. These
configuration keys have backward compatibility with [Bind IP addr](#bind-ip-addr),
[Bind port](#bind-port) and [Fronting proxy](#fronting-proxy-port) keys.
The bind configuration keys in this section have precedente if declared.

Any HAProxy supported option can be used, this will be copied verbatim to the
bind keyword. See HAProxy
[bind keyword doc](#https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-bind).

Configuration examples:

* `bind-http: ":::80"` and `bind-https: ":::443"`: Listen all IPv6 addresses
* `bind-http: ":80,:::80"` and `bind-https:  ":443,:::443"`: Listen all IPv4 and IPv6 addresses
* `bind-https: ":443,:8443"`: accept https connections on `443` and also `8443` port numbers

{{% alert title="Note" %}}
`bind-fronting-proxy` and `bind-http` can share the same port number, provided
that the whole configuration key match, not only the port number.
See [Fronting proxy](#fronting-proxy-port) doc.
{{% /alert %}}

{{% alert title="Warning" color="warning" %}}
Special care should be taken on port number overlap, nether haproxy itself nor
haproxy-ingress will warn if the same port number is used in more than one
configuration key.
{{% /alert %}}

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-bind
* [Bind IP addr](#bind-ip-addr)
* [Bind port](#bind-port)

---

## Bind IP addr

| Configuration key         | Scope    | Default | Since |
|---------------------------|----------|---------|-------|
| `bind-ip-addr-healthz`    | `Global` |         |       |
| `bind-ip-addr-http`       | `Global` |         |       |
| `bind-ip-addr-prometheus` | `Global` |         | v0.10 |
| `bind-ip-addr-stats`      | `Global` |         |       |
| `bind-ip-addr-tcp`        | `Global` |         |       |

Define listening IPv4/IPv6 address on public HAProxy frontends. Since v0.10 the default
value changed from `*` to an empty string, which haproxy interprets in the same way and
binds on all IPv4 address.

* `bind-ip-addr-tcp`: IP address of all TCP services declared on [`tcp-services`](#tcp-services-configmap) command-line option.
* `bind-ip-addr-healthz`: IP address of the health check URL.
* `bind-ip-addr-http`: IP address of all HTTP/s frontends, port `:80` and `:443`, and also [`https-to-http-port`](#https-to-http-port) if declared.
* `bind-ip-addr-prometheus`: IP address of the haproxy's internal Prometheus exporter.
* `bind-ip-addr-stats`: IP address of the statistics page. See also [`stats-port`](#stats).

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-bind
* [Bind](#bind)
* [Bind port](#bind-port)

---

## Bind port

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `healthz-port`    | `Global` | `10253` |       |
| `http-port`       | `Global` | `80`    |       |
| `https-port`      | `Global` | `443`   |       |
| `prometheus-port` | `Global` |         | v0.10 |

* `healthz-port`: Define the port number HAProxy should listen to in order to answer for health checking requests. Use `/healthz` as the request path.
* `http-port`: Define the port number of unencripted HTTP connections.
* `https-port`: Define the port number of encripted HTTPS connections.
* `prometheus-port`: Define the port number of the haproxy's internal Prometheus exporter. Defaults to not create the listener. A listener without being scraped does not use system resources, except for the listening port. The internal exporter supports scope filter as a query string, eg `/metrics?scope=frontend&scope=backend` will only export frontends and backends. See the full description in the [HAProxy's Prometheus exporter doc](https://git.haproxy.org/?p=haproxy-2.0.git;a=blob;f=contrib/prometheus-exporter/README;hb=HEAD).

{{% alert title="Note" %}}
The internal Prometheus exporter runs concurrently with request processing, and it is
about 5x slower and 20x more verbose than the CSV exporter. See the haproxy's exporter
[doc](https://github.com/haproxy/haproxy/blob/v2.0.0/contrib/prometheus-exporter/README#L44).
Consider use Prometheus' [haproxy_exporter](https://github.com/prometheus/haproxy_exporter)
on very large clusters - Prometheus' implementation reads the CSV from the stats page and
converts to the Prometheus syntax outside the haproxy process. On the other side the internal
exporter supports scope filtering, which should make at least the processing time between csv
and prometheus exporter very close if servers are filtered out. Make your own tests before
choosing between one or the other.
{{% /alert %}}

See also:

* [Bind](#bind) configuration key
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-monitor-uri (`healthz-port`)
* https://git.haproxy.org/?p=haproxy-2.0.git;a=blob;f=contrib/prometheus-exporter/README;hb=HEAD (`prometheus-port`)

---

## Blue-green

| Configuration key    | Scope     | Default  | Since |
|----------------------|-----------|----------|-------|
| `blue-green-balance` | `Backend` |          |       |
| `blue-green-cookie`  | `Backend` |          | v0.9  |
| `blue-green-header`  | `Backend` |          | v0.9  |
| `blue-green-mode`    | `Backend` | `deploy` |       |

Configure backend server groups based on the weight of the group - blue/green
balance - or a group selection based on http header or cookie value - blue/green selector.

Both blue/green configurations can be used together: if the http header or cookie isn't provided
or doesn't match a group, the blue/green balance will be used.

Blue/green reads endpoint weight from the pod lister. However the `--disable-pod-list`
command-line option can be safely used to save some memory on clusters with a huge amount of
pods. If pod list is disabled, pods are read straight from the k8s api, only when needed,
without changing blue/green behavior.

See below the description of the two blue/green configuration options.

**Blue/green balance**

Configures weight of a blue/green deployment. The annotation accepts a comma separated list of label
name/value pair and a numeric weight. Concatenate label name, label value and weight with an equal
sign, without spaces. The label name/value pair will be used to match corresponding pods or deploys.
There is no limit to the number of label/weight balance configurations.

The endpoints of a single backend are selected using service selectors, which also uses labels.
Because of that, in order to use blue/green deployment, the deployment, daemon set or replication
controller template should have at least two label name/value pairs - one that matches the service
selector and another that matches the blue/green selector.

* `blue-green-balance`: comma separated list of labels and weights
* `blue-green-deploy`: deprecated on v0.7, this is an alias to `blue-green-balance`.
* `blue-green-mode`: defaults to `deploy` on v0.7, defines how to apply the weights, might be `pod` or `deploy`

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

**Blue/green selector**

Configures header or cookie name and also a pod label name used to tag the group of backend servers.

* `blue-green-cookie`: the `CookieName:LabelName` pair
* `blue-green-header`: the `HeaderName:LabelName` pair

The `CookieName` or `HeaderName` is the name of the http cookie or header used in the request to match
a group name. The `LabelName` is the name of the pod label used to read the group name of the backend
server.

The following configuration `X-Server:group` on `blue-green-header` configures HAProxy to try to match
a backend server based on the value of its label `group`. A request with header `X-Server: green` will
match a pod labeled `group=green`. Cookie configuration follows the same rules.

The name of the header and the label follow the k8s label naming convention: must consist of
alphanumeric characters, `-`, `_` or `.`, and must start and end with an alphanumeric character.

Both cookie and header based configurations can be used together in the same backend (k8s service),
provided that the label name is the same. If the request uses the configured header and cookie, the
header will take precedence, and the cookie would be used if the header value provided doesn't match
a healthy backend server.

Note that blue/green selector should be used only on controlled testing scenarios because it
doesn't provide a proper load balancing: the first healthy backend server that match header or
cookie configuration will be used despite if a proper load balance algorithm would choose another
one. This can be changed in the future. Blue/green balance doesn't have this limitation and properly
uses the chosen load balance algorithm.

See also:

* [example]({{% relref "../examples/blue-green" %}}) page.
* [disable-pod-list]({{% relref "command-line/#disable-pod-list" %}}) command-line option doc.
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-weight (`weight` based balance)
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-use-server (`use-server` based selector)

---

## Configuration snippet

| Configuration key | Scope     | Default  | Since |
|-------------------|-----------|----------|-------|
| `config-backend`  | `Backend` |          |       |
| `config-defaults` | `Global`  |          | v0.8  |
| `config-frontend` | `Global`  |          |       |
| `config-global`   | `Global`  |          |       |

Add HAProxy configuration snippet to the configuration file. Use multiline content
to add more than one line of configuration.

Examples - ConfigMap:

```yaml
    config-global: |
      tune.bufsize 32768
```

```yaml
    config-defaults: |
      option redispatch
```

```yaml
    config-frontend: |
      capture request header X-User-Id len 32
```

Annotation:

```yaml
    annotations:
      ingress.kubernetes.io/config-backend: |
        acl bar-url path /bar
        http-request deny if bar-url
```

The following keys add a configuration snippet to the ...:

* `config-backend`: ... HAProxy backend section.
* `config-global`: ... end of the HAProxy global section.
* `config-defaults`: ... end of the HAProxy defaults section.
* `config-frontend`: ... HAProxy frontend sections.

---

## Connection

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `max-connections` | `Global`  | `2000`  |       |
| `maxconn-server`  | `Backend` |         |       |
| `maxqueue-server` | `Backend` |         |       |

Configuration of connection limits.

* `max-connections`: Define the maximum concurrent connections on all proxies. Defaults to `2000` connections, which is also the HAProxy default configuration.
* `maxconn-server`: Defines the maximum concurrent connections each server of a backend should receive. If not specified or a value lesser than or equal zero is used, an unlimited number of connections will be allowed. When the limit is reached, new connections will wait on a queue.
* `maxqueue-server`: Defines the maximum number of connections should wait in the queue of a server. When this number is reached, new requests will be redispached to another server, breaking sticky session if configured. The queue will be unlimited if the annotation is not specified or a value lesser than or equal to zero is used.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.2-maxconn (`max-connections`)
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-maxconn (`maxconn-server`)
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-maxqueue (`maxqueue-server`)

---

## CORS

| Configuration key        | Scope     | Default      | Since |
|--------------------------|-----------|--------------|-------|
| `cors-allow-credentials` | `Backend` | `true`       |       |
| `cors-allow-headers`     | `Backend` | *see below*  |       |
| `cors-allow-methods`     | `Backend` | *see below*  |       |
| `cors-allow-origin`      | `Backend` | `*`          |       |
| `cors-enable`            | `Backend` | `false`      |       |
| `cors-expose-headers`    | `Backend` |              | v0.8  |
| `cors-max-age`           | `Backend` | `86400`      |       |

Add CORS headers on OPTIONS http command (preflight) and reponses.

* `cors-enable`: Enable CORS if defined as `true`.
* `cors-allow-origin`: Optional, configures `Access-Control-Allow-Origin` header which defines the URL that may access the resource. Defaults to `*`.
* `cors-allow-methods`: Optional, configures `Access-Control-Allow-Methods` header which defines the allowed methods. Default value is `GET, PUT, POST, DELETE, PATCH, OPTIONS`.
* `cors-allow-headers`: Optional, configures `Access-Control-Allow-Headers` header which defines the allowed headers. Default value is `DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization`.
* `cors-allow-credentials`: Optional, configures `Access-Control-Allow-Credentials` header which defines whether or not credentials (cookies, authorization headers or client certificates) should be exposed. Defaults to `true`.
* `cors-max-age`: Optional, configures `Access-Control-Max-Age` header which defines the time in seconds the result should be cached. Defaults to `86400` (1 day).
* `cors-expose-headers`: Optional, configures `Access-Control-Expose-Headers` header which defines what headers are allowed to be passed through to the CORS application. Defaults to not add the header.

See also:

* https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

---

## CPU map

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `cpu-map`         | `Global` |         |       |
| `use-cpu-map`     | `Global` | `true`  |       |

Define how processes/threads map to CPUs. The default value is generated based
on [nbthread](#nbthread) and [nbproc](#nbproc).

* `cpu-map`: Custom override specifying the cpu mapping behaviour in the format described [here](https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-cpu-map).
* `use-cpu-map`: Set to `false` to prevent any cpu mapping

See also:

* [nbthread](#nbthread) configuration key
* [nbproc](#nbproc) configuration key
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-cpu-map

---

## DNS resolvers

| Configuration key           | Scope     | Default         | Since |
|-----------------------------|-----------|-----------------|-------|
| `dns-accepted-payload-size` | `Global`  |                 |       |
| `dns-cluster-domain`        | `Global`  | `cluster.local` |       |
| `dns-hold-obsolete`         | `Global`  | `0s`            |       |
| `dns-hold-valid`            | `Global`  | `1s`            |       |
| `dns-resolvers`             | `Global`  |                 |       |
| `dns-timeout-retry`         | `Global`  | `1s`            |       |
| `use-resolver`              | `Backend` |                 |       |

Configure dynamic backend server update using DNS service discovery.

The following keys are supported:

* `dns-resolvers`: Multiline list of DNS resolvers in `resolvername=ip:port` format
* `dns-accepted-payload-size`: Maximum payload size announced to the name servers
* `dns-timeout-retry`: Time between two consecutive queries when no valid response was received, defaults to `1s`
* `dns-hold-valid`: Time a resolution is considered valid. Keep in sync with DNS cache timeout. Defaults to `1s`
* `dns-hold-obsolete`: Time to keep valid a missing IP from a new DNS query, defaults to `0s`
* `dns-cluster-domain`: K8s cluster domain, defaults to `cluster.local`
* `use-resolver`: Name of the resolver that the backend should use

{{% alert title="Important advices" %}}
* Use resolver with **headless** services, see [k8s doc](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services), otherwise HAProxy will reference the service IP instead of the endpoints.
* Beware of DNS cache, eg kube-dns has `--max-ttl` and `--max-cache-ttl` to change its default cache of `30s`.
{{% /alert %}}

See also:

* [example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/dns-service-discovery) page.
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.3.2
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-resolvers
* https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
* https://kubernetes.io/docs/concepts/services-networking/service/#headless-services

---

## Drain support

| Configuration key          | Scope     | Default | Since |
|----------------------------|-----------|---------|-------|
| `drain-support`            | `Global`  | `false` |       |
| `drain-support-redispatch` | `Global`  | `true`  | v0.8  |

Set `drain-support` to true if you wish to use HAProxy's drain support for pods that are NotReady
(e.g., failing a k8s readiness check) or are in the process of terminating. This option only makes
sense with cookie affinity configured as it allows persistent traffic to be directed to pods that
are in a not ready or terminating state.

By default, sessions will be redispatched on a failed upstream connection once the target pod is terminated.
You can control this behavior by setting `drain-support-redispatch` flag to `false` to instead return a 503 failure.

See also:

* [disable-pod-list]({{% relref "command-line/#disable-pod-list" %}}) command-line option doc.

---

## Dynamic scaling

| Configuration key                   | Scope     | Default | Since |
|-------------------------------------|-----------|---------|-------|
| `backend-server-slots-increment`    | `Backend` | `1`     |       |
| `dynamic-scaling`                   | `Global`  | `true`  |       |
| `slots-min-free`                    | `Backend` | `6`     | v0.8  |

The `dynamic-scaling` option defines if backend updates should always be made starting
a new HAProxy instance that will read the new config file (`false`), or updating the
running HAProxy via a Unix socket (`true`) whenever possible. Despite the configuration,
the config files will stay in sync with in memory config. The default value was `false`
up to v0.7 if not declared, changed to `true` since v0.8.

`dynamic-scaling` is ignored if the backend uses [DNS resolver](#dns-resolvers).

If `true` HAProxy Ingress will create at least `backend-server-slots-increment`
servers on each backend and update them via a Unix socket without reloading HAProxy.
Unused servers will stay in a disabled state. If the change cannot be made via socket,
a new HAProxy instance will be started.

Starting on v0.8, a new ConfigMap option `slots-min-free` can be used to configure the
minimum number of free/empty servers per backend. If HAProxy need to be restarted and
an backend has less than `slots-min-free` available servers, another
`backend-server-slots-increment` new empty servers would be created.

Starting on v0.6, `dynamic-scaling` config will only force a reloading of HAProxy if
the number of servers on a backend need to be increased. Before v0.6 a reload will
also happen when the number of servers could be reduced.

The following keys are supported:

* `dynamic-scaling`: Define if dynamic scaling should be used whenever possible
* `backend-server-slots-increment`: Configures the minimum number of servers, the size of the increment when growing and the size of the decrement when shrinking of each HAProxy backend
* `slots-min-free`: Configures the minimum number of empty servers a backend should have on every HAProxy restarts

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/management.html#9.3

---

## Forwardfor

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `forwardfor`      | `Global`  | `add`   |       |

Define how the `X-Forwarded-For` header should be handled by haproxy.

Options:

* `add`: haproxy should generate a `X-Forwarded-For` header with the source IP
address. This is the default option and should be used on untrusted networks.
If the request has a `XFF` header, its value is copied to
`X-Original-Forwarded-For`.
* `update`: Only on `v0.9` and above. haproxy should preserve any `X-Forwarded-For`
header, if provided, updating with the source IP address, which should be a
fronting TCP or HTTP proxy/load balancer.
* `ignore`: do nothing - only send the `X-Forwarded-For` header if the client
provided one, without updating its content.
* `ifmissing`: add `X-Forwarded-For` header only if the incoming request
doesn't provide one.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-option%20forwardfor
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For

---

## Fronting proxy port

| Configuration key     | Scope    | Default | Since   |
|-----------------------|----------|---------|---------|
| `fronting-proxy-port` | `Global` |         | `v0.8`  |
| `https-to-http-port`  | `Global` |         |         |
| `use-forwarded-proto` | `Global` | `true`  | `v0.10` |

A port number to listen to http requests from a fronting proxy that does the ssl
offload, eg haproxy ingress behind a cloud load balancers that manages the TLS
certificates. `https-to-http-port` is an alias to `fronting-proxy-port`.

`fronting-proxy-port` and [`http-port`](#bind-port) can share the same port number, see below
what changes in the behaviour.

`use-forwarded-proto` defines if haproxy should use `X-Forwarded-Proto` header to decide
how to handle requests made to `fronting-proxy-port` port number.

If `use-forwarded-proto` is `false`, the request takes the `https` route and is handled as if
`X-Forwarded-Proto` header is `https`, see below. The actual header content is ignored by
haproxy and forwarded to the backend if provided.

If `use-forwarded-proto` is `true`, the default value, requests made to `fronting-proxy-port`
port number evaluate the `X-Forwarded-Proto` header to decide how to handle the request:

* If `X-Forwarded-Proto` header is `https`:
  * HAProxy will handle the request just like the ssl-offload was made by HAProxy itself - HSTS header is provided if configured and
`X-SSL-*` headers won't be changed or removed if provided.
* If `X-Forwarded-Proto` header is `http` or any other value except `https`:
  * HAProxy will redirect scheme to https
* If `X-Forwarded-Proto` header is missing:
  * If `fronting-proxy-port` has its own port --- HAProxy will redirect scheme to https
  * If `fronting-proxy-port` shares the HTTP port --- the request will be handled as plain http, being redirected to https only if `ssl-redirect` is `true`, just like if `fronting-proxy-port` wasn't configured.

{{% alert title="Warning on v0.7 and older" color="warning" %}}
On v0.7 and older and only if the `X-Forwarded-Proto` is missing: the
connecting port number was used to define which socket received the request, so
the fronting proxy should connect to the same port number defined in
`https-to-http-port`, eg cannot have any proxy like Kubernetes' `NodePort`
between the load balancer and HAProxy which changes the connecting port number.
This limitation doesn't exist on v0.8 or above.
{{% /alert %}}

See also:

* [Bind](#bind)
* [Bind port](#bind-port)

## Headers

| Configuration key | Scope     | Default | Since  |
|-------------------|-----------|---------|--------|
| `headers`         | `Backend` |         | v0.11  |

Configures a list of HTTP header names and the value it should be configured with. More than one header can be configured using a multi-line configuration value. The name of the header and its value should be separated with a colon and/or any amount of spaces.

The following variables can be used in the value:

* `%[namespace]`: namespace of the ingress or service
* `%[service]`: name of the service which received the request

Configuration example:

```yaml
    annotations:
      ingress.kubernetes.io/headers: |
        x-path: /
        host: %[service].%[namespace].svc.cluster.local
```

---

## Health check

| Configuration key         | Scope     | Default | Since |
|---------------------------|-----------|---------|-------|
| `health-check-addr`       | `Backend` |         | v0.8  |
| `health-check-fall-count` | `Backend` |         | v0.8  |
| `health-check-interval`   | `Backend` |         | v0.8  |
| `health-check-port`       | `Backend` |         | v0.8  |
| `health-check-rise-count` | `Backend` |         | v0.8  |
| `health-check-uri`        | `Backend` |         | v0.8  |

Controls server health checks on a per-backend basis.

* `health-check-uri`: If specified, this changes the default TCP health into an HTTP health check.
* `health-check-addr`: Defines the address for health checks. If omitted, the server addr will be used.
* `health-check-port`: Defines the port for health checks. If omitted, the server port will be used.
* `health-check-interval`: Defines the interval between health checks. The default value `2s` is used if omitted.
* `health-check-rise-count`: The number of successful health checks that must occur before a server is marked operational. If omitted, the default value is 2.
* `health-check-fall-count`: The number of failed health checks that must occur before a server is marked as dead. If omitted, the default value is 3.
* `backend-check-interval`: Deprecated, use `health-check-interval` instead.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4.2-option%20httpchk
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-addr
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-port
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-inter
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-rise
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-fall

---

## HSTS

| Configuration key         | Scope     | Default    | Since |
|---------------------------|-----------|------------|-------|
| `hsts`                    | `Backend` | `true`     |       |
| `hsts-include-subdomains` | `Backend` | `false`    |       |
| `hsts-max-age`            | `Backend` | `15768000` |       |
| `hsts-preload`            | `Backend` | `false`    |       |

Configure HSTS - HTTP Strict Transport Security. The following keys are supported:

* `hsts`: `true` if HSTS response header should be added
* `hsts-include-subdomains`: `true` if it should apply to subdomains as well
* `hsts-max-age`: time in seconds the browser should remember this configuration
* `hsts-preload`: `true` if the browser should include the domain to [HSTS preload list](https://hstspreload.org/)

See also:

* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

---

## Initial weight

| Configuration key | Scope     | Default | Since  |
|-------------------|-----------|---------|--------|
| `initial-weight`  | `Backend` | `1`     | `v0.8` |

Configures the weight value of each backend server - either the enabled and also the
disabled servers. The default value is `1`. Changing this value has no effect on the
proportional value between each server of a single backend, thus this doesn't change
the balance between the servers.

Change the default value to a higher number, eg `100`, if using with
[`agent-check`](#agent-check) and the agent is used to change the weight of the server.

Blue/green on `deploy` mode also uses `initial-weight` as its minimum weight value,
provided that the maximum is lesser than or equal `256`.

See also:

* [`agent-check`](#agent-check)
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-weight

---

## Limit

| Configuration key   | Scope     | Default | Since |
|---------------------|-----------|---------|-------|
| `limit-connections` | `Backend` |         |       |
| `limit-rps`         | `Backend` |         |       |
| `limit-whitelist`   | `Backend` |         |       |

Configure rate limit and concurrent connections per client IP address in order to mitigate DDoS attack.
If several users are hidden behind the same IP (NAT or proxy), this configuration may have a negative
impact for them. Whitelist can be used to these IPs.

The following annotations are supported:

* `limit-connections`: Maximum number os concurrent connections per client IP
* `limit-rps`: Maximum number of connections per second of the same IP
* `limit-whitelist`: Comma separated list of CIDRs that should be removed from the rate limit and concurrent connections check

---

## Load server state

| Configuration key   | Scope    | Default | Since |
|---------------------|----------|---------|-------|
| `load-server-state` | `Global` | `false` |       |

Define if HAProxy should save and reload it's current state between server reloads, like
uptime of backends, qty of requests and so on.

This is an experimental feature and has currently some issues if using with `dynamic-scaling`:
an old state with disabled servers will disable them in the new configuration.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-server-state-file
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-load-server-state-from-file

---

## Log format

| Configuration key  | Scope    | Default | Since |
|--------------------|----------|---------|-------|
| `http-log-format`  | `Global` |         |       |
| `https-log-format` | `Global` |         |       |
| `tcp-log-format`   | `Global` |         |       |

Customize the tcp, http or https log format using log format variables. Only used if
[syslog-endpoint](#syslog-endpoint) is also configured.

* `http-log-format`: log format of all HTTP proxies, defaults to HAProxy default HTTP log format.
* `https-log-format`: log format of TCP proxy used to inspect SNI extention. Use `default` to configure default TCP log format, defaults to not log.
* `tcp-log-format`: log format of TCP proxies, defaults to HAProxy default TCP log format. See also [TCP services configmap](#tcp-services-configmap) command-line option.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#8.2.4

---

## Modsecurity

| Configuration key                | Scope    | Default | Since |
|----------------------------------|----------|---------|-------|
| `modsecurity-endpoints`          | `Global` |         |       |
| `modsecurity-timeout-connect`    | `Global` | `5s`    | v0.10 |
| `modsecurity-timeout-hello`      | `Global` | `100ms` |       |
| `modsecurity-timeout-idle`       | `Global` | `30s`   |       |
| `modsecurity-timeout-processing` | `Global` | `1s`    |       |
| `modsecurity-timeout-server`     | `Global` | `5s`    | v0.10 |

Configure modsecurity agent. These options only have effect if `modsecurity-endpoints`
is configured.

Configure `modsecurity-endpoints` with a comma-separated list of `IP:port` of HAProxy
agents (SPOA) for ModSecurity. The default configuration expects the
`contrib/modsecurity` implementation from HAProxy source code.

Up to v0.7 all http requests will be parsed by the ModSecurity agent, even if the
ingress resource wasn't configured to deny requests based on ModSecurity response.
Since v0.8 the spoe filter is configured on a per-backend basis.

The following keys are supported:

* `modsecurity-endpoints`: Comma separated list of ModSecurity agent endpoints.
* `modsecurity-timeout-connect`: Defines the maximum time to wait for the connection to the agent be established. Configures the haproxy's timeout connect. Defaults to `5s` if not configured.
* `modsecurity-timeout-hello`: Defines the maximum time to wait for the AGENT-HELLO frame from the agent. Default value is `100ms`.
* `modsecurity-timeout-idle`: Defines the maximum time to wait before close an idle connection. Default value is `30s`.
* `modsecurity-timeout-processing`: Defines the maximum time to wait for the whole ModSecurity processing. Default value is `1s`.
* `modsecurity-timeout-server`: Defines the maximum time to wait for an agent response. Configures the haproxy's timeout server. Defaults to `5s` if not configured.

See also:

* [example]({{% relref "../examples/modsecurity" %}}) page.
* [`waf`](#waf) configuration key.
* https://www.haproxy.org/download/2.0/doc/SPOE.txt
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#9.3
* https://github.com/jcmoraisjr/modsecurity-spoa

---

## Nbproc

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `nbproc-ssl`      | `Global` | `0`     |       |

{{% alert title="Warning" color="warning" %}}
This option works only on v0.7 or below. Since v0.8 the only supported value is `0` zero.
{{% /alert %}}

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

See also:

* [nbthread](#nbthread) configuration key
* [cpu-map](#cpu-map) configuration key
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-nbproc
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-bind-process
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-cpu-map

---

## Nbthread

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `nbthread`        | `Global` | `2`     |       |

Define the number of threads a single HAProxy process should use to all its
processing. If using with [nbproc](#nbproc), every single HAProxy process will
share this same configuration.

If using two or more threads on a single HAProxy process, `cpu-map` is used to
bind each thread on its own CPU core.

See also:

* [cpu-map](#cpu-map) configuration key
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-nbthread
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-cpu-map

---

## OAuth

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `oauth`           | `Backend` |         |       |
| `oauth-headers`   | `Backend` |         |       |
| `oauth-uri-prefix`| `Backend` |         |       |

Configure OAuth2 via Bitly's `oauth2_proxy`.

* `oauth`: Defines the oauth implementation. The only supported option is `oauth2_proxy`.
* `oauth-uri-prefix`: Defines the URI prefix of the oauth service. The default value is `/oauth2`. There should be a backend with this path in the ingress resource.
* `oauth-headers`: Defines an optional comma-separated list of `<header>:<haproxy-var>` used to configure request headers to the upstream backends. The default value is `X-Auth-Request-Email:auth_response_email` which means configuring a header `X-Auth-Request-Email` with the value of the var `auth_response_email`. New variables can be added overwriting the default `auth-request.lua` script.

The `oauth2_proxy` implementation expects Bitly's [oauth2_proxy](https://github.com/bitly/oauth2_proxy)
running as a backend of the same domain that should be protected. `oauth2_proxy` has support
to GitHub, Google, Facebook, OIDC and many others.

Note to v0.7 or below: All paths of a domain will have the same oauth configurations, despite if the path is configured
on an ingress resource without oauth annotations. In other words, if two ingress resources share
the same domain but only one has oauth annotations - the one that has at least the `oauth2_proxy`
service - all paths from that domain will be protected.

See also:

* [example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/auth/oauth) page.

---

## Path type

| Configuration key | Scope    | Default                    | Since |
|-------------------|----------|----------------------------|-------|
| `path-type`       | `Host`   | `begin`                    | v0.11 |
| `path-type-order` | `Global` | `exact,prefix,begin,regex` | v0.12 |

Defines how the path of an incoming request should match a declared path in the ingress object.

* `path-type`: Configures the path type. Case insensitive, so `Begin` and `begin` configures the same path type option. The ingress spec has priority, this option will only be used if the `pathType` attribute from the ingress spec is declared as `ImplementationSpecific` or is not declared.
* `path-type-order`: Defines a comma-separated list of priority path types. First types has higher precedence, which means that if two distinct paths of two distinct types overlaps, the first in the list will be used to handle the request. All path types must be provided. Case insensitive, use all path types in lowercase.

{{% alert title="Warning" color="warning" %}}
Wildcard hostnames and alias-regex match incoming requests using the regex path type, even if the path itself has a distinct one. Changing the precedence order of paths also changes the precedence order of hostnames. See also [server-alias-regex](#server-alias) and [strict host](#strict-host).
{{% /alert %}}

Supported `path-type` values:

* `begin`: Case insensitive, matches the beginning of the path from the incoming request. This is the default value if not declared.
* `exact`: Case sensitive, matches the whole path. Implements the `Exact` path type from the ingress spec.
* `prefix`: Case sensitive, matches a whole subdirectory from the incoming path. A declared `/app` path matches `/app` and `/app/1` but does not match `/app1`. Implements the `Prefix` path type from the ingress spec.
* `regex`: Case sensitive, matches the incoming path using POSIX extended regular expression. The regular expression has an implicit start `^` and no ending `$` boundary, so a declared `/app[0-9]+/?` will match paths starting with this pattern. Add a trailing `$` if an exact match is desired.

Request and match examples:

| Path type | Request        | Match                               | Do not match                        |
|-----------|----------------|-------------------------------------|-------------------------------------|
| `begin`   | `/app`         | `/App` <br/> `/app` <br/> `/app/1` <br/> `/app1` | `/ap`                  |
| `exact`   | `/app`         | `/app`                              | `/App` <br/> `/app/` <br/> `/app1`  |
| `prefix`  | `/app`         | `/app` <br/> `/app/` <br/> `/app/1` | `/App` <br/> `/app1`                |
| `regex`   | `/app[0-9]+`   | `/app1` <br/> `/app15/sub` <br/> `/app25xx/sub` | `/App1` <br/> `/app/15` |
| `regex`   | `/app[0-9]+$`  | `/app1` <br/> `/app15`              | `/App1` <br/> `/app15/`             |
| `regex`   | `/app[0-9]+/?` | `/app1` <br/> `/app15/` <br/> `/app25/sub` | `/App15` <br/> `/app/25sub`  |

---

## Proxy body size

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `proxy-body-size` | `Backend` |         |       |

Define the maximum number of bytes HAProxy will allow on the body of requests. Default is
to not check, which means requests of unlimited size. This limit can be changed per ingress
resource.

Since 0.4 a suffix can be added to the size, so `10m` means
`10 * 1024 * 1024` bytes. Supported suffix are: `k`, `m` and `g`.

Since 0.7 `unlimited` can also be used to overwrite any global body size limit.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#7.3.6-req.body_size

---

## Proxy protocol

| Configuration key    | Scope     | Default | Since |
|----------------------|-----------|---------|-------|
| `proxy-protocol`     | `Backend` | `no`    |       |
| `use-proxy-protocol` | `Global`  | `false` |       |

Configures PROXY protocol in frontends and backends.

* `proxy-protocol`: Define if the upstream backends support proxy protocol and what version of the protocol should be used. Supported values are `v1`, `v2`, `v2-ssl`, `v2-ssl-cn` or `no`. The default behavior if not declared is that the protocol is not supported by the backends and should not be used.
* `use-proxy-protocol`: Define if HAProxy is behind another proxy that use the PROXY protocol. If `true`, ports `80` and `443` will expect the PROXY protocol. The stats endpoint (defaults to port `1936`) has it's own [`stats-proxy-protocol`](#stats) configuration key.

See also:

* https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.1-accept-proxy
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-send-proxy
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-send-proxy-v2
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-send-proxy-v2-ssl
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-send-proxy-v2-ssl-cn

---

## Rewrite target

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `rewrite-target`  | `Backend` |         |       |

Configures how URI of the requests should be rewritten before send the request to the backend.
The following table shows some examples:

| Ingress path | Request path | Rewrite target | Output  |
|--------------|--------------|----------------|---------|
| /abc         | /abc         | /              | /       |
| /abc         | /abc/        | /              | /       |
| /abc         | /abc/x       | /              | /x      |
| /abc         | /abc         | /y             | /y      |
| /abc         | /abc/        | /y             | /y/     |
| /abc         | /abc/x       | /y             | /y/x    |
| /abc/        | /abc         | /              | **404** |
| /abc/        | /abc/        | /              | /       |
| /abc/        | /abc/x       | /              | /x      |

---

## Secure backend

| Configuration key         | Scope     | Default | Since |
|---------------------------|-----------|---------|-------|
| `secure-backends`         | `Backend` |         |       |
| `secure-crt-secret`       | `Backend` |         |       |
| `secure-verify-ca-secret` | `Backend` |         |       |

Configure secure (TLS) connection to the backends.

* `secure-backends`: Define as true if the backend provide a TLS connection.
* `secure-crt-secret`: Optional secret name of client certificate and key. This cert/key pair must be provided if the backend requests a client certificate. Expected secret keys are `tls.crt` and `tls.key`, the same used if secret is built with `kubectl create secret tls <name>`.
* `secure-verify-ca-secret`: Optional secret name with certificate authority bundle used to validate server certificate, preventing man-in-the-middle attacks. Expected secret key is `ca.crt`. Since v0.9, an optional `ca.crl` key can also provide a CRL in PEM format for the server to verify against.

See also:

* [Backend protocol](#backend-protocol) configuration key.

---

## Security

| Configuration key  | Scope    | Default | Since |
|--------------------|----------|---------|-------|
| `use-chroot`       | `Global` | `false` | v0.9  |
| `use-haproxy-user` | `Global` | `false` | v0.9  |

Change security options.

* `use-chroot`: If `true`, configures haproxy to perform a `chroot()` in the empty and non-writable directory `/var/empty` during the startup process, just before it drops its own privileges. Only root can perform a `chroot()`, so HAProxy Ingress container should start as UID `0` if this option is configured as `true`. See the note below about `use-chroot` option limitations.
* `use-haproxy-user`: Defines if the haproxy's process should be changed to `haproxy`, UID `1001`. The default value `false` leaves haproxy running as root. Note that even running as root, haproxy always drops its own privileges before start its event loop.

In the default configuration, HAProxy Ingress container starts as root. Since v0.9 it's also possible to configure the container to start as `haproxy` user, UID `1001`. Read the [Security considerations](http://cbonte.github.io/haproxy-dconv/1.9/management.html#13) from HAProxy doc before change the starting user. The starting user can be changed in the deployment or daemonset's pod template using the following configuration:

```yaml
...
  template:
    spec:
      securityContext:
        runAsUser: 1001
```

Note that ports below 1024 cannot be bound if the container starts as non-root.

{{% alert title="Note" %}}
HAProxy does not have access to the file system after configure a `chroot()`. Unix sockets located outside the chroot directory are used in the following conditions:

* At least one `ssl-passthrough` is used, or `timeout-client` is used as an Ingress annotation (`timeout-client` as a configmap option is fine). Both configurations create a fronting TCP proxy inside haproxy, which uses an unix socket to communicate with the HTTP frontend.
* Internal ACME signer is used. HAProxy Ingress creates an internal server to answer the ACME challenge, and haproxy forwards the challenge requests to this server using an unix socket.

So only enable `use-chroot` if not using these features.
{{% /alert %}}

See also:

* http://cbonte.github.io/haproxy-dconv/1.9/management.html#13
* http://cbonte.github.io/haproxy-dconv/1.9/configuration.html#3.1-chroot
* http://cbonte.github.io/haproxy-dconv/1.9/configuration.html#3.1-uid
* http://cbonte.github.io/haproxy-dconv/1.9/configuration.html#3.1-gid
* http://cbonte.github.io/haproxy-dconv/1.9/configuration.html#3.1-unix-bind

---

## Server alias

| Configuration key    | Scope  | Default | Since |
|----------------------|--------|---------|-------|
| `server-alias`       | `Host` |         |       |
| `server-alias-regex` | `Host` |         |       |

Configure hostname alias. All annotations will be combined together with the host
attribute in the same ACL, and any of them might be used to match SNI extensions
(TLS) or Host HTTP header. The matching is case insensitive.

* `server-alias`: Defines an alias with hostname-like syntax. On v0.6 and older, wildcard `*` wasn't converted to match a subdomain. Regular expression was also accepted but dots were escaped, making this alias less useful as a regex. Starting v0.7 the same hostname syntax is used, so `*.my.domain` will match `app.my.domain` but won't match `sub.app.my.domain`.
* `server-alias-regex`: Only in v0.7 and newer. Match hostname using a POSIX extended regular expression. The regex will be used verbatim, so add `^` and `$` if strict hostname is desired and escape `\.` dots in order to strictly match them. Some HTTP clients add the port number in the Host header, so remember to add `(:[0-9]+)?$` in the end of the regex if a dollar sign `$` is being used to match the end of the string.

---

## Service upstream

| Configuration key  | Scope     | Default | Since |
|--------------------|-----------|---------|-------|
| `service-upstream` | `Backend` | `false` |       |

Defines if the HAProxy backend/server endpoints should be configured with the
service VIP/IPVS. If `false`, the default value, the endpoints will be used and
HAProxy will load balance the requests between them. If defined as `true` the
service's ClusterIP is used instead.

---

## SSL ciphers

| Configuration key           | Scope     | Default | Since |
|-----------------------------|-----------|---------|-------|
| `ssl-cipher-suites`         | `Host`    |         | v0.9  |
| `ssl-cipher-suites-backend` | `Backend` |         | v0.9  |
| `ssl-ciphers`               | `Host`    |         |       |
| `ssl-ciphers-backend`       | `Backend` |         | v0.9  |

Set the list of cipher algorithms used during the SSL/TLS handshake.

* `ssl-cipher-suites`: Cipher suites on TLS v1.3 handshake of incoming requests. HAProxy being the TLS server.
* `ssl-cipher-suites-backend`: Cipher suites on TLS v1.3 handshake to backend/servers. HAProxy being the TLS client.
* `ssl-ciphers`: Cipher suites on TLS up to v1.2 handshake of incoming requests. HAProxy being the TLS server.
* `ssl-ciphers-backend`: Cipher suites on TLS up to v1.2 handshake to backend/servers. HAProxy being the TLS client.

Default values on HAProxy Ingress up to v0.8:

* TLS up to v1.2: `ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK`

Default values on HAProxy Ingress v0.9 and newer:

* TLS up to v1.2: `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384`
* TLS v1.3: `TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`

`ssl-ciphers` and `ssl-cipher-suites` were `Global` scope up to v0.10.

See also:

* https://ssl-config.mozilla.org/#server=haproxy
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-ssl-default-bind-ciphers
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-ssl-default-bind-ciphersuites
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-ciphers
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.2-ciphersuites

---

## SSL DH

| Configuration key         | Scope    | Default | Since |
|---------------------------|----------|---------|-------|
| `ssl-dh-default-max-size` | `Global` | `1024`  |       |
| `ssl-dh-param`            | `Global` |         |       |

Configures Diffie-Hellman key exchange parameters.

* `ssl-dh-param`: Configure the secret name which defines the DH parameters file used on ephemeral Diffie-Hellman key exchange during the SSL/TLS handshake.
* `ssl-dh-default-max-size`: Define the maximum size of a temporary DH parameters used for key exchange. Only used if `ssl-dh-param` isn't provided.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#tune.ssl.default-dh-param
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-ssl-dh-param-file

---

## SSL engine

| Configuration key  | Scope    | Default | Since |
|--------------------|----------|---------|-------|
| `ssl-engine`       | `Global` |         | v0.8  |
| `ssl-mode-async`   | `Global` | `false` | v0.8  |

Set the name of the OpenSSL engine to use. The string shall include the engine name
and its parameters.

Additionally, `ssl-mode-async` can be set to enable asynchronous TLS I/O operations if
the ssl-engine used supports it.

Reference:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#ssl-engine
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#ssl-mode-async

---

## SSL options

| Configuration key     | Scope     | Default | Since |
|-----------------------|-----------|---------|-------|
| `ssl-options`         | `Global`  |         |       |
| `ssl-options-backend` | `Backend` |         | v0.9  |
| `ssl-options-host`    | `Host`    |         | v0.11 |

Define a space-separated list of options on SSL/TLS connections.

* `ssl-options`: Default options for all the TLS frontend connections - HAProxy being the server
* `ssl-options-backend`: Options for backend server connections - HAProxy being the client
* `ssl-options-host`: Options for TLS frontend connections - HAProxy being the server. This acts as a host scoped override to options defined in `ssl-options` and supports everything that HAProxy supports in the `crt-list`.

Default values for `ssl-options` and `ssl-options-backend`:

* v0.9 and newer: `no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets`
* up to v0.8: `no-sslv3 no-tls-tickets`

Supported options for `ssl-options` and `ssl-options-backend`:

* `force-sslv3`: Enforces use of SSLv3 only
* `force-tlsv10`: Enforces use of TLSv1.0 only
* `force-tlsv11`: Enforces use of TLSv1.1 only
* `force-tlsv12`: Enforces use of TLSv1.2 only
* `no-sslv3`: Disables support for SSLv3
* `no-tls-tickets`: Enforces the use of stateful session resumption
* `no-tlsv10`: Disables support for TLSv1.0
* `no-tlsv11`: Disables support for TLSv1.1
* `no-tlsv12`: Disables support for TLSv1.2

New supported options since v0.9 for `ssl-options` and `ssl-options-backend`:

* `force-tlsv13`: Enforces use of TLSv1.3 only
* `no-tlsv13`: Disables support for TLSv1.3
* `ssl-max-ver <SSLv3|TLSv1.0|TLSv1.1|TLSv1.2|TLSv1.3>`: Enforces the use of a SSL/TLS version or lower
* `ssl-min-ver <SSLv3|TLSv1.0|TLSv1.1|TLSv1.2|TLSv1.3>`: Enforces the use of a SSL/TLS version or upper

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.1-crt-list

---

## SSL passthrough

| Configuration key           | Scope    | Default | Since |
|-----------------------------|----------|---------|-------|
| `ssl-passthrough`           | `Host`   |         |       |
| `ssl-passthrough-http-port` | `Host`   |         |       |

Defines if HAProxy should work in TCP proxy mode and leave the SSL offload to the backend.
SSL passthrough is a per domain configuration, which means that other domains can be
configured to SSL offload on HAProxy.

If using SSL passthrough, only root `/` path is supported.

* `ssl-passthrough`: Enable SSL passthrough if defined as `true`. The backend is then expected to SSL offload the incoming traffic. The default value is `false`, which means HAProxy should do the SSL handshake.
* `ssl-passthrough-http-port`: Since v0.7. Optional HTTP port number of the backend. If defined, connections to the HAProxy HTTP port, default `80`, is sent to that port which expects to speak plain HTTP. If not defined, connections to the HTTP port will redirect connections to the HTTPS one.

---

## SSL redirect

| Configuration key           | Scope     | Default                       | Since |
|-----------------------------|-----------|-------------------------------|-------|
| `no-tls-redirect-locations` | `Global`  | `/.well-known/acme-challenge` |       |
| `ssl-redirect`              | `Backend` | `true`                        |       |
| `ssl-redirect-code`         | `Global`  | `302`                         | v0.10 |

Configures if an encripted connection should be used.

* `ssl-redirect`: Defines if HAProxy should send a `302 redirect` response to requests made on unencripted connections. Note that this configuration will only make effect if TLS is [configured](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/tls-termination).
* `ssl-redirect-code`: Defines the HTTP status code used in the redirect. The default value is `302` if not declared. Supported values are `301`, `302`, `303`, `307` and `308`.
* `no-tls-redirect-locations`: Defines a comma-separated list of URLs that should be removed from the TLS redirect. Requests to `:80` http port and starting with one of the URLs from the list will not be redirected to https despite of the TLS redirect configuration. This option defaults to `/.well-known/acme-challenge`, used by ACME protocol.

See also:

* http://cbonte.github.io/haproxy-dconv/2.0/configuration.html#redirect

---

## Stats

| Configuration key           | Scope     | Default | Since |
|-----------------------------|-----------|---------|-------|
| `stats-auth`                | `Global`  |         |       |
| `stats-port`                | `Global`  | `1936`  |       |
| `stats-proxy-protocol`      | `Global`  | `false` |       |
| `stats-ssl-cert`            | `Global`  |         |       |

Configurations of the HAProxy statistics page:

* `stats-auth`: Enable basic authentication with clear-text password - `<user>:<passwd>`
* `stats-port`: Change the port HAProxy should listen to requests
* `stats-proxy-protocol`: Define if the stats endpoint should enforce the PROXY protocol
* `stats-ssl-cert`: Optional namespace/secret-name of `tls.crt` and `tls.key` pair used to enable SSL on stats page. Plain http will be used if not provided, the secret wasn't found or the secret doesn't have a crt/key pair.

---

## Strict host

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `strict-host`     | `Global`  | `false` |       |

Defines whether the path of another matching host/FQDN should be used to try
to serve a request. The default value is `false`, which means all matching
wildcard hosts will be visited in order to try to match the path. If `true`,
a strict configuration is applied and the `default-backend` should be used
if a path couldn't be matched.

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

* `svc2` if `strict-host` is `false`, the default value
* `default-backend` if `strict-host` is `true`

---

## Syslog

| Configuration key | Scope     | Default    | Since |
|-------------------|-----------|------------|-------|
| `syslog-endpoint` | `Global`  |            |       |
| `syslog-format`   | `Global`  | `rfc5424`  | v0.8  |
| `syslog-length`   | `Global`  | `1024`     | v0.9  | 
| `syslog-tag`      | `Global`  | `ingress`  | v0.8  |

Logging configurations.

* `syslog-endpoint`: Configures the UDP syslog endpoint where HAProxy should send access logs.
* `syslog-format`: Configures the log format to be either `rfc5424` (default) or `rfc3164`.
* `syslog-length`: The maximum line length, log lines larger than this value will be truncated. Defaults to `1024`.
* `syslog-tag`: Configure the tag field in the syslog header to the supplied string.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-log
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-log-tag

---

## Timeout

| Configuration key      | Scope     | Default | Since |
|------------------------|-----------|---------|-------|
| `timeout-client`       | `Global`  | `50s`   |       |
| `timeout-client-fin`   | `Global`  | `50s`   |       |
| `timeout-connect`      | `Backend` | `5s`    |       |
| `timeout-http-request` | `Backend` | `5s`    |       |
| `timeout-keep-alive`   | `Backend` | `1m`    |       |
| `timeout-queue`        | `Backend` | `5s`    |       |
| `timeout-server`       | `Backend` | `50s`   |       |
| `timeout-server-fin`   | `Backend` | `50s`   |       |
| `timeout-stop`         | `Global`  |         |       |
| `timeout-tunnel`       | `Backend` | `1h`    |       |

Define timeout configurations. The unit defaults to milliseconds if missing, change the unit with `s`, `m`, `h`, ... suffix.

{{% alert title="Note" %}}
Since `v0.11`, `timeout-client` and `timeout-client-fin` are global configuration keys and cannot be configured per hostname.
{{% /alert %}}

The following keys are supported:

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

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#3.1-hard-stop-after (`timeout-stop`)
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#2.4 (time suffix)

---

## TLS ALPN

| Configuration key | Scope    | Default       | Since |
|-------------------|----------|---------------|-------|
| `tls-alpn`        | `Host`   | `h2,http/1.1` | v0.8  |

Defines the TLS ALPN extension advertisement. The default value is `h2,http/1.1` which enables
HTTP/2 on the client side.

`tls-alpn` was `Global` scope up to v0.10.

See also:

* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#5.1-alpn

---

## Use HTX

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `use-htx`         | `Global` | `true`  | v0.9  |

Defines if the new HTX internal representation for HTTP elements should be used. The default value
is `true` since v0.10, it was `false` on v0.9. HTX should be used to enable HTTP/2 protocol to backends.

See also:

* [backend-protocol](#backend-protocol) configuration keys
* https://cbonte.github.io/haproxy-dconv/2.0/configuration.html#4-option%20http-use-htx

---

## Var namespace

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `var-namespace`   | `Host`   | `false` | v0.8  |

If `var-namespace` is configured as `true`, a HAProxy var `txn.namespace` is created with the
kubernetes namespace owner of the service which is the target of the request. This variable is
useful on http logs. The default value is `false`. Usage: `k8s-namespace: %[var(txn.namespace)]`.

See also:

* [http-log](#log-format) configuration key

---

## WAF

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `waf`             | `Backend` |         |       |
| `waf-mode`        | `Backend` | `deny`  | v0.9  |

Defines which web application firewall (WAF) implementation should be used
to validate requests. Currently the only supported value is `modsecurity`.

This configuration has no effect if the ModSecurity endpoints are not configured.

The `waf-mode` key defines wether the WAF should be `deny` or `detect` for that Backend. 
If the WAF is in `detect` mode the requests are passed to ModSecurity and logged, but not denied.

The default behavior here is `deny` if `waf` is set to `modsecurity`.

See also:

* [Modsecurity](#modsecurity) configuration keys.
