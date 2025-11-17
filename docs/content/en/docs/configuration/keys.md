---
title: "Configuration keys"
linkTitle: "Keys"
weight: 3
description: >
  List of all annotations and global ConfigMap options.
---

Configuration keys are entry point configurations that allow users and admins to
dynamically fine-tune HAProxy status. HAProxy Ingress reads configuration keys
from Kubernetes resources, and this can be done in a couple of ways:

* Globally, from a ConfigMap
* Per IngressClass, from a ConfigMap linked in the IngressClass' `parameters` field
* Per Ingress, configuring or annotating Ingress resources
* Per backend, annotating Service resources

The list above also describes the precedence if the same configuration key is used
in more than one resource: Global configurations can be overridden by IngressClass
configurations, that can be overridden by Ingress resource configurations and so on.
This hierarchy creates a flexible model, where commonly used configurations can be
made in a higher level and overridden by local changes.

The following sections describe in a few more details how HAProxy Ingress classifies
an Ingress to be part of the final configuration, and how it reads the configuration
from Kubernetes resources.

## Class matter

HAProxy Ingress by default does not listen to Ingress resources, until one or more of
the following conditions are met:

* Ingress resources have the annotation `kubernetes.io/ingress.class` with the value `haproxy`
* Ingress resources have its `ingressClassName` field assigning an IngressClass resource whose `controller` name is `haproxy-ingress.github.io/controller`
* HAProxy Ingress was started with `--watch-ingress-without-class` command-line option

See [Ingress Class]({{% relref "command-line/#ingress-class" %}}) command-line doc for
customization options.

The first two options give more control on which Ingress resources should be part of the
final configuration. Class annotation and the IngressClass name can be changed on a running
controller, the configuration will be adjusted on the fly to reflect the new status. If
both options are configured in an Ingress resource, and they conflict - i.e. one of them
says the controller belongs to HAProxy Ingress and the other says that it does not belong -
the annotation value wins and a warning is logged.

Adding a class annotation or defining an IngressClass name means "classify" an Ingress
resource. The third and latest option asks HAProxy Ingress to also add "unclassified"
Ingress to the final configuration - i.e. add Ingress resources that does not have the
`kubernetes.io/ingress.class` annotation and also does not have the `ingressClassName`
field. Note that this is a new behavior since v0.12. Up to v0.11 HAProxy Ingress listen
to "unclassified" Ingress by default.

## Strategies

HAProxy Ingress reads configuration on three distinct ways:

* `ConfigMap` key/value data. ConfigMaps are assigned either via `--configmap` command-line option (used by Global options), or via parameters field of an `IngressClass`
* Annotations from classified `Ingress` resources and also from `Services` that these Ingress are linking to
* Spec configurations from classified `Ingress` resources

HAProxy Ingress follows [Ingress v1 spec](https://v1-18.docs.kubernetes.io/docs/concepts/services-networking/ingress/),
so any Ingress spec configuration should work as stated by the Kubernetes documentation.

Annotations and ConfigMap customizations extend the Ingress spec via the configuration
keys, and this is what the rest of this documentation page is all about.

The following sections describe in a few more details about configuration strategies.

### ConfigMap

ConfigMap key/value options are read in the following conditions:

* Global config, using `--configmap` command-line option. The installation process configures a Global config ConfigMap named `haproxy-ingress` in the controller namespace. This is the only way to configure keys from the `Global` scope. See about scopes [later](#scope) in this page. Note, `--configmap` needs to be in the following format: `<namespace>/<configmap-name>`.
* IngressClass config, using its `parameters` field linked to a ConfigMap declared in the same namespace of the controller. See about IngressClass [later](#ingressclass) in this same section.

A configuration key is used verbatim as the ConfigMap key name, without any prefix.
The ConfigMap spec expects a string as the key value, so declare numbers and booleans
as strings, HAProxy Ingress will convert them when needed.

```yaml
apiVersion: v1
data:
  balance-algorithm: leastconn
  max-connections: "10000"
  ssl-redirect: "true"
kind: ConfigMap
metadata:
  name: haproxy-ingress
  namespace: ingress-controller
```

### Annotation

Annotations are read in the following conditions:

* From classified `Ingress` resources, see about classification in the [Class matter](#class-matter) section. `Ingresses` accept keys from the `Host`, `Backend`, `Path` and `TCP` scopes. See about scopes [later](#scope) in this page.
* From `Services` that classified Ingress resources are linking to. `Services` only accept keys from the `Backend` scope.

A configuration key needs a prefix in front of its name to use as an annotation key.
The default prefix is `haproxy-ingress.github.io`, and `ingress.kubernetes.io` is also
supported for backward compatibility. Change the prefix with the
[`--annotations-prefix`]({{% relref "command-line#annotations-prefix" %}})
command-line option. The annotation value spec expects a string as the key value, so
declare numbers and booleans as strings, HAProxy Ingress will convert them when needed.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    haproxy-ingress.github.io/balance-algorithm: roundrobin
    haproxy-ingress.github.io/maxconn-server: "500"
    haproxy-ingress.github.io/ssl-redirect: "false"
  name: app
  namespace: default
spec:
  ...
```

### IngressClass

IngressClass configurations are read when the `ingressClassName` field of an Ingress
resource links to an IngressClass that configures its `parameters` field.

The IngressClass' `parameters` field currently only accepts ConfigMap resources, and
the ConfigMap must be declared in the same namespace of the controller.

{{< alert title="Note" >}}
Even though a ConfigMap is used, configuration keys of the `Global` scope cannot be
used and will be ignored.
{{< /alert >}}

The following resources create the same final configuration of the Annotation
section [above](#annotation), with the benefit of allowing the reuse of the
IngressClass+ConfigMap configuration.

```yaml
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: my-class
spec:
  controller: haproxy-ingress.github.io/controller
  parameters:
    kind: ConfigMap
    name: my-options
```

```yaml
apiVersion: v1
data:
  balance-algorithm: roundrobin
  maxconn-server: "500"
  ssl-redirect: "false"
kind: ConfigMap
metadata:
  name: my-options
  namespace: ingress-controller
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  namespace: default
spec:
  ingressClassName: my-class
  ...
```

### Updates

Changes to any configuration in any classified `Ingress` resources (annotations
or spec), `Service` resources (annotations) or any referenced `ConfigMap` will
reflect in the update of the final HAProxy configuration.

If the new state cannot be dynamically applied and requires HAProxy to be reloaded,
this will happen preserving the in progress requests and the long running connections.

### Fragmentation

Ingress resources can be fragmented in order to add distinct configurations
to distinct routes. For example:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-front
spec:
  rules:
  - host: app.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 8080
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    haproxy-ingress.github.io/rewrite-target: /
  name: app-back
spec:
  rules:
  - host: app.local
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: backend
            port:
              number: 8080
```

HAProxy Ingress will merge all the resources, so there is no difference if the
configuration is in the same or in distinct Ingress. Distinct Ingress however
might lead to conflicting configuration, more about conflict in the
[scope](#scope) section below.

There is no hard limit to the number of Ingresses or Services - clusters with
tens of thousands of Ingress and Service resources report to work smoothly and
fast with HAProxy Ingress.

## Scope

HAProxy Ingress configuration keys may be in one of six distinct scopes: `Global`, `Frontend`, `Host`, `Backend`, `Path`, `TCP`. A scope defines where a configuration key value is applied in the HAProxy configuration, described in the sections below.

Configuration keys declared in `Ingress` resources might conflict in the case the same `Frontend` ports, `Host` hostname, `Backend` service, or the `TCP` port number is used on distinct ingress resources, and those ingress resources configure the same key with distinct values. In the case this happens, a warning will be logged and the used value will be of the Ingress resource that was created first.

### Global

Configuration keys from this scope are global for the whole HAProxy instance, and it is usually configured in the global area of the configuration file.

The only way to configure global scoped keys are via the global config ConfigMap resource. They are ignored if declared elsewhere. Since these keys cannot be configured via Ingress resources, they will also never conflict.

### Frontend

Configuration keys from this scope are applied per HAProxy frontend, so it is always related with the current `http-port` and `https-port` values, which will indicate the correct frontend receiving the configuration. Distinct frontends can receive distinct values from keys of this scope.

Frontend scoped keys can be declared in global or IngressClass related ConfigMaps as default values, or in any Ingress resource for a more granular configuration. They can conflict since they can be configured via Ingress resource.

When a frontend scoped key is used as an annotation, they should always be configured along with both `http-port` and `https-port`, and those ports should have a distinct value from the global one; otherwise, the global and frontend scoped configurations will conflict.

### Host

Configuration keys from the host scope are applied per hostname, which is more a Kubernetes API and HAProxy Ingress concept than a HAProxy one. Distinct hostnames can receive distinct values from keys of this scope.

Host scoped keys can be declared in global or IngressClass related ConfigMaps as default values, or in any Ingress resource for a more granular configuration. They can conflict since they can be configured via Ingress resource.

### Backend

Configuration keys from this scope are applied per HAProxy backend, which has an one-to-one relationship with the Kubernetes Service when configured via Ingress API. So, distinct referenced services can receive distinct values from keys of this scope.

Backend scoped keys can be declared in global or IngressClass related ConfigMaps as default values, or in any Ingress or Service resources for a more granular configuration. They can conflict when configured via Ingress, and will never conflict when configured via Service. In the case of a conflict between a Service and an Ingress, the Service configuration is used.

### Path

Configuration keys from this scope are applied per a combination of the hostname and the HTTP path. Just like the `Host` scope, it is more a Kubernetes API and HAProxy Ingress concept than a HAProxy one. Distinct combinations of hostname and path can receive distinct values from keys of this scope.

Path scoped keys can be declared in global or IngressClass related ConfigMaps as default values, or in any Ingress or Service resource for a more granular configuration. They can only conflict in the case the same key is configured both in an Ingress and the Service it points to. They will never conflict if configured exclusively via Ingress, since the same path, with the same match type, under the same hostname cannot be configured more than once. If this happens, HAProxy Ingress will reject the path declaration instead of conflict the configuration key value.

### TCP

Keys from this scope are applied per configured TCP port, assigned via the `tcp-service-port`. Every distinct TCP port creates a distinct HAProxy frontend, so distinct TCP port numbers, consequently their frontends, can receive distinct values from keys of this scope.

TCP scoped keys can be declared in global or IngressClass related ConfigMaps as default values, or in any Ingress resource for a more granular configuration. They can conflict since they can be configured via Ingress resource.

## Keys

The table below describes all supported configuration keys.

| Configuration key                                    | Data type                               | Scope    | Default value                    |
|------------------------------------------------------|-----------------------------------------|----------|----------------------------------|
| [`acme-emails`](#acme)                               | email1,email2,...                       | Global   |                                  |
| [`acme-endpoint`](#acme)                             | [`v2-staging`\|`v2`\|`endpoint`]        | Global   |                                  |
| [`acme-expiring`](#acme)                             | number of days                          | Global   | `30`                             |
| [`acme-preferred-chain`](#acme)                      | CN (Common Name) of the issuer          | Host     |                                  |
| [`acme-shared`](#acme)                               | [true\|false]                           | Global   | `false`                          |
| [`acme-terms-agreed`](#acme)                         | [true\|false]                           | Global   | `false`                          |
| [`affinity`](#affinity)                              | affinity type                           | Backend  |                                  |
| [`agent-check-addr`](#agent-check)                   | address for agent checks                | Backend  |                                  |
| [`agent-check-interval`](#agent-check)               | time with suffix                        | Backend  |                                  |
| [`agent-check-port`](#agent-check)                   | backend agent listen port               | Backend  |                                  |
| [`agent-check-send`](#agent-check)                   | string to send upon agent connection    | Backend  |                                  |
| [`allowlist-source-range`](#allowlist)               | Comma-separated IPs or CIDRs            | Path     |                                  |
| [`allowlist-source-header`](#allowlist)              | Header name that will be used as a src  | Path     |                                  |
| [`app-root`](#app-root)                              | /url                                    | Host     |                                  |
| [`assign-backend-server-id`](#backend-server-id)     | [true\|false]                           | Backend  | `false`                          |
| [`auth-external-placement`](#auth-external)          | [backend\|frontend]                     | Path     | `backend`                        |
| [`auth-headers-fail`](#auth-external)                | `<header>,...`                          | Path     | `*`                              |
| [`auth-headers-request`](#auth-external)             | `<header>,...`                          | Path     | `*`                              |
| [`auth-headers-succeed`](#auth-external)             | `<header>,...`                          | Path     | `*`                              |
| [`auth-log-format`](#log-format)                     | http log format for auth external       | Global   | do not log                       |
| [`auth-method`](#auth-external)                      | http request method                     | Path     | `GET`                            |
| [`auth-proxy`](#auth-external)                       | frontend name and tcp port interval     | Global   | `_front__auth:14415-14499`       |
| [`auth-realm`](#auth-basic)                          | realm string                            | Path     |                                  |
| [`auth-secret`](#auth-basic)                         | secret name                             | Path     |                                  |
| [`auth-signin`](#auth-external)                      | Sign in URL                             | Path     |                                  |
| [`auth-tls-cert-header`](#auth-tls)                  | [true\|false]                           | Backend  |                                  |
| [`auth-tls-error-page`](#auth-tls)                   | url                                     | Host     |                                  |
| [`auth-tls-secret`](#auth-tls)                       | namespace/secret name                   | Host     |                                  |
| [`auth-tls-strict`](#auth-tls)                       | [true\|false]                           | Host     |                                  |
| [`auth-tls-verify-client`](#auth-tls)                | [off\|optional\|on\|optional_no_ca]     | Host     |                                  |
| [`auth-url`](#auth-external)                         | Authentication URL                      | Path     |                                  |
| [`backend-check-interval`](#health-check)            | time with suffix                        | Backend  | `2s`                             |
| [`backend-protocol`](#backend-protocol)              | [h1\|h2\|h1-ssl\|h2-ssl]                | Backend  | `h1`                             |
| [`backend-server-naming`](#backend-server-naming)    | [sequence\|ip\|pod]                     | Backend  | `sequence`                       |
| [`backend-server-slots-increment`](#dynamic-scaling) | number of slots                         | Backend  | `1`                              |
| [`balance-algorithm`](#balance-algorithm)            | algorithm name                          | Backend  | `random(2)`                      |
| [`bind-fronting-proxy`](#bind)                       | ip + port                               | Frontend |                                  |
| [`bind-http`](#bind)                                 | ip + port                               | Frontend |                                  |
| [`bind-https`](#bind)                                | ip + port                               | Frontend |                                  |
| [`bind-ip-addr-healthz`](#bind-ip-addr)              | IP address                              | Global   |                                  |
| [`bind-ip-addr-http`](#bind-ip-addr)                 | IP address                              | Frontend |                                  |
| [`bind-ip-addr-prometheus`](#bind-ip-addr)           | IP address                              | Global   |                                  |
| [`bind-ip-addr-stats`](#bind-ip-addr)                | IP address                              | Global   |                                  |
| [`bind-ip-addr-tcp`](#bind-ip-addr)                  | IP address                              | Global   |                                  |
| [`blue-green-balance`](#blue-green)                  | label=value=weight,...                  | Backend  |                                  |
| [`blue-green-cookie`](#blue-green)                   | `CookieName:LabelName` pair             | Backend  |                                  |
| [`blue-green-deploy`](#blue-green)                   | label=value=weight,...                  | Backend  |                                  |
| [`blue-green-header`](#blue-green)                   | `HeaderName:LabelName` pair             | Backend  |                                  |
| [`blue-green-mode`](#blue-green)                     | [pod\|deploy]                           | Backend  |                                  |
| [`cert-signer`](#acme)                               | "acme"                                  | Host     |                                  |
| [`close-sessions-duration`](#close-sessions-duration) | time with suffix or percentage         | Global   | leave sessions open              |
| [`config-backend`](#configuration-snippet)           | multiline backend config                | Backend  |                                  |
| [`config-defaults`](#configuration-snippet)          | multiline config for the defaults section | Global |                                  |
| [`config-frontend`](#configuration-snippet)          | multiline HTTP and HTTPS frontend config | Global  |                                  |
| [`config-frontend-early`](#configuration-snippet)    | multiline HTTP and HTTPS frontend config, applied before any builtin logic | Global | |
| [`config-frontend-late`](#configuration-snippet)     | multiline HTTP and HTTPS frontend config, same as `config-frontend` | Global |        |
| [`config-global`](#configuration-snippet)            | multiline config for the global section | Global   |                                  |
| [`config-peers`](#configuration-snippet)             | multiline config for the peers section  | Global   |                                  |
| [`config-proxy`](#configuration-snippet)             | multiline config for any proxy          | Global   |                                  |
| [`config-sections`](#configuration-snippet)          | multiline custom sections declaration   | Global   |                                  |
| [`config-tcp`](#configuration-snippet)               | multiline ConfigMap based TCP config    | Global   |                                  |
| [`config-tcp-service`](#configuration-snippet)       | multiline TCP service config            | TCP      |                                  |
| [`cookie-key`](#affinity)                            | secret key                              | Global   | `Ingress`                        |
| [`cors-allow-credentials`](#cors)                    | [true\|false]                           | Path     |                                  |
| [`cors-allow-headers`](#cors)                        | headers list                            | Path     |                                  |
| [`cors-allow-methods`](#cors)                        | methods list                            | Path     |                                  |
| [`cors-allow-origin`](#cors)                         | URL                                     | Path     |                                  |
| [`cors-allow-origin-regex`](#cors)                   | regex                                   | Path     |                                  |
| [`cors-enable`](#cors)                               | [true\|false]                           | Path     |                                  |
| [`cors-expose-headers`](#cors)                       | headers                                 | Path     |                                  |
| [`cors-max-age`](#cors)                              | time (seconds)                          | Path     |                                  |
| [`cpu-map`](#cpu-map)                                | haproxy CPU Map format                  | Global   |                                  |
| [`cross-namespace-secrets-ca`](#cross-namespace)     | [allow\|deny]                           | Global   | `deny`                           |
| [`cross-namespace-secrets-crt`](#cross-namespace)    | [allow\|deny]                           | Global   | `deny`                           |
| [`cross-namespace-secrets-passwd`](#cross-namespace) | [allow\|deny]                           | Global   | `deny`                           |
| [`cross-namespace-services`](#cross-namespace)       | [allow\|deny]                           | Global   | `deny`                           |
| [`default-backend-redirect`](#default-redirect)      | Location                                | Global   |                                  |
| [`default-backend-redirect-code`](#default-redirect) | HTTP status code                        | Global   | `302`                            |
| [`denylist-source-range`](#allowlist)                | Comma-separated IPs or CIDRs            | Path     |                                  |
| [`dns-accepted-payload-size`](#dns-resolvers)        | number                                  | Global   | `8192`                           |
| [`dns-cluster-domain`](#dns-resolvers)               | cluster name                            | Global   | `cluster.local`                  |
| [`dns-hold-obsolete`](#dns-resolvers)                | time with suffix                        | Global   | `0s`                             |
| [`dns-hold-valid`](#dns-resolvers)                   | time with suffix                        | Global   | `1s`                             |
| [`dns-resolvers`](#dns-resolvers)                    | multiline resolver=ip[:port]            | Global   |                                  |
| [`dns-timeout-retry`](#dns-resolvers)                | time with suffix                        | Global   | `1s`                             |
| [`drain-support`](#drain-support)                    | [true\|false]                           | Global   | `false`                          |
| [`drain-support-redispatch`](#drain-support)         | [true\|false]                           | Global   | `true`                           |
| [`dynamic-scaling`](#dynamic-scaling)                | [true\|false]                           | Backend  | `true`                           |
| [`external-has-lua`](#external)                      | [true\|false]                           | Global   | `false`                          |
| [`fcgi-app`](#fastcgi)                               | fcgi-app section name                   | Backend  |                                  |
| [`fcgi-enabled-apps`](#fastcgi)                      | comma-separated list of names           | Global   | `*`                              |
| [`forwardfor`](#forwardfor)                          | [add\|ignore\|ifmissing]                | Global   | `add`                            |
| [`fronting-proxy-port`](#fronting-proxy-port)        | port number                             | Frontend | 0 (do not listen)                |
| [`groupname`](#security)                             | haproxy group name                      | Global   | `haproxy`                        |
| [`headers`](#headers)                                | multiline header:value pair             | Backend  |                                  |
| [`health-check-addr`](#health-check)                 | address for health checks               | Backend  |                                  |
| [`health-check-fall-count`](#health-check)           | number of failures                      | Backend  |                                  |
| [`health-check-interval`](#health-check)             | time with suffix                        | Backend  |                                  |
| [`health-check-port`](#health-check)                 | port for health checks                  | Backend  |                                  |
| [`health-check-rise-count`](#health-check)           | number of successes                     | Backend  |                                  |
| [`health-check-uri`](#health-check)                  | uri for http health checks              | Backend  |                                  |
| [`healthz-port`](#bind-port)                         | port number                             | Global   | `10253`                          |
| [`hsts`](#hsts)                                      | [true\|false]                           | Path     | `true`                           |
| [`hsts-include-subdomains`](#hsts)                   | [true\|false]                           | Path     | `false`                          |
| [`hsts-max-age`](#hsts)                              | number of seconds                       | Path     | `15768000`                       |
| [`hsts-preload`](#hsts)                              | [true\|false]                           | Path     | `false`                          |
| [`http-header-match`](#http-match)                   | header name and value, exact match      | Path     |                                  |
| [`http-header-match-regex`](#http-match)             | header name and value, regex match      | Path     |                                  |
| [`http-log-format`](#log-format)                     | http log format                         | Global   | HAProxy default log format       |
| [`http-port`](#bind-port)                            | port number                             | Frontend | `80`                             |
| [`http-response-<code>`](#http-response)             | response output                         | vary     |                                  |
| [`http-response-prometheus-root`](#http-response)    | response output                         | Global   |                                  |
| [`https-log-format`](#log-format)                    | https(tcp) log format\|`default`        | Global   | do not log                       |
| [`https-port`](#bind-port)                           | port number                             | Frontend | `443`                            |
| [`https-to-http-port`](#fronting-proxy-port)         | port number                             | Frontend | 0 (do not listen)                |
| [`initial-weight`](#initial-weight)                  | weight value                            | Backend  | `1`                              |
| [`limit-connections`](#limit)                        | qty                                     | Backend  |                                  |
| [`limit-rps`](#limit)                                | rate per second                         | Backend  |                                  |
| [`limit-whitelist`](#limit)                          | cidr list                               | Backend  |                                  |
| [`load-server-state`](#load-server-state) (experimental) |[true\|false]                        | Global   | `false`                          |
| [`master-exit-on-failure`](#master-worker)           | [true\|false]                           | Global   | `true`                           |
| [`max-connections`](#connection)                     | number                                  | Global   | `2000`                           |
| [`maxconn-server`](#connection)                      | qty                                     | Backend  |                                  |
| [`maxqueue-server`](#connection)                     | qty                                     | Backend  |                                  |
| [`modsecurity-args`](#modsecurity)                   | space-separated list of strings         | Global   | `unique-id method path query req.ver req.hdrs_bin req.body_size req.body` |
| [`modsecurity-endpoints`](#modsecurity)              | comma-separated list of IP:port (spoa)  | Global   | no waf config                    |
| [`modsecurity-timeout-hello`](#modsecurity)          | time with suffix                        | Global   | `100ms`                          |
| [`modsecurity-timeout-idle`](#modsecurity)           | time with suffix                        | Global   | `30s`                            |
| [`modsecurity-timeout-processing`](#modsecurity)     | time with suffix                        | Global   | `1s`                             |
| [`modsecurity-use-coraza`](#modsecurity)             | [true\|false]                           | Global   | `false`                          |
| [`nbproc-ssl`](#nbproc)                              | number of process                       | Global   | `0`                              |
| [`nbthread`](#nbthread)                              | number of threads                       | Global   |                                  |
| [`no-redirect-locations`](#redirect)                 | comma-separated list of URIs            | Global   | `/.well-known/acme-challenge`    |
| [`no-tls-redirect-locations`](#ssl-redirect)         | comma-separated list of URIs            | Global   | `/.well-known/acme-challenge`    |
| [`oauth`](#oauth)                                    | "oauth2_proxy"                          | Path     |                                  |
| [`oauth-headers`](#oauth)                            | `<header>:<var>,...`                    | Path     |                                  |
| [`oauth-uri-prefix`](#oauth)                         | URI prefix                              | Path     |                                  |
| [`original-forwarded-for-hdr`](#forwardfor)          | header name                             | Global   | `X-Original-Forwarded-For`       |
| [`path-type`](#path-type)                            | path matching type                      | Path     | `begin`                          |
| [`path-type-order`](#path-type)                      | comma-separated path type list          | Global   | `exact,prefix,begin,regex`       |
| [`peers-name`](#peers)                               | peers section name                      | Global   | `ingress`                        |
| [`peers-port`](#peers)                               | port number                             | Global   |                                  |
| [`peers-table`](#peers)                              | stick-table declaration                 | Backend  |                                  |
| [`peers-table-global`](#peers)                       | stick-table declaration                 | Global   |                                  |
| [`prometheus-port`](#bind-port)                      | port number                             | Global   |                                  |
| [`proxy-body-size`](#proxy-body-size)                | size (bytes)                            | Path     | unlimited                        |
| [`proxy-protocol`](#proxy-protocol)                  | [v1\|v2\|v2-ssl\|v2-ssl-cn]             | Backend  |                                  |
| [`real-ip-hdr`](#forwardfor)                         | header name                             | Global   | `X-Real-IP`                      |
| [`redirect-from`](#redirect)                         | domain name                             | Host     |                                  |
| [`redirect-from-code`](#redirect)                    | http status code                        | Frontend | `302`                            |
| [`redirect-from-regex`](#redirect)                   | regex                                   | Host     |                                  |
| [`redirect-to`](#redirect)                           | fully qualified URL                     | Path     |                                  |
| [`redirect-to-code`](#redirect)                      | http status code                        | Frontend | `302`                            |
| [`rewrite-target`](#rewrite-target)                  | path string                             | Path     |                                  |
| [`secure-backends`](#secure-backend)                 | [true\|false]                           | Backend  |                                  |
| [`secure-crt-secret`](#secure-backend)               | secret name                             | Backend  |                                  |
| [`secure-sni`](#secure-backend)                      | [`sni`\|`host`\|`<hostname>`]           | Backend  |                                  |
| [`secure-verify-ca-secret`](#secure-backend)         | secret name                             | Backend  |                                  |
| [`secure-verify-hostname`](#secure-backend)          | hostname                                | Backend  |                                  |
| [`server-alias`](#server-alias)                      | domain name                             | Host     |                                  |
| [`server-alias-regex`](#server-alias)                | regex                                   | Host     |                                  |
| [`service-upstream`](#service-upstream)              | [true\|false]                           | Backend  | `false`                          |
| [`session-cookie-domain`](#affinity)                 | domain name                             | Backend  |                                  |
| [`session-cookie-dynamic`](#affinity)                | [true\|false]                           | Backend  |                                  |
| [`session-cookie-keywords`](#affinity)               | cookie options                          | Backend  | `indirect nocache httponly`      |
| [`session-cookie-name`](#affinity)                   | cookie name                             | Backend  |                                  |
| [`session-cookie-preserve`](#affinity)               | [true\|false]                           | Backend  | `false`                          |
| [`session-cookie-shared`](#affinity)                 | [true\|false]                           | Backend  | `false`                          |
| [`session-cookie-strategy`](#affinity)               | [insert\|prefix\|rewrite]               | Backend  |                                  |
| [`session-cookie-value-strategy`](#affinity)         | [server-name\|pod-uid]                  | Backend  | `server-name`                    |
| [`slots-min-free`](#dynamic-scaling)                 | minimum number of free slots            | Backend  | `0`                              |
| [`source-address-intf`](#source-address-intf)        | `<intf1>[,<intf2>...]`                  | Backend  |                                  |
| [`ssl-always-add-https`](#ssl-always-add-https)      | [true\|false]                           | Host     | `false`                          |
| [`ssl-always-follow-redirect`](#ssl-always-add-https) | [true\|false]                          | Host     | `true`                           |
| [`ssl-cipher-suites`](#ssl-ciphers)                  | colon-separated list                    | Host     | [see description](#ssl-ciphers)  |
| [`ssl-cipher-suites-backend`](#ssl-ciphers)          | colon-separated list                    | Backend  | [see description](#ssl-ciphers)  |
| [`ssl-ciphers`](#ssl-ciphers)                        | colon-separated list                    | Host     | [see description](#ssl-ciphers)  |
| [`ssl-ciphers-backend`](#ssl-ciphers)                | colon-separated list                    | Backend  | [see description](#ssl-ciphers)  |
| [`ssl-dh-default-max-size`](#ssl-dh)                 | number                                  | Global   | `1024`                           |
| [`ssl-dh-param`](#ssl-dh)                            | namespace/secret name                   | Global   | no custom DH param               |
| [`ssl-engine`](#ssl-engine)                          | OpenSSL engine name and parameters      | Global   | no engine set                    |
| [`ssl-fingerprint-lower`](#auth-tls)                 | [true\|false]                           | Backend  | `false`                          |
| [`ssl-fingerprint-sha2-bits`](#auth-tls)             | Bits of the SHA-2 fingerprint           | Backend  |                                  |
| [`ssl-headers-prefix`](#auth-tls)                    | prefix                                  | Global   | `X-SSL`                          |
| [`ssl-mode-async`](#ssl-engine)                      | [true\|false]                           | Global   | `false`                          |
| [`ssl-options`](#ssl-options)                        | space-separated list                    | Global   | [see description](#ssl-options)  |
| [`ssl-options-backend`](#ssl-options)                | space-separated list                    | Backend  | [see description](#ssl-options)  |
| [`ssl-options-host`](#ssl-options)                   | space-separated list                    | Host     | [see description](#ssl-options)  |
| [`ssl-passthrough`](#ssl-passthrough)                | [true\|false]                           | Host     |                                  |
| [`ssl-passthrough-http-port`](#ssl-passthrough)      | backend port                            | Host     |                                  |
| [`ssl-redirect`](#ssl-redirect)                      | [true\|false]                           | Path     | `true`                           |
| [`ssl-redirect-code`](#ssl-redirect)                 | http status code                        | Global   | `302`                            |
| [`stats-auth`](#stats)                               | user:passwd                             | Global   | no auth                          |
| [`stats-port`](#stats)                               | port number                             | Global   | `1936`                           |
| [`stats-proxy-protocol`](#stats)                     | [true\|false]                           | Global   | `false`                          |
| [`stats-ssl-cert`](#stats)                           | namespace/secret name                   | Global   | no ssl/plain http                |
| [`strict-host`](#strict-host)                        | [true\|false]                           | Global   | `false`                          |
| [`syslog-endpoint`](#syslog)                         | IP:port (udp)                           | Global   | do not log                       |
| [`syslog-format`](#syslog)                           | rfc5424\|rfc3164                        | Global   | `rfc5424`                        |
| [`syslog-length`](#syslog)                           | maximum length                          | Global   | `1024`                           |
| [`syslog-tag`](#syslog)                              | syslog tag field string                 | Global   | `ingress`                        |
| [`tcp-log-format`](#log-format)                      | ConfigMap based TCP log format          | Global   |                                  |
| [`tcp-service-log-format`](#log-format)              | TCP service log format                  | TCP      | HAProxy default log format       |
| [`tcp-service-port`](#tcp-services)                  | TCP service port number                 | TCP      |                                  |
| [`tcp-service-proxy-protocol`](#proxy-protocol)      | [true\|false]                           | TCP      | `false`                          |
| [`timeout-client`](#timeout)                         | time with suffix                        | Global   | `50s`                            |
| [`timeout-client-fin`](#timeout)                     | time with suffix                        | Global   | `50s`                            |
| [`timeout-connect`](#timeout)                        | time with suffix                        | Backend  | `5s`                             |
| [`timeout-http-request`](#timeout)                   | time with suffix                        | Backend  | `5s`                             |
| [`timeout-keep-alive`](#timeout)                     | time with suffix                        | Backend  | `1m`                             |
| [`timeout-queue`](#timeout)                          | time with suffix                        | Backend  | `5s`                             |
| [`timeout-server`](#timeout)                         | time with suffix                        | Backend  | `50s`                            |
| [`timeout-server-fin`](#timeout)                     | time with suffix                        | Backend  | `50s`                            |
| [`timeout-stop`](#timeout)                           | time with suffix                        | Global   | `10m`                            |
| [`timeout-tunnel`](#timeout)                         | time with suffix                        | Backend  | `1h`                             |
| [`tls-alpn`](#tls-alpn)                              | TLS ALPN advertisement                  | Host     | `h2,http/1.1`                    |
| [`use-chroot`](#security)                            | [true\|false]                           | Global   | `false`                          |
| [`use-cpu-map`](#cpu-map)                            | [true\|false]                           | Global   | `true`                           |
| [`use-forwarded-proto`](#fronting-proxy-port)        | [true\|false]                           | Frontend | `true`                           |
| [`use-haproxy-user`](#security)                      | [true\|false]                           | Global   | `false`                          |
| [`use-htx`](#use-htx)                                | [true\|false]                           | Global   | `false`                          |
| [`use-proxy-protocol`](#proxy-protocol)              | [true\|false]                           | Frontend | `false`                          |
| [`use-resolver`](#dns-resolvers)                     | resolver name                           | Backend  |                                  |
| [`username`](#security)                              | haproxy user name                       | Global   | `haproxy`                        |
| [`var-namespace`](#var-namespace)                    | [true\|false]                           | Host     | `false`                          |
| [`waf`](#waf)                                        | "modsecurity"                           | Path     |                                  |
| [`waf-mode`](#waf)                                   | [deny\|detect]                          | Path     | `deny` (if waf is set)           |
| [`whitelist-source-range`](#allowlist)               | Comma-separated IPs or CIDRs            | Path     |                                  |
| [`worker-max-reloads`](#master-worker)               | number of reloads                       | Global   | `0`                              |

---

### Acme

| Configuration key      | Scope    | Default | Since   |
|------------------------|----------|---------|---------|
| `acme-emails`          | `Global` |         | v0.9    |
| `acme-endpoint`        | `Global` |         | v0.9    |
| `acme-expiring`        | `Global` | `30`    | v0.9    |
| `acme-preferred-chain` | `Host`   |         | v0.13.5 |
| `acme-shared`          | `Global` | `false` | v0.9    |
| `acme-terms-agreed`    | `Global` | `false` | v0.9    |
| `cert-signer`          | `Host`   |         | v0.9    |

Configures dynamic options used to authorize and sign certificates against a server
which implements the acme protocol, version 2.

The popular [Let's Encrypt](https://letsencrypt.org) certificate authority implements
acme-v2.

Supported acme configuration keys:

* `acme-emails`: mandatory, a comma-separated list of emails used to configure the client account. The account will be updated if this option is changed.
* `acme-endpoint`: mandatory, endpoint of the acme environment. `v2-staging` and `v02-staging` are alias to `https://acme-staging-v02.api.letsencrypt.org`, while `v2` and `v02` are alias to `https://acme-v02.api.letsencrypt.org`.
* `acme-expiring`: how many days before expiring a certificate should be considered old and should be updated. Defaults to `30` days.
* `acme-preferred-chain`: optional, defines the Issuer's CN (Common Name) of the topmost certificate in the chain, if the acme server offers multiple certificate chains. The default certificate chain will be used if empty or no match is found. Note that changing this option will not force a new certificate to be issued if a valid one is already in place and actual and preferred chains differ. A new certificate can be emitted by changing the secret name in the ingress resource, or removing the secret being referenced.
* `acme-shared`: defines if another certificate signer is running in the cluster. If `false`, the default value, any request to `/.well-known/acme-challenge/` is sent to the local acme server despite any ingress object configuration. Otherwise, if `true`, a configured ingress object would take precedence.
* `acme-terms-agreed`: mandatory, it should be defined as `true`; otherwise, certificates won't be issued.
* `cert-signer`: defines the certificate signer that should be used to authorize and sign new certificates. The only supported value is `"acme"`. Add this config as an annotation in the ingress object that should have its certificate managed by haproxy-ingress and signed by the configured acme environment. The annotation `kubernetes.io/tls-acme: "true"` is also supported if the command-line option `--acme-track-tls-annotation` is used.

**Minimum setup**

The command-line option `--acme-server` need to be declared to start the local
server and the work queue used to authorize and sign new certificates. See [other
command-line options]({{% relref "command-line/#acme" %}}).

The following configuration keys are mandatory: `acme-emails`, `acme-endpoint`,
`acme-terms-agreed`.

A cluster-wide permission to `create` and `update` the `secrets` resources should
also be made.

{{< alert title="Note" >}}
haproxy-ingress need cluster-wide permissions `create` and `update` on resource
`secrets` to store the client private key (new account) and the generated certificate
and its private key. The default clusterrole configuration doesn't provide these
permissions.
{{< /alert >}}

**How it works**

All haproxy-ingress instances should declare `--acme-server`
[command-line option]({{% relref "command-line/#acme" %}}), which will start a local
server to answer acme challenges, a work queue to enqueue the domain authorization
and certificate signing, and will also start a leader election to define which
haproxy-ingress instance should perform authorizations and certificate signing.

The haproxy-ingress leader tracks ingress objects that declares the annotation
`haproxy-ingress.github.io/cert-signer` with value `acme` and a configured secret name for
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

### Affinity

| Configuration key               | Scope     | Default                     | Since   |
|---------------------------------|-----------|-----------------------------|---------|
| `affinity`                      | `Backend` | `false`                     |         |
| `cookie-key`                    | `Global`  | `Ingress`                   |         |
| `session-cookie-domain`         | `Backend` |                             | v0.13.6 |
| `session-cookie-dynamic`        | `Backend` | `true`                      |         |
| `session-cookie-keywords`       | `Backend` | `indirect nocache httponly` | v0.11   |
| `session-cookie-name`           | `Backend` | `INGRESSCOOKIE`             |         |
| `session-cookie-preserve`       | `Backend` | `false`                     | v0.12   |
| `session-cookie-same-site`      | `Backend` | `false`                     | v0.12   |
| `session-cookie-shared`         | `Backend` | `false` (deprecated)        | v0.8    |
| `session-cookie-strategy`       | `Backend` | `insert`                    |         |
| `session-cookie-value-strategy` | `Backend` | `server-name`               | v0.12   |

Configure if HAProxy should maintain client requests to the same backend server.

* `affinity`: the only supported option is `cookie`. If declared, clients will receive a cookie with a hash of the server it should be fidelized to.
* `cookie-key`: defines a secret key used with the IP address and port number of a backend server to dynamically create a cookie to that server. Defaults to `Ingress` if not provided.
* `session-cookie-domain`: configures the domain to which the persistence cookie should be sent. All subdomains of the configured domain will also receive the cookie. The ingress' hostname must match this configuration, or should be a subdomain; otherwise, modern browsers will refuse to accept the cookie. E.g. if the ingress is configured as `sub.example.com`, the `session-cookie-domain` value must be only `sub.example.com` or `example.com`. If `example.com` is used, all of its subdomains will receive the cookie. This option has precedence over `session-cookie-shared`. Note that, although hostname related, this is a backend scoped configuration key, so the configuration will conflict if used in two or more distinct ingress, with distinct values, pointing to the same Kubernetes service. See [backend scope](#backend) for further information about configuration conflict.
* `session-cookie-dynamic`: indicates whether or not dynamic cookie value will be used. With the default of `true`, a cookie value will be generated by HAProxy using a hash of the server IP address, TCP port, and dynamic cookie secret key. When `false`, the server name will be used as the cookie name. Note that setting this to `false` will have no impact if [use-resolver](#dns-resolvers) is set.
* `session-cookie-keywords`: additional options to the `cookie` option like `nocache`, `httponly`. For the sake of backwards compatibility the default is `indirect nocache httponly` if not declared and `strategy` is `insert`.
* `session-cookie-name`: the name of the cookie. `INGRESSCOOKIE` is the default value if not declared.
* `session-cookie-preserve`: indicates whether the session cookie will be set to `preserve` mode. If this mode is enabled, haproxy will allow backend servers to use a `Set-Cookie` HTTP header to emit their own persistence cookie value, meaning the backend servers have knowledge of which cookie value should route to which server. Since the cookie value is tightly coupled with a particular backend server in this scenario, this mode will cause dynamic updating to understand that it must keep the same cookie value associated with the same backend server. If this is disabled, dynamic updating is free to assign servers in a way that can make their cookie value no longer matching.
* `session-cookie-same-site`: if `true`, adds the `SameSite=None; Secure` attributes, which configures the browser to send the persistence cookie with both cross-site and same-site requests. The default value is `false`, which means only same-site requests will send the persistence cookie.
* `session-cookie-shared`: defines if the persistence cookie should be shared between all domains that uses this backend. Defaults to `false`. If `true` the `Set-Cookie` response will declare all the domains that shares this backend, indicating to the HTTP agent that all of them should use the same backend server. Note that this option is active only for backward compatibility: modern browsers accept only one domain attribute, deprecating how this option builds the persistence cookie configuration. Use `session-cookie-domain` instead.
* `session-cookie-strategy`: the cookie strategy to use (insert, rewrite, prefix). `insert` is the default value if not declared.
* `session-cookie-value-strategy`: the strategy to use to calculate the cookie value of a server (`server-name`, `pod-uid`). `server-name` is the default if not declared, and indicates that the cookie will be set based on the name defined in `backend-server-naming`. `pod-uid` indicates that the cookie will be set to the `UID` of the pod running the target server.

Note for `dynamic-scaling` users only, v0.5 or older: the hash of the server is built based on it's name.
When the slots are scaled down, the remaining servers might change it's server name on
HAProxy configuration. In order to circumvent this, always configure the slot increment at
least as much as the number of replicas of the deployment that need to use affinity. This
limitation was removed on v0.6.

See also:

* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
* https://docs.haproxy.org/2.8/configuration.html#4-cookie
* https://docs.haproxy.org/2.8/configuration.html#5.2-cookie
* https://www.haproxy.com/blog/load-balancing-affinity-persistence-sticky-sessions-what-you-need-to-know/
* https://docs.haproxy.org/2.8/configuration.html#dynamic-cookie-key

---

### Agent check

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

{{< alert title="Note" >}}
* `agent-check-port` must be provided for any of the agent check options to be applied
* define [`initial-weight`](#initial-weight) if using `agent-check` to change the server weight
{{< /alert >}}

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

* https://docs.haproxy.org/2.8/configuration.html#5.2-agent-check
* https://docs.haproxy.org/2.8/configuration.html#5.2-agent-port
* https://docs.haproxy.org/2.8/configuration.html#5.2-agent-inter
* https://docs.haproxy.org/2.8/configuration.html#5.2-agent-send

---

### Allowlist

| Configuration key        | Scope  | Default | Since   |
|--------------------------|--------|---------|---------|
| `allowlist-source-range` | `Path` |         | v0.12   |
| `denylist-source-range`  | `Path` |         | v0.12   |
| `whitelist-source-range` | `Path` |         |         |
| `allowlist-source-header`| `Path` |         | v0.13.2 |

Defines a comma-separated list of source IPs or CIDRs allowed or denied to connect.
The default behavior is to allow all source IPs if neither the allow list nor the
deny list are declared. The lists support IPv4 and IPv6.

This is a path scoped configuration: distinct paths in the same hostname can have
distinct configurations. However this doesn't happen if the backend has
[ssl-passthrough](#ssl-passthrough), which uses HAProxy's TCP mode, in this case
the allow and deny lists act as a backend scoped config.

Since v0.12 IPs or CIDRs can be prefixed with `!`, which means an exception to the
rule, so an allow list with `"10.0.0.0/8,!10.100.0.0/16"` will allow only IPs from
the range `10.x.x.x`, except the range `10.100.x.x` which will continue to be denied.

* `allowlist-source-range`: Used to deny requests by default, allowing only the IPs
and CIDRs in the list, except IPs and CIDRs prefixed with `!` which will continue to
be denied. `whitelist-source-range` is an alias to preserve backward compatibility,
and will be ignored if `allowlist-source-range` is declared.
* `denylist-source-range`: Used to allow requests by default, denying only the IPs
and CIDRs in the list, except IPs and CIDRs prefixed with `!` which will continue to
be allowed.
* `allowlist-source-header`: Used to define a header from which source IP will be
taken in order to compare with the allow and deny list. If not defined a normal source
will be used. This option is useful when ingress is hidden behind reverse proxy but you
still want to control access to separate paths from ingress configuration.

Allowlist and denylist can be used together. The request will be denied if the
configurations overlap and a source IP matches both the allowlist and denylist.

{{< alert title="Warning" color="warning" >}}
Setting a `allowlist-source-header` comes with a security risk. You must ensure that
the selected header can be trusted!
{{< /alert >}}

See also:

* https://docs.haproxy.org/2.8/configuration.html#4.2-http-request%20deny
* https://docs.haproxy.org/2.8/configuration.html#4.2-http-request%20set-src

---

### App root

| Configuration key | Scope  | Default | Since  |
|-------------------|--------|---------|--------|
| `app-root`        | `Host` |         |        |

Defines a distinct application root path. HAProxy will redirect requests to the
configured path, using `302` status code, when the HTTP client sends a request
to the root context of the configured domain. `app-root` key binds to the root
context path, so it needs to be declared in the same Ingress that configures it.

See also:

* [Redirect](#redirect) configuration keys.

---

### Auth Basic

| Configuration key | Scope   | Default   | Since  |
|-------------------|---------|-----------|--------|
| `auth-realm`      | `Path`  | localhost |        |
| `auth-secret`     | `Path`  |           |        |

Configures Basic Authentication options.

* `auth-secret`: A secret name with users and passwords used to configure basic authentication. The secret can be in the same namespace of the Ingress resource, or any other namespace if cross namespace is enabled. Secret in the same namespace does not need to be prepended with `namespace/`. A filename prefixed with `file://` can be used containing the list of users and passwords, eg `file:///dir/users.list`.
* `auth-realm`: Optional, configures the authentication realm string. `localhost` will be used if not provided.

The secret referenced by `auth-secret` should have a key named `auth` with users and passwords, one per line. The following two formats are supported and both are supported in the same secret or file:

* `<user>::<password>`: User and password are separated by 2 (two) colons. The password will be copied verbatim, stored in the configuration file in an insecure way.
* `<user>:<password-hash>`: User and password are separated by 1 (one) colon. This syntax needs a password hash that can be generated with `mkpasswd`.

{{< alert title="Note" >}}
Up to v0.12 the configuration key `auth-type` was mandatory, it enabled the only supported authentication type `basic`. Since v0.13 this configuration is deprecated and both Basic and External authentication types can be enabled at the same time: configure `auth-secret` to enable basic authentication, and configure `auth-url` to enable external authentication.
{{< /alert >}}

See also:

* [--allow-cross-namespace]({{% relref "command-line/#allow-cross-namespace" %}}) command-line option
* [Auth TLS](#auth-tls) configuration keys
* [Auth Basic example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/auth/basic) page

---

### Auth External

| Configuration key         | Scope    | Default   | Since |
|---------------------------|--------- |-----------|-------|
| `auth-external-placement` | `Path`   | `backend` | v0.15 |
| `auth-headers-fail`       | `Path`   | `*`       | v0.13 |
| `auth-headers-request`    | `Path`   | `*`       | v0.13 |
| `auth-headers-succeed`    | `Path`   | `*`       | v0.13 |
| `auth-method`             | `Path`   | `GET`     | v0.13 |
| `auth-proxy`              | `Global` | `_front__auth__local:14415-14499` | v0.13 |
| `auth-signin`             | `Path`   |           | v0.13 |
| `auth-url`                | `Path`   |           | v0.13 |

Configures External Authentication options.

* `auth-url`: Configures the endpoint(s) of the authentication service. All requests made to the target backend server will be validated by the authentication service before continue, which should respond with `2xx` HTTP status code; otherwise, the request is considered as failed. In the case of a failure, the backend server is not used and the client receives the response from the authentication service.
* `auth-external-placement`: Defines where the external service call should be configured. Options are `backend` and `frontend`. Default value is `backend` and this is the value that has the better performance. Use `frontend` if the external service create HTTP headers used on early stages, e.g. [HTTP header routing constraints](#http-match). Note that placing the external authentication configuration in the frontend comes with a performance penalty, because all the incoming requests will need to evaluate the ACLs of this configuration. Avoid placing too much (dozens) paths in the frontend on high loaded proxies.
* `auth-method`: Configures the HTTP method used in the request to the external authentication service. Use an asterisk `*` to copy the same method used in the client request. The default value is `GET`.
* `auth-headers-request`: Configures a comma-separated list of header names that should be copied from the client to the authentication service. All HTTP headers will be copied if not declared.
* `auth-headers-succeed`: Configures a comma-separated list of header names that should be copied from the authentication service to the backend server if the authentication succeed. All HTTP headers will be copied if not declared.
* `auth-headers-fail`: Configures a comma-separated list of header names that should be copied from the authentication service to the client if the authentication fail. This option is ignored if `auth-signin` is used. All HTTP headers will be copied if not declared.
* `auth-signin`: Optional, configures the endpoint of the sign in server used to redirect failed requests. The content is parsed by haproxy as a [log-format](https://docs.haproxy.org/2.8/configuration.html#8.2.4) string and the result is copied verbatim to the `Location` header of a HTTP 302 response. The default behavior is to use the authentication service response.
* `auth-proxy`: Optional, changes the name of a frontend proxy and a free TCP port range, used by `auth-request.lua` script to query the external authentication endpoint.

**External service URL**

`auth-url` is the only mandatory option and receives the external authentication service endpoint. The url format is `<proto>://<name>[:<port>][<path>]`, which means:

* `<proto>`: can be `http`, `https`, `service` or `svc`.
* `<name>`: the IP or hostname if `http` or `https`, or the name of a service if `service`. `svc` is an alias to `service`. Note that the hostname is resolved to a list of IP when the ingress is parsed and will not be dynamically updated later if the DNS record changes.
* `<port>`: the port number, must be provided if a service is used and can be omitted if using `http` or `https`. If the service uses named ports, use the service's `port.targetPort` field value instead.
* `<path>`: optional, the fully qualified path to the authentication service.

`http` and `https` protocols are straightforward: use them to connect to an IP or hostname without any further configuration. `http` adds the HTTP `Host` header if a hostname is used, and `https` adds also the sni extension. Note that `https` connects in an insecure way and currently cannot be customized. Do NOT use neither `http` nor `https` if haproxy -> authentication service communication has untrusted networks.

`svc` protocol allows to use a Kubernetes service declared in the same namespace of the ingress or the service being annotated. Services on other namespaces can also be used in the form `svc://namespace/servicename:port/path` if global config [`cross-namespace-services`](#cross-namespace) was configured as `allow`. The service can be of any type and a port must always be declared - both in the `auth-url` configuration and in the service resource. Using `svc` protocol allows to configure a secure connection, see [secure](#secure-backend) configuration keys and annotate them in the target service.

Configuration examples:

* `auth-url: "http://10.0.0.2"`: Authentication service accepts plain HTTP connection, TCP port `80` and root path are used.
* `auth-url: "https://10.0.0.2/auth"`: Authentication service accepts HTTPS connection, TCP port `443` and path `/auth` are used.
* `auth-url: "https://auth.local:8443"`: Domain `auth.local` is resolved during configuration building, and requests will be distributed among all its IPs, using the default load balance algorithm. Authentication service accepts HTTPS connection, TCP port `8443` and root path are used. SNI extension and Host header are added to the request.
* `auth-url: "svc://auth-cluster:8443/auth"`: A service named `auth-cluster` will be used as the destination of the request, service port `8443` and path `/auth`. The service can be annotated with Backend and Path scoped configuration keys, eg [`secure-backends`](#secure-backend) to provide a secure connection.

**Forwarding headers**

There are three distinct configurations to forward header names:

* `auth-headers-request`: headers from the client to the authentication service.
* `auth-headers-succeed`: headers from the authentication service to the backend server.
* `auth-headers-fail`: headers from the authentication service to the client.

The first option will always be used, the second one only on succeeded requests, the last one only on failures.

These configuration keys can be defined as a comma-separated list of header names. All HTTP headers will be copied if not declared. Each header name can use wildcard. Using a dash `-` or an empty string instructs the controller not to copy any header.

Configuration examples:

* `auth-headers-request: "X-*"`: copy only headers started with `X-` from the client to the authentication service. All headers provided by the authentication service will be copied to the backend server if the authentication succeed, or to the client if the authentication fail.
* `auth-headers-request: "X-*"` and `auth-headers-succeed: "X-Token,X-User-*"`: just like the config above, copy only headers started with `X-` from the client to the authentication service. If the request succeed, headers started with `X-User-` and also the header `X-Token` is copied to the backend server. If the request fail, all the provided headers are copied from the authentication server to the client.

**Dependencies and port range**

HAProxy Ingress uses [`auth-request.lua`](https://github.com/TimWolla/haproxy-auth-request) script, which in turn uses HAProxy Technologies' [`haproxy-lua-http`](https://github.com/haproxytech/haproxy-lua-http/) to perform the authentication request and wait for the response. The request is managed by an internal haproxy frontend/backend pair, which can be fine tuned with `auth-proxy`. The default value is `_front__auth:14415-14499`: `_front__auth` is the name of the frontend helper and `14415-14499` is an [unassigned TCP port range](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) that `haproxy-lua-http` uses to connect and send the authentication request. Requests to this proxy can be added to the log, see [`auth-log-format`](#log-format") configuration key.

{{< alert title="Note" >}}
Auth External needs [`external-has-lua`](#external) enabled if running on an external haproxy deployment. The external haproxy needs Lua json module installed (Alpine's `lua-json4` package)
{{< /alert >}}

See also:

* [Auth TLS](#auth-tls) configuration keys
* [OAuth](#oauth) configuration keys
* [`external-has-lua`](#external) configuration key.

---

### Auth TLS

| Configuration key           | Scope     | Default | Since  |
|-----------------------------|-----------|---------|--------|
| `auth-tls-cert-header`      | `Backend` | `false` |        |
| `auth-tls-error-page`       | `Host`    |         |        |
| `auth-tls-secret`           | `Host`    |         |        |
| `auth-tls-strict`           | `Host`    | `true`  | v0.8.1 |
| `auth-tls-verify-client`    | `Host`    |         |        |
| `ssl-fingerprint-lower`     | `Backend` | `false` | v0.10  |
| `ssl-fingerprint-sha2-bits` | `Backend` |         | v0.14  |
| `ssl-headers-prefix`        | `Global`  | `X-SSL` |        |

Configure client authentication with X509 certificate. The following headers are
added to the request:

* `X-SSL-Client-SHA1`: Hex encoding of the SHA-1 fingerprint of the X509 certificate. The default output uses uppercase hexadecimal digits, configure `ssl-fingerprint-lower` to `true` to use lowercase digits instead.
* `X-SSL-Client-DN`: Distinguished name of the certificate
* `X-SSL-Client-CN`: Common name of the certificate

These headers can also be added depending on the configuration:

* `X-SSL-Client-SHA2`: Only if `ssl-fingerprint-sha2-bits` is declared. Hex encoding of the SHA-2 fingerprint of the X509 certificate. Valid `ssl-fingerprint-sha2-bits` values are `224`, `256`, `384` or `512`. The default output uses uppercase hexadecimal digits, configure `ssl-fingerprint-lower` to `true` to use lowercase digits instead.
* `X-SSL-Client-Cert`: Only if `auth-tls-cert-header` is `true`. Base64 encoding of the X509 certificate in DER format.

The prefix of the header names can be configured with `ssl-headers-prefix` key.
The default value is to `X-SSL`, which will create a `X-SSL-Client-DN` header with
the DN of the certificate.

The following keys are supported:

* `auth-tls-cert-header`: If `true` HAProxy will add `X-SSL-Client-Cert` http header with a base64 encoding of the X509 certificate provided by the client. Default is to not provide the client certificate.
* `auth-tls-error-page`: Optional URL of the page to redirect the user if he doesn't provide a certificate or the certificate is invalid.
* `auth-tls-secret`: Mandatory secret name with `ca.crt` key providing all certificate authority bundles used to validate client certificates. Since v0.9, an optional `ca.crl` key can also provide a CRL in PEM format for the server to verify against. A filename prefixed with `file://` can be used containing the CA bundle in PEM format, and optionally followed by a comma and the filename with the crl, eg `file:///dir/ca.pem` or `file:///dir/ca.pem,/dir/crl.pem`.
* `auth-tls-strict`: Defines if a wrong or incomplete configuration, eg missing secret with `ca.crt`, should forbid connection attempts. If `false`, a wrong or incomplete configuration will ignore the authentication config, allowing anonymous connection. If `true`, a strict configuration is used: all requests will be rejected with HTTP 495 or 496, or redirected to the error page if configured, until a proper `ca.crt` is provided. Strict configuration will only be used if `auth-tls-secret` has a secret name and `auth-tls-verify-client` is missing or is not configured as `off`. This options used to have `false` as the default value up to v0.13, changing its default to `true` since v0.14 to improve security.
* `auth-tls-verify-client`: Optional configuration of Client Verification behavior. Supported values are `off`, `on`, `optional` and `optional_no_ca`. The default value is `on` if a valid secret is provided, `off` otherwise. `optional` makes the certificate optional but validates it when provided by the client. From v0.8 to v0.13 controller versions, `optional_no_ca` used to validate the certificate as well, since v0.14 it makes the proxy bypass any validation.
* `ssl-fingerprint-lower`: Defines if the certificate fingerprint should be in lowercase hexadecimal digits. The default value is `false`, which uses uppercase digits.
* `ssl-fingerprint-sha2-bits`: Defines the number of bits of the SHA-2 fingerprint of the client certificate. Valid values are `224`, `256`, `384` or `512`. The header `X-SSL-Client-SHA2` will only be added if this option is declared.
* `ssl-headers-prefix`: Configures which prefix should be used on HTTP headers. Since [RFC 6648](https://tools.ietf.org/html/rfc6648) `X-` prefix on unstandardized headers changed from a convention to deprecation. This configuration allows to select which pattern should be used on header names.

See also:

* [example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/auth/client-certs) page.

---

### Backend protocol

| Configuration key  | Scope     | Default | Since |
|--------------------|-----------|---------|-------|
| `backend-protocol` | `Backend` | `h1`    | v0.9  |

Defines the HTTP protocol version of the backend. Note that HTTP/2 is only supported if HTX is enabled.
A case-insensitive match is used, so either `h1` or `H1` configures HTTP/1 protocol. A non SSL/TLS
configuration does not overrides [secure-backends](#secure-backend), so `h1` and secure-backends `true`
will still configure SSL/TLS.

Options:

* `h1`: the default value, configures HTTP/1 protocol. `http` is an alias to `h1`.
* `h1-ssl`: configures HTTP/1 over SSL/TLS. `https` is an alias to `h1-ssl`.
* `h2`: configures HTTP/2 protocol. `grpc` is an alias to `h2`.
* `h2-ssl`: configures HTTP/2 over SSL/TLS. `grpcs` is an alias to `h2-ssl`.
* `fcgi`: since v0.16 - configures FastCGI protocol.
* `fcgi-ssl`: since v0.16 - configures FastCGI over SSL/TLS.

FastCGI protocol needs a reference to valid haproxy's fcgi-app section via [`fcgi-app`](#fastcgi) configuration key, either inheriting from the global ConfigMap or via annotation.

See also:

* [use-htx](#use-htx) configuration key to enable HTTP/2 backends.
* [secure-backend](#secure-backend) configuration keys to configure optional client certificate and certificate authority bundle of SSL/TLS connections.
* [FastCGI](#fastcgi) configuration keys.
* https://docs.haproxy.org/2.8/configuration.html#5.2-proto

---

### Backend server naming

| Configuration key       | Scope     | Default    | Since    |
|-------------------------|-----------|------------|----------|
| `backend-server-naming` | `Backend` | `sequence` | `v0.8.1` |

Configures how to name backend servers.

* `sequence`: Names backend servers with a prefixed number sequence: `srv001`, `srv002`, and so on. This is the default configuration and the preferred option if dynamic update is used. `seq` is an alias to `sequence`.
* `pod`: Uses the k8s pod name as the backend server name. This option doesn't work on backends whose [`service-upstream`](#service-upstream) is `true`, falling back to `sequence`.
* `ip`: Uses target's `<ip>:<port>` as the server name.

{{< alert title="Note" >}}
HAProxy Ingress won't refuse to change the default naming if dynamic update is `true`, this would however lead to undesired behaviour: empty slots would still be named as sequences, old-named backend servers will dynamically receive new workloads with new pod names or IP numbers which do not relate with the name anymore, making the naming useless, if not wrong. If you have [cookie affinity](#affinity) enabled, dynamic updating can cause the cookie values to get out of sync with the servers. This can be avoided by using `session-cookie-preserve` with a value of `true`.
{{< /alert >}}

---

### Backend server ID

| Configuration key          | Scope     | Default | Since   |
|----------------------------|-----------|---------|---------|
| `assign-backend-server-id` | `Backend` | `false` | `v0.13` |

When `true`, each backend server will receive an `id` in HAProxy config based on the Kubernetes UID of the pod backing it. When using a hash-based [`balance-algorithm`](#balance-algorithm) (for example `uri` or `source`) together with consistent hashing, this will maintain the stability of assignments when pods are added or removed — that is, a given URI component or source IP will mostly keep hashing to the same server. When this setting is `false`, an addition or deletion in the server list may disturb the hash assignments of some or all of the remaining servers.

Server IDs can't dynamically updated, so if this option is enabled, adding or removing a server will cause a reload even when [`dynamic-scaling`](#dynamic-scaling) is true.

---

### Balance algorithm

| Configuration key   | Scope     | Default     | Since |
|---------------------|-----------|-------------|-------|
| `balance-algorithm` | `Backend` | `random(2)` |       |

Defines a valid HAProxy load balancing algorithm. Since v0.16 the default value is `random(2)`, also known as the Power of Two Random Choices.

See also:

* https://docs.haproxy.org/2.8/configuration.html#4-balance
* https://www.mail-archive.com/haproxy@formilux.org/msg46011.html
* https://www.eecs.harvard.edu/~michaelm/postscripts/handbook2001.pdf

---

### Bind

| Configuration key      | Scope      | Default | Since |
|------------------------|------------|---------|-------|
| `bind-fronting-proxy`  | `Frontend` |         | v0.8  |
| `bind-http`            | `Frontend` |         | v0.8  |
| `bind-https`           | `Frontend` |         | v0.8  |

Configures listening IP and port for HTTP/s incoming requests. These
configuration keys have backward compatibility with [Bind IP addr](#bind-ip-addr),
[Bind port](#bind-port) and [Fronting proxy](#fronting-proxy-port) keys.
The bind configuration keys in this section have precedence if declared.

Any HAProxy supported option can be used, this will be copied verbatim to the
bind keyword. See HAProxy
[bind keyword doc](#https://docs.haproxy.org/2.8/configuration.html#4-bind).

Configuration examples:

* `bind-http: ":::80"` and `bind-https: ":::443"`: Listen all IPv6 addresses
* `bind-http: ":80,:::80"` and `bind-https:  ":443,:::443"`: Listen all IPv4 and IPv6 addresses
* `bind-https: ":443,:8443"`: accept https connections on `443` and also `8443` port numbers

{{< alert title="Note" >}}
Since v0.17, `bind-fronting-proxy` and `bind-http` cannot share neither the same frontend nor the same TCP port anymore.
{{< /alert >}}

{{< alert title="Warning" color="warning" >}}
Special care should be taken on port number overlap, neither haproxy itself nor haproxy-ingress will warn if the same port number is used on more than one configuration key. Moreover, although it is possible to configure a binding address completely unrelated with the configured `http-port` or `https-port`, the suggestion is that both configurations match somehow.
{{< /alert >}}

See also:

* https://docs.haproxy.org/2.8/configuration.html#4-bind
* [Bind IP addr](#bind-ip-addr)
* [Bind port](#bind-port)

---

### Bind IP addr

| Configuration key         | Scope      | Default | Since |
|---------------------------|------------|---------|-------|
| `bind-ip-addr-healthz`    | `Global`   |         |       |
| `bind-ip-addr-http`       | `Frontend` |         |       |
| `bind-ip-addr-prometheus` | `Global`   |         | v0.10 |
| `bind-ip-addr-stats`      | `Global`   |         |       |
| `bind-ip-addr-tcp`        | `Global`   |         |       |

Define listening IPv4/IPv6 address on public HAProxy frontends. Since v0.10 the default
value changed from `*` to an empty string, which haproxy interprets in the same way and
binds on all IPv4 address.

* `bind-ip-addr-tcp`: IP address of all ConfigMap based TCP services declared on [`tcp-services-configmap`]({{% relref "command-line#tcp-services-configmap" %}}) command-line option.
* `bind-ip-addr-healthz`: IP address of the health check URL.
* `bind-ip-addr-http`: IP address of HTTP/s frontends.
* `bind-ip-addr-prometheus`: IP address of the haproxy's internal Prometheus exporter.
* `bind-ip-addr-stats`: IP address of the statistics page. See also [`stats-port`](#stats).

See also:

* https://docs.haproxy.org/2.8/configuration.html#4-bind
* [Bind](#bind)
* [Bind port](#bind-port)

---

### Bind port

| Configuration key | Scope      | Default | Since |
|-------------------|------------|---------|-------|
| `healthz-port`    | `Global`   | `10253` |       |
| `http-port`       | `Frontend` | `80`    |       |
| `https-port`      | `Frontend` | `443`   |       |
| `prometheus-port` | `Global`   |         | v0.10 |

* `healthz-port`: Define the port number HAProxy should listen to in order to answer for health checking requests. Use `/healthz` as the request path.
* `http-port`: Define the port number of unencrypted HTTP connections.
* `https-port`: Define the port number of encrypted HTTPS connections.
* `prometheus-port`: Define the port number of the haproxy's internal Prometheus exporter. Defaults to not create the listener. A listener without being scraped does not use system resources, except for the listening port. The internal exporter supports scope filter as a query string, eg `/metrics?scope=frontend&scope=backend` will only export frontends and backends. See the full description in the [HAProxy's Prometheus exporter doc](https://git.haproxy.org/?p=haproxy-2.0.git;a=blob;f=contrib/prometheus-exporter/README;hb=HEAD).

{{< alert title="Note" >}}
The internal Prometheus exporter runs concurrently with request processing, and it is
about 5x slower and 20x more verbose than the CSV exporter. See the haproxy's exporter
[doc](https://github.com/haproxy/haproxy/blob/v2.0.0/contrib/prometheus-exporter/README#L44).
Consider use Prometheus' [haproxy_exporter](https://github.com/prometheus/haproxy_exporter)
on very large clusters - Prometheus' implementation reads the CSV from the stats page and
converts to the Prometheus syntax outside the haproxy process. On the other side the internal
exporter supports scope filtering, which should make at least the processing time between csv
and prometheus exporter very close if servers are filtered out. Make your own tests before
choosing between one or the other.
{{< /alert >}}

See also:

* [Bind](#bind) configuration key
* https://docs.haproxy.org/2.8/configuration.html#4-monitor-uri (`healthz-port`)
* https://git.haproxy.org/?p=haproxy-2.0.git;a=blob;f=contrib/prometheus-exporter/README;hb=HEAD (`prometheus-port`)

---

### Blue-green

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
* https://docs.haproxy.org/2.8/configuration.html#5.2-weight (`weight` based balance)
* https://docs.haproxy.org/2.8/configuration.html#4-use-server (`use-server` based selector)

---

### Close sessions duration

| Configuration key         | Scope    | Default  | Since |
|---------------------------|----------|----------|-------|
| `close-sessions-duration` | `Global` |          | v0.14 |

Defines the amount of time used to close active sessions before a stopping instance times out
and terminates. A stopping instance is an haproxy that doesn't listen sockets anymore, has an
old configuration, and it's just waiting remaining connections to terminate.

Long lived sessions, like websockets or TCP connections, are usually closed only when the
`timeout-stop` of the old instance expires. Depending on how the clients are configured,
all the disconnected clients will reconnect almost at the same time. `close-sessions-duration`
configures the amount of time used to fairly distribute the sessions shutdown, so distributing
client reconnections to the new HAProxy instance.

The default behavior is to not anticipate the disconnections, so all the active sessions will
be closed at the same time when `timeout-stop` expires. `close-sessions-duration` will only
take effect if `timeout-stop` configuration key and `--track-old-instances` command-line option
are also configured.

The duration needs a suffix, which can be a time suffix like `s` (seconds), `m` (minutes) or
`h` (hours), or a `%` that represents a percentage of the `timeout-stop` configuration:

* `10m` means that the last 10 minutes of the `timeout-stop` will be used to distribute sessions shutdown
* `10%` and a `timeout-stop` of `1h`, means that the last 6 minutes of the `timeout-stop` will be used to distribute sessions shutdown

If the suffix is a time unit, the resulting value should be lower than the `timeout-stop`
configuration. If the suffix is a percentage, the value should be between `2%` and `98%`.

See also:

* [`track-old-instances`]({{% relref "command-line#track-old-instances" %}}) command-line option
* [`timeout-stop`](#timeout) configuration key

---

### Configuration snippet

| Configuration key       | Scope     | Default  | Since |
|-------------------------|-----------|----------|-------|
| `config-backend`        | `Backend` |          |       |
| `config-backend-early`  | `Backend` |          | v0.16 |
| `config-backend-late`   | `Backend` |          | v0.16 |
| `config-defaults`       | `Global`  |          | v0.8  |
| `config-frontend`       | `Global`  |          |       |
| `config-frontend-early` | `Global`  |          | v0.14 |
| `config-frontend-late`  | `Global`  |          | v0.14 |
| `config-global`         | `Global`  |          |       |
| `config-peers`          | `Global`  |          | v0.16 |
| `config-proxy`          | `Global`  |          | v0.13 |
| `config-sections`       | `Global`  |          | v0.13 |
| `config-tcp`            | `Global`  |          | v0.13 |
| `config-tcp-service`    | `TCP`     |          | v0.13 |

Add HAProxy configuration snippet to the configuration file. Use multiline content
to add more than one line of configuration.

* `config-backend`: Adds a configuration snippet to a HAProxy backend section, alias for `config-backend-late`.
* `config-backend-early`: Adds a configuration snippet to a HAProxy backend section, before any builtin logic.
* `config-backend-late`: Adds a configuration snippet to a HAProxy backend section, same as `config-backend`.
* `config-defaults`: Adds a configuration snippet to the end of the HAProxy defaults section.
* `config-frontend`: Adds a configuration snippet to the HTTP and HTTPS frontend sections, alias for `config-frontend-late`.
* `config-frontend-early`: Adds a configuration snippet to the HTTP and HTTPS frontend sections, before any builtin logic.
* `config-frontend-late`: Adds a configuration snippet to the HTTP and HTTPS frontend sections, same as `config-frontend`.
* `config-global`: Adds a configuration snippet to the end of the HAProxy global section.
* `config-peers`: Adds a configuration snippet to the Peers section.
* `config-proxy`: Adds a configuration snippet to any HAProxy proxy - listen, frontend or backend. It accepts a multi section configuration, where the name of the section is the name of a HAProxy proxy without the listen/frontend/backend prefix. A section whose proxy is not found is ignored. The content of each section should be indented, the first line without indentation is the start of a new section which will configure another proxy.
* `config-sections`: Allows to declare new HAProxy sections. The configuration is used verbatim, without any indentation or validation.
* `config-tcp`: Adds a configuration snippet to the ConfigMap based TCP sections.
* `config-tcp-service`: Adds a configuration snippet to a TCP service section.

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
    config-tcp: |
      tcp-request content reject if !{ src 10.0.0.0/8 }
```

```yaml
    config-peers: |
      log stdout format raw local0
```

```yaml
    config-proxy: |
      _tcp_default_postgresql_5432
          tcp-request content reject if !{ src 10.0.0.0/8 }
      _front__tls
          tcp-request content reject if !{ src 10.0.0.0/8 } { req.ssl_sni -m reg ^intra\..* }
```

```yaml
    config-sections: |
      cache icons
          total-max-size 4
          max-age 240
      ring myring
          format rfc3164
          maxlen 1200
          size 32764
          timeout connect 5s
          timeout server 10s
          server syslogsrv 127.0.0.1:6514 log-proto octet-count
```

```yaml
    config-frontend: |
      capture request header X-User-Id len 32
```

```yaml
    config-frontend-early: |
      tcp-request connection reject if !{ src 10.0.0.0/8 }
```

```yaml
    config-frontend-late: |
      capture request header X-User-Id len 32
```

Annotations:

```yaml
    annotations:
      haproxy-ingress.github.io/config-backend: |
        acl bar-url path /bar
        http-request deny if bar-url
        http-request set-var(txn.path) path
        http-request cache-use icons if { var(txn.path) -m end .ico }
        http-response cache-store icons if { var(txn.path) -m end .ico }
```

```yaml
    annotations:
      haproxy-ingress.github.io/config-backend-early: |
        stick-table type ip size 100k expire 1m store http_req_rate(10s)
        http-request track-sc1 src
        http-request deny if { sc1_http_req_rate gt 100 } # average of 10rps per source IP, over the last 10s
```

```yaml
    annotations:
      haproxy-ingress.github.io/config-backend-late: |
        http-request deny if { path /internal }
```

```yaml
    annotations:
      haproxy-ingress.github.io/config-tcp-service: |
        timeout client 1m
        timeout connect 15s
```

---

### Connection

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `max-connections` | `Global`  | `2000`  |       |
| `maxconn-server`  | `Backend` |         |       |
| `maxqueue-server` | `Backend` |         |       |

Configuration of connection limits.

* `max-connections`: Define the maximum concurrent connections on all proxies. Defaults to `2000` connections, which is also the HAProxy default configuration.
* `maxconn-server`: Defines the maximum concurrent connections each server of a backend should receive. If not specified or a value lesser than or equal zero is used, an unlimited number of connections will be allowed. When the limit is reached, new connections will wait on a queue.
* `maxqueue-server`: Defines the maximum number of connections should wait in the queue of a server. When this number is reached, new requests will be redispatched to another server, breaking sticky session if configured. The queue will be unlimited if the annotation is not specified or a value lesser than or equal to zero is used.

See also:

* https://docs.haproxy.org/2.8/configuration.html#3.2-maxconn (`max-connections`)
* https://docs.haproxy.org/2.8/configuration.html#5.2-maxconn (`maxconn-server`)
* https://docs.haproxy.org/2.8/configuration.html#5.2-maxqueue (`maxqueue-server`)

---

### CORS

| Configuration key        | Scope  | Default      | Since |
|--------------------------|--------|--------------|-------|
| `cors-allow-credentials` | `Path` | `true`       |       |
| `cors-allow-headers`     | `Path` | *see below*  |       |
| `cors-allow-methods`     | `Path` | *see below*  |       |
| `cors-allow-origin`      | `Path` | `*`          |       |
| `cors-allow-origin-regex`| `Path` |              |       |
| `cors-enable`            | `Path` | `false`      |       |
| `cors-expose-headers`    | `Path` |              | v0.8  |
| `cors-max-age`           | `Path` | `86400`      |       |

Add CORS headers on OPTIONS http command (preflight) and reponses.

* `cors-enable`: Enable CORS if defined as `true`.
* `cors-allow-origin`: Optional, configures `Access-Control-Allow-Origin` header which defines the URL that may access the resource. Defaults to `*`. This option accepts a comma-separated list of origins, the response will be dynamically built based on the `Origin` request header. If `Origin` belongs to the list, its content will be sent back to the client in the `Access-Control-Allow-Origin` header; otherwise, the first item of the list will be used.
* `cors-allow-origin-regex`: Optional, like `cors-allow-origin` but with regex matching. Defaults to empty. This option accepts a space-separated list of origin regexes, the response will be dynamically built based on the `Origin` request header. If `Origin` matches any regex in the list, its content will be sent back to the client in the `Access-Control-Allow-Origin` header; otherwise, `cors-allow-origin` will be considered. This is why you **must also set** `cors-allow-origin` (probably to something other than `*`) when using this option.
* `cors-allow-methods`: Optional, configures `Access-Control-Allow-Methods` header which defines the allowed methods. Default value is `GET, PUT, POST, DELETE, PATCH, OPTIONS`.
* `cors-allow-headers`: Optional, configures `Access-Control-Allow-Headers` header which defines the allowed headers. Default value is `DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization`.
* `cors-allow-credentials`: Optional, configures `Access-Control-Allow-Credentials` header which defines whether or not credentials (cookies, authorization headers or client certificates) should be exposed. Defaults to `true`.
* `cors-max-age`: Optional, configures `Access-Control-Max-Age` header which defines the time in seconds the result should be cached. Defaults to `86400` (1 day).
* `cors-expose-headers`: Optional, configures `Access-Control-Expose-Headers` header which defines what headers are allowed to be passed through to the CORS application. Defaults to not add the header.

See also:

* https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

---

### CPU map

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `cpu-map`         | `Global` |         |       |
| `use-cpu-map`     | `Global` | `true`  |       |

Define how processes/threads map to CPUs. The default value is generated based
on [nbthread](#nbthread) and [nbproc](#nbproc).

* `cpu-map`: Custom override specifying the [cpu mapping behaviour](https://docs.haproxy.org/2.8/configuration.html#3.1-cpu-map).
* `use-cpu-map`: Set to `false` to prevent any cpu mapping

See also:

* [nbthread](#nbthread) configuration key
* [nbproc](#nbproc) configuration key
* https://docs.haproxy.org/2.8/configuration.html#3.1-cpu-map

---

### Cross Namespace

| Configuration key                | Scope    | Default | Since |
|----------------------------------|----------|---------|-------|
| `cross-namespace-secrets-ca`     | `Global` | `deny`  | v0.13 |
| `cross-namespace-secrets-crt`    | `Global` | `deny`  | v0.13 |
| `cross-namespace-secrets-passwd` | `Global` | `deny`  | v0.13 |
| `cross-namespace-services`       | `Global` | `deny`  | v0.13 |

Defines if resources declared on a namespace can read resources declared on another namespace. Supported values are `allow` or `deny`. The default configuration denies access from all cross namespace access.

* `cross-namespace-secrets-ca`: Allows or denies cross namespace reading of CA bundles and CRL files, used by [`auth-tls-secret`](#auth-tls) and [`secure-verify-ca-secret`](#secure-backend) configuration keys.
* `cross-namespace-secrets-crt`: Allows or denies cross namespace reading of x509 certificates and private keys, used by gateway's, httpRoute's and ingress' tls attribute, and also [`secure-crt-secret`](#secure-backend) configuration key.
* `cross-namespace-secrets-passwd`: Allows or denies cross namespace reading of password files, used by [`auth-secret`](#auth-basic) configuration key.
* `cross-namespace-services`: Allows or denies cross namespace reading of Kubernetes Service resources, used by [`auth-url`](#auth-external) configuration key.

{{< alert title="Note" >}}
[`--allow-cross-namespace`]({{% relref "command-line#allow-cross-namespace" %}}) command-line option, if declared, overrides all the secret related configuration keys.
{{< /alert >}}

---

### Default Redirect

| Configuration key                | Scope    | Default | Since |
|----------------------------------|----------|---------|-------|
| `default-backend-redirect`       | `Global` |         |       |
| `default-backend-redirect-code`  | `Global` | `302`   |       |

Define a redirect location of the HAProxy for unknown resources.

* `default-backend-redirect`: Defines a location in which Ingress should redirect
an user if the incoming request doesn't match any hostname, or the requested path
doesn't match any location within the desired hostname. An internal
404 error page is used if not declared and also if `default-backend-service` was
not configured on command line.

* `default-backend-redirect-code`: Defines the return code to be used when redirecting
a user. Defaults to 302 (Moved Temporarily)

---

### DNS resolvers

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

{{< alert title="Important advices" >}}
* Use resolver with **headless** services, see [k8s doc](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services); otherwise, HAProxy will reference the service IP instead of the endpoints.
* Beware of DNS cache, eg kube-dns has `--max-ttl` and `--max-cache-ttl` to change its default cache of `30s`.
{{< /alert >}}

See also:

* [example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/dns-service-discovery) page.
* https://docs.haproxy.org/2.8/configuration.html#5.3.2
* https://docs.haproxy.org/2.8/configuration.html#5.2-resolvers
* https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
* https://kubernetes.io/docs/concepts/services-networking/service/#headless-services

---

### Drain support

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

### Dynamic scaling

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

* https://docs.haproxy.org/2.8/management.html#9.3

---

### External

| Configuration key  | Scope    | Default | Since |
|--------------------|----------|---------|-------|
| `external-has-lua` | `Global` | `false` | v0.12 |

Defines features that can be found in the external haproxy deployment, if an
external deployment is used. These options have no effect if using the embedded
haproxy.

* `external-has-lua`: Define as true if the external haproxy has Lua libraries
installed in the operating system. Currently [Auth External](#auth-external)
and [OAuth](#oauth) need Lua json module installed (Alpine's `lua-json4`
package) and will not work if `external-has-lua` is not enabled.

See also:

* [Auth External](#auth-external) configuration keys.
* [OAuth](#oauth) configuration keys.
* [master-socket]({{% relref "command-line#master-socket" %}}) command-line option

---

### FastCGI

| Configuration key   | Scope     | Default | Since |
|---------------------|-----------|---------|-------|
| `fcgi-app`          | `Backend` |         | v0.16 |
| `fcgi-enabled-apps` | `Global`  | `*`     | v0.16 |

Configures FastCGI applications.

* `fcgi-enabled-apps`: Comma separated list of haproxy's fcgi-app sections already declared via `config-sections` configuration key. Only these app identifiers are allowed to be used by backends. If ommited, defaults to allow all configured fcgi-app sections.
* `fcgi-app`: Defines the haproxy's fcgi-app section a backend should use. It must be one of the apps in `fcgi-enabled-apps` if configured, or any of the declared ones in `config-sections` otherwise. `fcgi-app` is a mandatory configuration if fcgi server protocol is used, either declaring as an annotation along with the protocol itself, or as a global configuration that should be inherited by all FastCGI backends.

FastCGI related configurations are only used on backends whose server protocol is configured as fcgi, they are ignored otherwise.

Currently there is no helper to configure the haproxy's fcgi-app section, it should be done via the global [`config-sections`](#configuration-snippet) configuration key. Configure as much fcgi-app sections as needed in the same key. See an example below:

```yaml
    config-sections: |
      fcgi-app app1
          log-stderr global
          docroot /var/www/app1
          index index.php
      fcgi-app app2
          log-stderr global
          docroot /var/www/app2
          index index.php
      ... (other custom haproxy sections)
```

See also:

* [`backend-protocol`](#backend-protocol) configuration key.
* https://docs.haproxy.org/2.8/configuration.html#10

---

### Forwardfor

| Configuration key            | Scope     | Default                    | Since   |
|------------------------------|-----------|----------------------------|---------|
| `forwardfor`                 | `Global`  | `add`                      |         |
| `original-forwarded-for-hdr` | `Global`  | `X-Original-Forwarded-For` | `v0.15` |
| `real-ip-hdr`                | `Global`  | `X-Real-IP`                | `v0.15` |

Defines `X-Forwarded-For` header and source address handling.

* `forwardfor`: Defines how `X-Forwarded-For` header should be handled, options are `add`, `update`, `ignore` and `ifmissing`. See details below.
* `original-forwarded-for-hdr`: Defines a header name for the original `X-Forwarded-For` header value, if present. Defaults to `X-Original-Forwarded-For` header, and an empty string disables this header declaration.
* `real-ip-hdr`: Defines a header name that should receive the source IP address, despite of any `X-Forwarded-For` configuration. Defaults to `X-Real-IP` header, and an empty string disables this header declaration.

`forwardfor` options:

* `add`: haproxy should generate a `X-Forwarded-For` header with the source IP address. This is the default option and should be used on untrusted networks.
* `update`: haproxy should preserve any `X-Forwarded-For` header, if provided, updating with the source IP address, which should be a fronting TCP or HTTP proxy/load balancer.
* `ignore`: Do nothing - only send the `X-Forwarded-For` header if the client provided one, without updating its content.
* `ifmissing`: Add `X-Forwarded-For` header only if the incoming request doesn't provide one.

See also:

* https://docs.haproxy.org/2.8/configuration.html#4-option%20forwardfor
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For

---

### Fronting proxy port

| Configuration key     | Scope      | Default | Since   |
|-----------------------|------------|---------|---------|
| `fronting-proxy-port` | `Frontend` |         | `v0.8`  |
| `https-to-http-port`  | `Frontend` |         |         |
| `use-forwarded-proto` | `Frontend` | `true`  | `v0.10` |

Configures HAProxy Ingress to accept plain HTTP requests from a fronting load balancer doing the SSL offload.

* `fronting-proxy-port`: configures the port number that should accept the HTTP requests. This configuration was allowed to collide with `http-port` up to v0.16, but since v0.17 fronting-proxy is a flag to the whole frontend. Configure distinct frontends to support both regular HTTP and Fronting Proxy requests on the same deployment, and the port number cannot collide anymore.
* `use-forwarded-proto`: if `true`, the default value, configures HAProxy to redirect the request to https if the `X-Forwarded-Proto` header is not `https`. If `false`, `X-Forwarded-Proto` header is ignored and passed as is to the backend.
* `https-to-http-port`: old and deprecated key, now an alias to `fronting-proxy-port`.

HAProxy Ingress has a few differences on HTTP and HTTPS configurations, like, redirect from HTTP if `ssl-redirect` is `true`, add HSTS headers (when configured) only on HTTPS responses, and drop incoming `X-SSL-*` headers for security reasons. Configuring a fronting proxy port makes HAProxy Ingress to have HTTPS behavior over HTTP connection, allowing a fronting load balancer to SSL offload the TLS requests, talking plain HTTP with HAProxy.

{{< alert title="Security warning" color="warning" >}}
This option must only be used if the network from the fronting load balancer and the ingress nodes is trusted, since the communication happens on plain HTTP, and all the communication is visible via tools like tcpdump. Give also the configured port a special attention and block it from external access: an user can easily add the `X-SSL-*` headers, authenticating itself as any user on applications using mTLS.
{{< /alert >}}

See also:

* [Bind](#bind)

### Headers

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
      haproxy-ingress.github.io/headers: |
        x-path: /
        host: %[service].%[namespace].svc.cluster.local
```

---

### Health check

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

* https://docs.haproxy.org/2.8/configuration.html#4.2-option%20httpchk
* https://docs.haproxy.org/2.8/configuration.html#5.2-addr
* https://docs.haproxy.org/2.8/configuration.html#5.2-port
* https://docs.haproxy.org/2.8/configuration.html#5.2-inter
* https://docs.haproxy.org/2.8/configuration.html#5.2-rise
* https://docs.haproxy.org/2.8/configuration.html#5.2-fall

---

### HSTS

| Configuration key         | Scope  | Default    | Since |
|---------------------------|--------|------------|-------|
| `hsts`                    | `Path` | `true`     |       |
| `hsts-include-subdomains` | `Path` | `false`    |       |
| `hsts-max-age`            | `Path` | `15768000` |       |
| `hsts-preload`            | `Path` | `false`    |       |

Configure HSTS - HTTP Strict Transport Security. The following keys are supported:

* `hsts`: `true` if HSTS response header should be added
* `hsts-include-subdomains`: `true` if it should apply to subdomains as well
* `hsts-max-age`: time in seconds the browser should remember this configuration
* `hsts-preload`: `true` if the browser should include the domain to [HSTS preload list](https://hstspreload.org/)

See also:

* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security

---

### HTTP Match

| Configuration key               | Scope    | Default | Since |
|---------------------------------|----------|---------|-------|
| `http-header-match`             | `Path`   |         | v0.15 |
| `http-header-match-regex`       | `Path`   |         | v0.15 |

Add HTTP constraints for request routing.

* `http-header-match`: Add HTTP header with exact match, one header name and value pair per line. The first white space, or colon followed by an optional white space, separates the header name and the match value. the header name is case-insensitive while the value is case-sensitive.
* `http-header-match-regex`: Same as `http-header-match` but using regex match. Anchors are not added, so the value `bar` would match with `foobar` and `barbaz`, while `^bar` would only match with `barbaz`.

More than one annotation can be used at the same time, and more than one match can be used in the same annotation. All the matches from all the annotations will be grouped together, and all of them must evaluate to true in order to the request be accepted and sent to the backend.

Note that any match that potentially changes the backend of a request, like HTTP match, must be running in the HAProxy frontend, so earlier than most of other matching rules. External authentication is an example. See [`auth-external-placement`](#auth-external) configuration key if using external authentication to provide headers to HTTP match rules.

**Examples**

Match the header `X-Env` with value `staging` - header name is case-insensitive, header value is case-sensitive:

```yaml
    annotations:
      haproxy-ingress.github.io/http-header-match: "X-Env: staging"
```

Match the header `X-Env` with value `staging`, and header `X-User` with value `admin`:

```yaml
    annotations:
      haproxy-ingress.github.io/http-header-match: |
        X-Env: staging
        X-User: admin
```

Match the header `X-Env` with value that matches the regex `^(test|staging)$`:

```yaml
    annotations:
      haproxy-ingress.github.io/http-header-match-regex: |
        X-Env: ^(test|staging)$
```

See also:

* [`auth-external-placement`](#auth-external) configuration key

---

### HTTP Response

| Configuration key               | Scope    | Default | Since |
|---------------------------------|----------|---------|-------|
| `http-response-<code>`          | vary     |         | v0.14 |
| `http-response-prometheus-root` | `Global` |         | v0.14 |

Overwrites the default response payload for all the HAProxy's generated HTTP responses.

* `http-response-<code>`: Represents all the payload of HAProxy or HAProxy Ingress generated HTTP responses. Used to be a global option up to v0.15, since v0.16 their scope vary depending on the status code. Change `<code>` to one of the supported HTTP status code. See Supported codes below.
* `http-response-prometheus-root`: Response used on requests sent to the root context of the prometheus exporter port.

**Supported codes**

The following list has all the HTTP status codes supported by the controller, as well as the scope it is applied:

{{< alert title="Note" >}}
All the overwrites refer to HAProxy or HAProxy Ingress generated responses, e.g. a 403 response overwrite will not change a 403 response generated by a backend server, but instead only 403 responses that HAProxy generates itself, such as when an allow list rule denies a request to reach a backend server.
{{< /alert >}}

> All descriptions with `[haproxy]` refers to internal HAProxy responses, described in the [HAProxy documentation](https://docs.haproxy.org/2.8/configuration.html#1.3.1) or in the [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status). All the others are handled and issued by HAProxy Ingress configurations.

| Code  | Scope     | Reason | Description |
|-------|-----------|--------|-------------|
| `200` | `Backend` | OK | `[haproxy]` |
| `400` | `Backend` | Bad Request | `[haproxy]` |
| `401` | `Backend` | Unauthorized | `[haproxy]` |
| `403` | `Backend` | Forbidden | `[haproxy]` |
| `404` | `Global`  | Not Found | Request does not match a host and path, and neither `--default-backend-service`, nor ingress default backend or root path was configured. |
| `405` | `Backend` | Method Not Allowed | `[haproxy]` |
| `407` | `Backend` | Proxy Authentication Required | `[haproxy]` |
| `408` | `Backend` | Request Timeout | `[haproxy]` |
| `410` | `Backend` | Gone | `[haproxy]` |
| `413` | `Backend` | Payload Too Large | A request is bigger than specified in the `proxy-body-size` configuration key. |
| `421` | `Host`    | Misdirected Request | Incoming SNI was used to match a hostname and the Host header has a distinct value. |
| `425` | `Backend` | Too Early | `[haproxy]` |
| `429` | `Backend` | Too Many Requests | `[haproxy]` |
| `495` | `Host`    | SSL Certificate Error | An invalid certificate was used on a mTLS connection. |
| `496` | `Host`    | SSL Certificate Required | A certificate wasn't used on a mTLS connection but a certificate is mandatory. |
| `500` | `Backend` | Internal Server Error | `[haproxy]` |
| `501` | `Backend` | Not Implemented | `[haproxy]` |
| `502` | `Backend` | Bad Gateway | `[haproxy]` |
| `503` | `Backend` | Service Unavailable | `[haproxy]` |
| `504` | `Backend` | Gateway Timeout | `[haproxy]` |

**Syntax**

A multi-line configuration is used to customize the response payload on all the configuration keys:

* The very first line: Optional, the HTTP status code of the response, optionally followed by the status reason used on HTTP/1.1 responses. The default value is used if missing. Valid inputs are e.g. `404` or `404 Not Found`.
* Lines before the first empty line: Optional HTTP headers, one per line, whose name and value are separated by a colon `:`. It is recommended to always add `content-type` header. `content-length` is always calculated and should not be used.
* Lines after the first empty line: Optional HTTP body. It will be copied verbatim to a Lua script. Any char is allowed here except the `]==]` string which is reserved by the controller.

Some general hints about response overwriting:

* Do not create huge responses, the whole overwrite must fit into the internal buffer, which is 16k by default, leaving some room to configured downstream rules to operate. See [HAProxy's errorfile doc](https://docs.haproxy.org/2.8/configuration.html#4-errorfile).
* Take care with external links, e.g. the overwrite of a 503 error page might lead to another 503 error.
* Only add the status code line if changing the code; otherwise, let the controller configure with default values.
* A missing status code and status reason will lead to default values, but missing headers and missing body will lead to, respectively, only the `content-length` header and an empty body.
* Always add at least the HTTP header `content-type` with the correct value.
* The HTTP header `content-length` will be overwritten if used.

**Examples**

Change the payload type and content, using the default status code and status reason:

```yaml
  data:
    http-response-404: |
      content-type: text/plain
      connection: close

      404 not found
```

Overwrite the Status Code - always add the status reason (see [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)) if changing the status code:

```yaml
  data:
    http-response-404: |
      302 Found
      location: https://this.other.local
```

Response without header and with an empty body:

```yaml
  data:
    http-response-404: |
      404 Not Found
```

Response with the headers only:

```yaml
  data:
    http-response-404: |
      connection: close
```

Response with only the body - discouraged, at least the content-type should be added:

```yaml
  data:
    http-response-404: |

      not found
```

See also:

* [`--default-backend-service`]({{% relref "command-line#default-backend-service" %}}) command-line option
* [`proxy-body-size`](#proxy-body-size) configuration key
* [mTLS](#auth-tls) related configuration keys
* https://docs.haproxy.org/2.8/configuration.html#4-errorfile
* HAProxy's HTTP response at [HAProxy documentation](https://docs.haproxy.org/2.8/configuration.html#1.3.1)
* HTTP response status codes at [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

---

### Initial weight

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
* https://docs.haproxy.org/2.8/configuration.html#5.2-weight

---

### Limit

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

### Load server state

| Configuration key   | Scope    | Default | Since |
|---------------------|----------|---------|-------|
| `load-server-state` | `Global` | `false` |       |

Define if HAProxy should save and reload it's current state between server reloads, like
uptime of backends, qty of requests and so on.

This is an experimental feature and has currently some issues if using with `dynamic-scaling`:
an old state with disabled servers will disable them in the new configuration.

See also:

* https://docs.haproxy.org/2.8/configuration.html#3.1-server-state-file
* https://docs.haproxy.org/2.8/configuration.html#4-load-server-state-from-file

---

### Log format

| Configuration key        | Scope    | Default | Since |
|--------------------------|----------|---------|-------|
| `auth-log-format`        | `Global` |         | v0.13 |
| `http-log-format`        | `Global` |         |       |
| `https-log-format`       | `Global` |         |       |
| `tcp-log-format`         | `Global` |         |       |
| `tcp-service-log-format` | `TCP`    |         | v0.13 |

Customize the tcp, http or https log format using log format variables. Only used if
[`syslog-endpoint`](#syslog) is also configured.

* `auth-log-format`: log format of all auth external frontends. Use `default` to configure default HTTP log format, defaults to not log.
* `http-log-format`: log format of all HTTP proxies, defaults to HAProxy default HTTP log format.
* `https-log-format`: log format of TCP proxy used to inspect SNI extension. Use `default` to configure default TCP log format, defaults to not log.
* `tcp-log-format`: log format of the ConfigMap based TCP proxies. Defaults to HAProxy default TCP log format. See also [`--tcp-services-configmap`]({{% relref "command-line#tcp-services-configmap" %}}) command-line option.
* `tcp-service-log-format`: log format of TCP frontends, configured via ingress resources and [`tcp-service-port`](#tcp-services) configuration key. Defaults to HAProxy default TCP log format.

See also:

* https://docs.haproxy.org/2.8/configuration.html#8.2.4
* [`syslog`](#syslog)
* [Auth External](#auth-external) configuration keys.
* [TCP Services](#tcp-services) configuration keys.

---

### Master-worker

| Configuration key        | Scope    | Default | Since |
|--------------------------|----------|---------|-------|
| `master-exit-on-failure` | `Global` | `true`  | v0.12 |
| `worker-max-reloads`     | `Global` | `0`     | v0.12 |

Configures master-worker related options. These options are only used when
[`--master-worker`]({{% relref "command-line#master-worker" %}})
command-line option is configured as `true`.

* `master-exit-on-failure`: If `true`, kill all the remaining workers and exit
from master in the case of an unexpected failure of a worker, eg a segfault.
* `worker-max-reloads`: Defines how many reloads a haproxy worker should
survive before receive a SIGTERM. The default value is `0` which means
unlimited. This option limits the number of active workers and the haproxy's
pod memory usage. Useful on workloads with long running connections, eg
websockets, and clusters that frequently changes and forces haproxy to reload.

See also:

* [External HAProxy example]({{% relref "/docs/examples/external-haproxy" %}}) page
* https://docs.haproxy.org/2.8/configuration.html#3.1-master-worker
* https://docs.haproxy.org/2.8/configuration.html#mworker-max-reloads
* [master-socket]({{% relref "command-line#master-socket" %}}) and [master-worker]({{% relref "command-line#master-worker" %}}) command-line options

---

### Modsecurity

| Configuration key                | Scope    | Default | Since |
|----------------------------------|----------|---------|-------|
| `modsecurity-args`               | `Global` | `unique-id method path query req.ver req.hdrs_bin req.body_size req.body` | v0.14 |
| `modsecurity-endpoints`          | `Global` |         |       |
| `modsecurity-timeout-connect`    | `Global` | `5s`    | v0.10 |
| `modsecurity-timeout-hello`      | `Global` | `100ms` |       |
| `modsecurity-timeout-idle`       | `Global` | `30s`   |       |
| `modsecurity-timeout-processing` | `Global` | `1s`    |       |
| `modsecurity-timeout-server`     | `Global` | `5s`    | v0.10 |
| `modsecurity-use-coraza`         | `Global` | `false` | v0.14 |


Configure modsecurity agent. These options only have effect if `modsecurity-endpoints`
is configured.

Configure `modsecurity-endpoints` with a comma-separated list of `IP:port` of HAProxy
agents (SPOA) for ModSecurity. The default configuration expects the
`contrib/modsecurity` implementation from HAProxy source code.

Up to v0.7 all http requests will be parsed by the ModSecurity agent, even if the
ingress resource wasn't configured to deny requests based on ModSecurity response.
Since v0.8 the spoe filter is configured on a per-backend basis.

The following keys are supported:

* `modsecurity-args`: Space separated list of arguments that HAProxy will send to the modsecurity agent. You can override this to e.g. prevent sending the request body to modsecurity which will improve performance, but reduce security. The arguments must be valid HAProxy [sample fetch methods](https://www.haproxy.com/documentation/hapee/latest/configuration/fetches/overview/).
* `modsecurity-endpoints`: Comma separated list of ModSecurity agent endpoints.
* `modsecurity-timeout-connect`: Defines the maximum time to wait for the connection to the agent be established. Configures the haproxy's timeout connect. Defaults to `5s` if not configured.
* `modsecurity-timeout-hello`: Defines the maximum time to wait for the AGENT-HELLO frame from the agent. Default value is `100ms`.
* `modsecurity-timeout-idle`: Defines the maximum time to wait before close an idle connection. Default value is `30s`.
* `modsecurity-timeout-processing`: Defines the maximum time to wait for the whole ModSecurity processing. Default value is `1s`.
* `modsecurity-timeout-server`: Defines the maximum time to wait for an agent response. Configures the haproxy's timeout server. Defaults to `5s` if not configured.
* `modsecurity-use-coraza`: Defines whether the generated SPOE config should include Coraza-specific values. In order to use Coraza instead of Modsecurity, you must set this to "true" and also set `modsecurity-args` based on the instructions in the [coraza-spoa repository](https://github.com/corazawaf/coraza-spoa). See a [full example using coraza instead of modsecurity]({{% relref "../examples/modsecurity#using-coraza-instead-of-modsecurity" %}}).

See also:

* [modsecurity example]({{% relref "../examples/modsecurity" %}}) page.
* [`waf`](#waf) configuration key.
* https://www.haproxy.org/download/2.0/doc/SPOE.txt
* https://docs.haproxy.org/2.8/configuration.html#9.3
* https://github.com/jcmoraisjr/modsecurity-spoa

---

### Nbproc

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `nbproc-ssl`      | `Global` | `0`     |       |

{{< alert title="Warning" color="warning" >}}
This option works only on v0.7 or below. Since v0.8 the only supported value is `0` zero.
{{< /alert >}}

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
* https://docs.haproxy.org/2.8/configuration.html#3.1-nbproc
* https://docs.haproxy.org/2.8/configuration.html#4-bind-process
* https://docs.haproxy.org/2.8/configuration.html#3.1-cpu-map

---

### Nbthread

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `nbthread`        | `Global` |         |       |

Define the number of threads a single HAProxy process should use to all its
processing. If not declared, the number of threads will be adjusted to the
number of available CPUs on platforms that support CPU affinity.

If using two or more threads, `cpu-map` is used by default to bind each
thread on its own CPU core.

See also:

* [cpu-map](#cpu-map) configuration key
* https://docs.haproxy.org/2.8/configuration.html#3.1-nbthread
* https://docs.haproxy.org/2.8/configuration.html#3.1-cpu-map

---

### OAuth

| Configuration key | Scope  | Default                | Since |
|-------------------|--------|------------------------|-------|
| `oauth`           | `Path` |                        |       |
| `oauth-headers`   | `Path` | `X-Auth-Request-Email` |       |
| `oauth-uri-prefix`| `Path` | `/oauth2`              |       |

Configure OAuth2 via Bitly's `oauth2_proxy`. These options have less precedence if used with [`auth-url`](#auth-external).

* `oauth`: Defines the oauth implementation. The only supported option is `oauth2_proxy` or its alias `oauth2-proxy`.
* `oauth-uri-prefix`: Defines the URI prefix of the oauth service. The default value is `/oauth2`. There should be a backend with this path in the ingress resource.
* `oauth-headers`: Defines an optional comma-separated list of `<header>[:<source>]` used to configure request headers to the upstream backend. The default value is `X-Auth-Request-Email` which copies this HTTP header from oauth2-proxy service response to the backend service. An optional `<source>` can be provided with another HTTP header or an internal HAProxy variable.

OAuth2 expects [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy),
or any other compatible implementation running as a backend of the same domain that should be protected.
`oauth2-proxy` has support to GitHub, Google, Facebook, OIDC and [others](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider).

{{< alert title="Note" >}}
OAuth2 needs [`external-has-lua`](#external) enabled if running on an external haproxy deployment. The external haproxy needs Lua json module installed (Alpine's `lua-json4` package)
{{< /alert >}}

Since v0.13 these same options can be used with [Auth External](#auth-external) configuration keys. Change `<oauth2-proxy-service>` below with the oauth2-proxy service name, and `<hostname>` to the hostname of the oauth2-proxy and the backend servers:

* `auth-url: "svc://<oauth2-proxy-service>/oauth2/auth"`.
* `auth-signin: "https://<hostname>/oauth2/start?rd=%[path]"` - the content is parsed by haproxy as a [log-format](https://docs.haproxy.org/2.8/configuration.html#8.2.4) string and the result is copied verbatim to the `Location` header of a HTTP 302 response. The `rd` query field asks oauth2-proxy to preserve the path provided by the client.
* `auth-headers-succeed: "X-Auth-Request-Email"` - copy the `X-Auth-Request-Email` HTTP header with the user email from oauth2-proxy to the backend server.

Configure oauth2 on a distinct ingress, without the `auth-url` annotation; otherwise, it will endless loop in a HTTP 403 error.

See also:

* [Auth External](#auth-external) configuration keys.
* [`external-has-lua`](#external) configuration key.
* [example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/auth/oauth) page.

---

### Path type

| Configuration key | Scope    | Default                    | Since |
|-------------------|----------|----------------------------|-------|
| `path-type`       | `Path`   | `begin`                    | v0.11 |
| `path-type-order` | `Global` | `exact,prefix,begin,regex` | v0.12 |

Defines how the path of an incoming request should match a declared path in the ingress object.

* `path-type`: Configures the path type. Case insensitive, so `Begin` and `begin` configures the same path type option. The ingress spec has priority, this option will only be used if the `pathType` attribute from the ingress spec is declared as `ImplementationSpecific`.
* `path-type-order`: Defines a comma-separated list of the order that non overlapping paths should be matched, which means that `/dir/sub` will always be checked before `/dir` despite their type and the configured order. Mostly used to define when `regex` path types should be checked for incoming requests, since HAProxy Ingress doesn't calculate overlapping from regex paths. All path types must be provided. Case insensitive, use all path types in lowercase.

{{< alert title="Warning" color="warning" >}}
Wildcard hostnames and alias-regex match incoming requests using the regex path type, even if the path itself has a distinct one. This happens because hostname and path are checked for a match in a single step. So, changing the precedence order of paths also changes the precedence order of hostnames. See also [server-alias-regex](#server-alias) and [strict host](#strict-host).
{{< /alert >}}

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

### Peers

| Configuration key    | Scope     | Default   | Since |
|----------------------|-----------|-----------|-------|
| `peers-name`         | `Global`  | `ingress` | v0.16 |
| `peers-port`         | `Global`  |           | v0.16 |
| `peers-table`        | `Backend` |           | v0.16 |
| `peers-table-global` | `Global`  |           | v0.16 |

Configures HAProxy `peers` section and stick tables.

* `peers-name`: Name of the peers section, defaults to `ingress`. The peers section name is used on stick-table configurations.
* `peers-port`: Port number the HAProxy instances should use to communicate each other. This is a mandatory option.
* `peers-table`: A per backend configuration of the stick-table to be shared on all ingress instances.
* `peers-table-global`: A single, global configuration of the stick-table to be shared on all ingress instances. Useful on frontend metrics.

HAProxy uses stick tables to track a number of metrics, including counters and rate for requests, sessions, bytes in/out and many others. Peers configuration is the ability to group all those metrics together, from all the instances of a HAProxy cluster, so every single instance can deal with them having the perspective of the whole ingress cluster.

Here are some notes about enabling peers:

* There is not a centralized data, instead, all the instances of the ingress cluster will talk with each other, sharing their data.
* Because of the former, the connectivity between all the HAProxy pods via the configured TCP port should be allowed in the cluster.
* The Kubernetes node will listen to the configured TCP port on its IP address if HAProxy Ingress is deployed in the host network.

Aggregation is made locally, which adds some caveats about metrics aggregation:

* From every configured `peers-table-global` or `peers-table`, HAProxy Ingress creates one stick-table per proxy instance, which means that 3 configured backends, from a cluster of 5 ingress nodes, 15 stick-tables will be created on every single instance.
* Every table on every instance has the metrics of a single instance, so everytime an aggregated value is needed, haproxy will make a lookup on all the tables that defines that metric, and sum the current value from all of them.

**Usage**

The following examples demonstrate how to configure HAProxy Ingress to collect some request metrics.

Frontend should be configured via the global ConfigMap:

```yaml
    peers-table-global: |
      stick-table type ip size 100k expire 1m peers ingress store http_req_rate(10s)
    config-frontend-early: |
      ...
      http-request track-sc0 src table %[peers_table_global]
      http-request deny if { src,lua.peers_sum(%[peers_group_global],http_req_rate) gt 100 }
```

Backends can be configured via Ingress or Service annotations:

```yaml
    annotations:
      haproxy-ingress.github.io/peers-table: |
        stick-table type ip size 100k expire 1m peers ingress store http_req_rate(10s)
      haproxy-ingress.github.io/config-backend-early: |
        ...
        http-request track-sc1 src table %[peers_table_backend]
        http-request deny if { src,lua.peers_sum(%[peers_group_backend],http_req_rate) gt 100 }
```

Regarding the configurations above:

1. `peers-table-global` (global) and `peers-table` (ing/svc annotation) define one stick table per existing ingress instance, automatically updated when the cluster scales.
1. The first line of the configuration snippet tracks the current request and uses the source IP address as the key of the collected data. It is assigned to the stick table dedicated to the local requests.
1. The second line uses a Lua script converter to calculate the sum of the request rate, denying the request if it goes beyond of a threshold.

This will deny requests from source IPs issuing more than 10rps in average over the last 10 seconds. Since peers is configured, the local metric is shared among all the other proxies. Since the aggregation converter `lua.peers_sum` is used, the 10rps limit corresponds to the sum of all the rate requests from all the proxies of the cluster over that same source IP.

{{< alert title="Note" >}}
Give the tracked sticky counter names (`track-sc0`, `track-sc1`) a special attention: the backend declared one will not collect request metrics if its ID matches the one used in the frontend. As a suggestion, from the HAProxy documentation:
> It is a recommended practice to use the first set of counters (`track-sc0`) for the per-frontend counters and the second set (`track-sc0`) for the per-backend ones. But this is just a guideline, all may be used everywhere.
{{< /alert >}}

Useful notes:

* Always use the same fetch sample, `src` in the examples above, on tracking configuration and as the incoming value of the `lua.peers_sum` converter.
* `lua.peers_sum` converter is only available if either `peers-table-global` global config or `peers-table` annotation is configured.
* Both `peers-table-global` and `peers-table` configurations expect a fully configured stick-table, so the `peers` parameter should be added either to the automatically created `ingress`, or another one created manually.

**Variables**

HAProxy Ingress provides some variables to be used on configuration snippets, useful on metric related configurations.

* `%[peers_group_global]`: name of the group of stick tables declared via `peers-table-global`. Useful to configure peers_sum converter. Visible on both global ConfigMap and annotation based snippets.
* `%[peers_group_backend]`: name of the group of stick tables declared via `peers-table` annotation. Useful to configure peers_sum converter. Visible only on annotation based snippets.
* `%[peers_table_global]`: name of the global scoped stick table declared via `peers-table-global` that should be used to store local metrics. Useful on `track-sc*` action. Visible on both global ConfigMap and annotation based snippets.
* `%[peers_table_backend]`: name of the backend scoped stick table declared via `peers-table` annotation that should be used to store local metrics. Useful on `track-sc*` action. Visible only on annotation based snippets.

See also:

* [`config-peers`](#configuration-snippet) configuration key
* https://docs.haproxy.org/2.8/configuration.html#3.5
* https://docs.haproxy.org/2.8/configuration.html#4-stick-table
* https://docs.haproxy.org/2.8/configuration.html#4.2-http-request%20track-sc0
* https://www.haproxy.com/blog/introduction-to-haproxy-stick-tables

---

### Proxy body size

| Configuration key | Scope  | Default | Since |
|-------------------|--------|---------|-------|
| `proxy-body-size` | `Path` |         |       |

Define the maximum number of bytes HAProxy will allow on the body of requests. Default is
to not check, which means requests of unlimited size. This limit can be changed per ingress
resource.

Since 0.4 a suffix can be added to the size, so `10m` means
`10 * 1024 * 1024` bytes. Supported suffix are: `k`, `m` and `g`.

Since 0.7 `unlimited` can also be used to overwrite any global body size limit.

See also:

* https://docs.haproxy.org/2.8/configuration.html#7.3.6-req.body_size

---

### Proxy protocol

| Configuration key            | Scope      | Default | Since |
|------------------------------|------------|---------|-------|
| `proxy-protocol`             | `Backend`  | `no`    |       |
| `tcp-service-proxy-protocol` | `TCP`      | `false` | v0.13 |
| `use-proxy-protocol`         | `Frontend` | `false` |       |

Configures PROXY protocol in frontends and backends.

* `proxy-protocol`: Define if the upstream backends support proxy protocol and what version of the protocol should be used. Supported values are `v1`, `v2`, `v2-ssl`, `v2-ssl-cn` or `no`. The default behavior if not declared is that the protocol is not supported by the backends and should not be used.
* `use-proxy-protocol`: Define if HTTP services are behind another proxy that uses the PROXY protocol. If `true`, HTTP ports will expect the PROXY protocol, version 1 or 2. The stats endpoint (defaults to port `1936`) has its own [`stats-proxy-protocol`](#stats) configuration key.
* `tcp-service-proxy-protocol`: Define if the TCP service is behind another proxy that uses the PROXY protocol. Configures as `"true"` if the proxy should expect requests using the PROXY protocol, version 1 or 2. The default value is `"false"`.

See also:

* https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt
* https://docs.haproxy.org/2.8/configuration.html#5.1-accept-proxy
* https://docs.haproxy.org/2.8/configuration.html#5.2-send-proxy
* https://docs.haproxy.org/2.8/configuration.html#5.2-send-proxy-v2
* https://docs.haproxy.org/2.8/configuration.html#5.2-send-proxy-v2-ssl
* https://docs.haproxy.org/2.8/configuration.html#5.2-send-proxy-v2-ssl-cn

---

### Redirect

| Configuration key       | Scope      | Default                       | Since   |
|-------------------------|------------|-------------------------------|---------|
| `no-redirect-locations` | `Global`   | `/.well-known/acme-challenge` | v0.14.3 |
| `redirect-from`         | `Host`     |                               | v0.13   |
| `redirect-from-code`    | `Frontend` | `302`                         | v0.13   |
| `redirect-from-regex`   | `Host`     |                               | v0.13   |
| `redirect-to`           | `Path`     |                               | v0.13   |
| `redirect-to-code`      | `Frontend` | `302`                         | v0.13   |

Configures HTTP redirect. Redirect *from* matches source hostnames that should be redirected
to the hostname declared in the ingress spec. Redirect *to* uses the hostname declared in the
ingress spec as the matching source and redirects the request to the configured URL. See
examples below.

* `redirect-from`: Defines a source domain using hostname-like syntax, so wildcard domains can also be used. The request is redirected to the configured hostname, preserving protocol, path and query string.
* `redirect-from-regex`: Defines a POSIX extended regular expression used to match a source domain. The regex will be used verbatim, so add `^` and `$` if strict hostname is desired and escape `\.` dots in order to strictly match them.
* `redirect-from-code`: Which HTTP status code should be used in the redirect from. A `302` response is used by default if not configured.
* `redirect-to`: Defines the destination URL to redirect the incoming request. The declared hostname and path are used only to match the request, the backend will not be used and it's only needed to be declared to satisfy ingress spec validation.
* `redirect-to-code`: Which HTTP status code should be used in the redirect to. A `302` response is used by default if not configured.
* `no-redirect-locations`: Defines a comma-separated list of paths that should be ignored by all the redirects. Default value is `/.well-known/acme-challenge`, used by ACME protocol. Configure as an empty string to make the redirect happen on all paths, including the ACME challenge.

**Using redirect-from**

The following configuration redirects `app.local` to `www.app.local`, preserving protocol,
path and query string:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    haproxy-ingress.github.io/redirect-from: "app.local"
  name: app
spec:
  rules:
  - host: www.app.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app
            port:
              number: 8080
```

The same source domain can be configured just once, and a target domain can be assigned
just once as well, which means that this configuration can only be used on ingress
resources that defines just one hostname. The redirect configuration has the lesser
precedence, so if a source domain is also configured as a hostname on an ingress spec,
or as an alias using annotation, the redirect will not happen.

**Using redirect-to**

The following configuration redirects `app.local/...` to `https://www.app.local/login`,
without preserving protocol, path or query string:

Note: `www.app.local` should be configured on another ingress resource, and app service
below will not be used.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    haproxy-ingress.github.io/redirect-to: "https://www.app.local/login"
  name: app
spec:
  rules:
  - host: app.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app
            port:
              number: 8080
```

See also:

* [`app-root`](#app-root) configuration key.

---

### Rewrite target

| Configuration key | Scope  | Default | Since |
|-------------------|--------|---------|-------|
| `rewrite-target`  | `Path` |         |       |

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

### Secure backend

| Configuration key         | Scope     | Default | Since |
|---------------------------|-----------|---------|-------|
| `secure-backends`         | `Backend` |         |       |
| `secure-crt-secret`       | `Backend` |         |       |
| `secure-sni`              | `Backend` |         | v0.11 |
| `secure-verify-ca-secret` | `Backend` |         |       |
| `secure-verify-hostname`  | `Backend` |         | v0.11 |

Configure secure (TLS) connection to the backends.

* `secure-backends`: Define as true if the backend provide a TLS connection.
* `secure-crt-secret`: Optional secret name of client certificate and key. This cert/key pair must be provided if the backend requests a client certificate. Expected secret keys are `tls.crt` and `tls.key`, the same used if secret is built with `kubectl create secret tls <name>`. A filename prefixed with `file://` can also be used, containing both certificate and private key in PEM format, eg `file:///dir/crt.pem`.
* `secure-sni`: Optional hostname that should be used as the SNI TLS extension sent to the backend server. If `host` is used as the content, the header Host from the incoming request is used as the SNI extension in the request to the backend. `sni` can also be used, which will use the same SNI from the incoming request. Note that, although the header Host is always right, the incoming SNI might be wrong if a TLS connection that's already opened is reused - this is a common practice on browsers connecting over http2. Any other value different of `host` or `sni` will be used verbatim and should be a valid domain. If `secure-verify-ca-secret` is also provided, this hostname is also used to validate the server certificate names.
* `secure-verify-ca-secret`: Optional but recommended secret name with certificate authority bundle used to validate server certificate, preventing man-in-the-middle attacks. Expected secret key is `ca.crt`. Since v0.9, an optional `ca.crl` key can also provide a CRL in PEM format for the server to verify against. A filename prefixed with `file://` can be used containing the CA bundle in PEM format, and optionally followed by a comma and the filename with the crl, eg `file:///dir/ca.pem` or `file:///dir/ca.pem,/dir/crl.pem`. Configure either `secure-sni` or `secure-verify-hostname` to verify the certificate name.
* `secure-verify-hostname`: Optional hostname used to verify the name of the server certificate, without using the SNI TLS extension. This option can only be used if `secure-verify-ca-secret` was provided, and only supports hardcoded domains which is used verbatim.

See also:

* [Backend protocol](#backend-protocol) configuration key.
* https://docs.haproxy.org/2.8/configuration.html#5.2-verify
* https://docs.haproxy.org/2.8/configuration.html#5.2-verifyhost
* https://docs.haproxy.org/2.8/configuration.html#5.2-sni

---

### Security

| Configuration key  | Scope    | Default | Since |
|--------------------|----------|---------|-------|
| `groupname`        | `Global` |         | v0.12 |
| `use-chroot`       | `Global` | `false` | v0.9  |
| `use-haproxy-user` | `Global` | `false` | v0.9  |
| `username`         | `Global` |         | v0.12 |

{{< alert title="Warning" color="warning" >}}
Since v0.15 HAProxy Ingress starts as the non root user `haproxy`, UID `99`, so all the configurations below can only be used if deployment's security context is changed to run the container as UID `0`.
{{< /alert >}}

Change security options for deployments starting as root user.

* `username` and `groupname`: Changes the user and group names used to run haproxy as non root. The default value is an empty string, which means leave haproxy running as root. Note that even running as root, haproxy always drops its own privileges before start its event loop. Both options should be declared to the configuration take effect.
* `use-chroot`: If `true`, configures haproxy to perform a `chroot()` in the empty and non-writable directory `/var/empty` during the startup process, just before it drops its own privileges. See **Using chroot()** section below.
* `use-haproxy-user`: If `true`, configures `username` and `groupname` configuration keys as `haproxy`. See `username` and `groupname` above. Note that this user and group exists in the embedded haproxy, and should exist in the external haproxy if used. In the case of a conflict, `username` and `groupname` declaration will have priority and `use-haproxy-user` will be ignored. If `false`, the default value, user and group names will not be changed.

**Starting as root**

In the default configuration HAProxy Ingress container starts as the non root user `haproxy`, UID `99`. Since its 2.4 version, `docker.io/haproxy` image starts as the same user and UID.

Starting as root can be useful to configure chroot, and [Security Considerations](https://docs.haproxy.org/2.8/management.html#13) from the HAProxy doc describes some other use cases.

The starting user can be changed in the deployment or daemonset's pod template using the following configuration:

```yaml
...
  template:
    spec:
      securityContext:
        runAsUser: 0
```

Configuring the Helm chart:

```yaml
controller:
  securityContext:
    runAsUser: 0
```

**Using chroot()**

Beware of some chroot limitations:

{{< alert title="Note" >}}
HAProxy does not have access to the file system after configure a `chroot()`. Unix sockets located outside the chroot directory are used in the following conditions:

* At least one `ssl-passthrough` is used. It enforces the creation of a fronting TCP proxy inside haproxy, which uses an unix socket to communicate with the HTTP frontend.
* Internal ACME signer is used. HAProxy Ingress creates an internal server to answer the ACME challenge, and haproxy forwards the challenge requests to this server using an unix socket.

So only enable `use-chroot` if not using these features.
{{< /alert >}}

See also:

* https://docs.haproxy.org/2.8/management.html#13
* https://docs.haproxy.org/2.8/configuration.html#3.1-chroot
* https://docs.haproxy.org/2.8/configuration.html#3.1-uid
* https://docs.haproxy.org/2.8/configuration.html#3.1-gid
* https://docs.haproxy.org/2.8/configuration.html#3.1-unix-bind

---

### Server alias

| Configuration key    | Scope  | Default | Since |
|----------------------|--------|---------|-------|
| `server-alias`       | `Host` |         |       |
| `server-alias-regex` | `Host` |         |       |

Configure hostname alias. All annotations will be combined together with the host
attribute in the same ACL, and any of them might be used to match SNI extensions
(TLS) or Host HTTP header. The matching is case-insensitive.

* `server-alias`: Defines an alias with hostname-like syntax. On v0.6 and older, wildcard `*` wasn't converted to match a subdomain. Regular expression was also accepted but dots were escaped, making this alias less useful as a regex. Starting v0.7 the same hostname syntax is used, so `*.my.domain` will match `app.my.domain` but won't match `sub.app.my.domain`.
* `server-alias-regex`: Only in v0.7 and newer. Match hostname using a POSIX extended regular expression. The regex will be used verbatim, so add `^` and `$` if strict hostname is desired and escape `\.` dots in order to strictly match them. Some HTTP clients add the port number in the Host header, so remember to add `(:[0-9]+)?$` in the end of the regex if a dollar sign `$` is being used to match the end of the string.

---

### Service upstream

| Configuration key  | Scope     | Default | Since |
|--------------------|-----------|---------|-------|
| `service-upstream` | `Backend` | `false` |       |

Defines if the HAProxy backend/server endpoints should be configured with the
service VIP/IPVS. If `false`, the default value, the endpoints will be used and
HAProxy will load balance the requests between them. If defined as `true` the
service's ClusterIP is used instead.

---

### Source Address Intf

| Configuration key     | Scope     | Default | Since |
|-----------------------|-----------|---------|-------|
| `source-address-intf` | `Backend` |         | v0.13 |

Configures a list of network interface names whose IPv4 address should be used as the source address for outgoing connections.

* `source-address-intf`: Comma separated list of network interface names

As the default behavior, HAProxy will leave the operating system choose the most appropriate address. However the same source address will be used, even if the network interface has more IP address or other interfaces can also reach the destination, leading to outgoing TCP port exhaustion on deployments that needs more than 64k concurrent connections. Using more source IPs allows to bypass the maximum of 64k concurrent connections per instance.

HAProxy Ingress will list all IPv4 from all provided interfaces, ignoring interfaces that cannot be found, does not have IPv4, or cannot list its IPs. The IP addresses will be distributed among all the servers/endpoints, where each distinct server will use an IP from the list as its source address for its outgoing connections. If there are more replicas than IPs, some IPs from the list will be used more than once. If there are more IPs than replicas, some of the IPs from the list will not be used in a particular backend, but can be used on others that shares the configuration. The IP distribution consistently starts on distinct positions on distinct backends, fairly distributing all the IPs from the list on workloads with a big amount of backends with one or so servers each. If all the interfaces failed to list IP address, HAProxy falls back to the default behavior and leaves the operating system to choose the source IP.

Update also `/proc/sys/net/ipv4/ip_local_port_range` in the HAProxy hosts to allow each source IP use more than its default 28k ephemeral ports.

{{< alert title="Note" >}}
Neither HAProxy Ingress nor HAProxy will validate if the configured network interface and/or their IPs are valid sources for the outgoing connection, its up to the admin to ensure that the correct interface is properly configured.
{{< /alert >}}

{{< alert title="Warning" color="warning" >}}
The source IP is a static configuration added on each backend server. This configuration cannot be used on backends that use DNS resolver.
{{< /alert >}}

See also:

* https://docs.haproxy.org/2.8/configuration.html#4-source
* https://docs.haproxy.org/2.8/configuration.html#5.2-source
* https://www.kernel.org/doc/html/v5.12/networking/ip-sysctl.html#ip-variables

---

### SSL always add HTTPS

| Configuration key            | Scope | Default | Since   |
|------------------------------|-------|---------|---------|
| `ssl-always-add-https`       | Host  | `false` | v0.12.4 |
| `ssl-always-follow-redirect` | Host  | `true`  | v0.14.7 |

Every hostname declared on an Ingress resource is added to an internal HTTP map. If at least one Ingress adds the hostname in the `tls` attribute, the hostname is also added to an internal HTTPS map and does ssl offload using the default certificate. A secret name can also be added in the `tls` attribute, overriding the certificate used in the TLS handshake.

`ssl-always-add-https` asks the controller to always add the domain in the internal HTTP and HTTPS maps, even if the `tls` attribute isn't declared. If `false`, a missing `tls` attribute will only declare the domain in the HTTP map and `ssl-redirect` is ignored. If `true`, a missing `tls` attribute adds the domain in the HTTPS map, and the TLS handshake will use the default certificate. If `tls` attribute is used, this configuration is ignored.

`ssl-always-follow-redirect` configures how the `ssl-redirect` option should be used when the `tls` attribute is missing, but the host is added in the HTTPS map. When `false`, it makes the controller to mimic a v0.11 and older behavior by not redirecting to HTTPS if the ingress does not declare the `tls` attribute. When `true`, SSL redirect will happen if configured, regardless the presence of the `tls` attribute. This option is ignored if `ssl-always-add-https` is false.

The default value for `ssl-always-add-https` is `false` since v0.13 to correctly implement Ingress spec. The default value can be globally changed in the global ConfigMap.

These options are implemented to help teams upgrade from older controller versions without disruptions. It is suggested not to be changed, and if so, it is also suggested to evolve ingress resources to a state that does not depend on it in the mid term.

---

### SSL ciphers

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
* https://docs.haproxy.org/2.8/configuration.html#3.1-ssl-default-bind-ciphers
* https://docs.haproxy.org/2.8/configuration.html#3.1-ssl-default-bind-ciphersuites
* https://docs.haproxy.org/2.8/configuration.html#5.2-ciphers
* https://docs.haproxy.org/2.8/configuration.html#5.2-ciphersuites

---

### SSL DH

| Configuration key         | Scope    | Default | Since |
|---------------------------|----------|---------|-------|
| `ssl-dh-default-max-size` | `Global` | `1024`  |       |
| `ssl-dh-param`            | `Global` |         |       |

Configures Diffie-Hellman key exchange parameters.

* `ssl-dh-param`: Configure the secret name which defines the DH parameters file used on ephemeral Diffie-Hellman key exchange during the SSL/TLS handshake. A filename prefixed with `file://` can be used containing the DH parameters file in PEM format, eg `file:///dir/dh-param.pem`.
* `ssl-dh-default-max-size`: Define the maximum size of a temporary DH parameters used for key exchange. Only used if `ssl-dh-param` isn't provided.

See also:

* https://docs.haproxy.org/2.8/configuration.html#tune.ssl.default-dh-param
* https://docs.haproxy.org/2.8/configuration.html#3.1-ssl-dh-param-file

---

### SSL engine

| Configuration key  | Scope    | Default | Since |
|--------------------|----------|---------|-------|
| `ssl-engine`       | `Global` |         | v0.8  |
| `ssl-mode-async`   | `Global` | `false` | v0.8  |

Set the name of the OpenSSL engine to use. The string shall include the engine name
and its parameters.

Additionally, `ssl-mode-async` can be set to enable asynchronous TLS I/O operations if
the ssl-engine used supports it.

Reference:

* https://docs.haproxy.org/2.8/configuration.html#ssl-engine
* https://docs.haproxy.org/2.8/configuration.html#ssl-mode-async

---

### SSL options

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

* https://docs.haproxy.org/2.8/configuration.html#5.1-crt-list

---

### SSL passthrough

| Configuration key           | Scope    | Default | Since |
|-----------------------------|----------|---------|-------|
| `ssl-passthrough`           | `Host`   |         |       |
| `ssl-passthrough-http-port` | `Host`   |         |       |

Defines if HAProxy should work in TCP proxy mode and leave the SSL offload to the backend.
SSL passthrough is a per domain configuration, which means that other domains can be
configured to SSL offload on HAProxy.

{{< alert title="Note" >}}
Up to v0.12, `ssl-passthrough` supports only root `/` path. Since v0.13, non root paths are also supported and configured in the HAProxy's HTTP port.
{{< /alert >}}

* `ssl-passthrough`: Enable SSL passthrough if defined as `true`. The backend is then expected to SSL offload the incoming traffic. The default value is `false`, which means HAProxy should do the SSL handshake.
* `ssl-passthrough-http-port`: Optional HTTP port number of the ssl-passthrough backend. If defined, connections to the HAProxy's HTTP port, defaults to `80`, is sent to the configured port number of the backend, which expects to speak plain HTTP. If not defined, connections to the HTTP port will redirect the client to HTTPS. Note that this configuration only applies to the root path, since any non root path under ssl-passthrough configuration is already configured under the plain HTTP frontend.

Hostnames configured as `ssl-passthrough` configures HAProxy in the following way:

* Requests to the HTTPS port, defaults to `443`, will be sent to the backend and port number configured in the root `/` path of the domain. Such port must speak TLS and will make the TLS handshake with the client. There is no path inspection, so only one backend is supported.
* Requests to the HTTP port, defaults to `80`, will follow the same rules of non `ssl-passthrough` domains: if the request matches a non root path, the configured backend will be used and it should speak plain HTTP, except if [`secure-backends`](#secure-backend) is also configured. If there isn't non root paths or if they doesn't match, the request will fall back to: redirect to HTTPS (default), or the request will be sent to `ssl-passthrough-http-port` port number of the ssl backend.

---

### SSL redirect

| Configuration key           | Scope    | Default                       | Since |
|-----------------------------|----------|-------------------------------|-------|
| `no-tls-redirect-locations` | `Global` | `/.well-known/acme-challenge` |       |
| `ssl-redirect`              | `Path`   | `true`                        |       |
| `ssl-redirect-code`         | `Global` | `302`                         | v0.10 |

Configures if an encrypted connection should be used.

* `ssl-redirect`: Defines if HAProxy should send a `302 redirect` response to requests made on unencrypted connections. Note that this configuration will only make effect if TLS is [configured](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/tls-termination).
* `ssl-redirect-code`: Defines the HTTP status code used in the redirect. The default value is `302` if not declared. Supported values are `301`, `302`, `303`, `307` and `308`.
* `no-tls-redirect-locations`: Defines a comma-separated list of URLs that should be removed from the TLS redirect. Requests to `:80` http port and starting with one of the URLs from the list will not be redirected to https despite of the TLS redirect configuration. This option defaults to `/.well-known/acme-challenge`, used by ACME protocol.

See also:

* [`ssl-always-add-https`](#ssl-always-add-https) configuration key
* https://docs.haproxy.org/2.8/configuration.html#redirect

---

### Stats

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
* `stats-ssl-cert`: Optional namespace/secret-name of `tls.crt` and `tls.key` pair used to enable SSL on stats page. A filename prefixed with `file://` can be used, containing both certificate and private key in PEM format, eg `file:///dir/crt.pem`. Plain http will be used if not provided, the secret wasn't found, the secret doesn't have a crt/key pair or the file is not found.

---

### Strict host

| Configuration key | Scope     | Default | Since |
|-------------------|-----------|---------|-------|
| `strict-host`     | `Global`  | `false` |       |

Defines whether the path of another matching host/FQDN should be used to try
to serve a request. The default value is `false`, which means all matching
wildcard hosts will be visited in order to try to match the path. If `true`,
a strict configuration is applied and the `default-backend` should be used
if a path couldn't be matched.

Using the following configuration:

```yaml
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

### Syslog

| Configuration key | Scope     | Default    | Since |
|-------------------|-----------|------------|-------|
| `syslog-endpoint` | `Global`  |            |       |
| `syslog-format`   | `Global`  | `rfc5424`  | v0.8  |
| `syslog-length`   | `Global`  | `1024`     | v0.9  |
| `syslog-tag`      | `Global`  | `ingress`  | v0.8  |

Logging configurations.

* `syslog-endpoint`: Configures the UDP syslog endpoint where HAProxy should send access logs.
* `syslog-format`: Configures the log format to be either `rfc5424` (default), `rfc3164` or `raw`.
* `syslog-length`: The maximum line length, log lines larger than this value will be truncated. Defaults to `1024`.
* `syslog-tag`: Configure the tag field in the syslog header to the supplied string.

The HAProxy process can also send logs to stdout, instead of an external syslog endpoint or a syslog sidecar, by following the steps below:

* Configure `syslog-endpoint` as `stdout` and `syslog-format` as `raw`
* From v0.12 and newer, configure HAProxy to run as a sidecar, see the [example page]({{% relref "../examples/external-haproxy" %}})
* From v0.14 and newer, it is also possible to make embedded HAProxy send logs to the controller container by adding [`--master-worker`]({{% relref "command-line/#master-worker" %}}) command-line option - in this case, both controller and haproxy logs will share the same stream

See also:

* https://docs.haproxy.org/2.8/configuration.html#3.1-log
* https://docs.haproxy.org/2.8/configuration.html#3.1-log-tag

---

### TCP Services

| Configuration key            | Scope | Default | Since |
|------------------------------|-------|---------|-------|
| `tcp-service-port`           | `TCP` |         | v0.13 |

Configures a TCP proxy.

* `tcp-service-port`: Defines the port number HAProxy should listen to.

By default ingress resources configure HTTP services, and incoming requests are routed to backend servers based on hostnames and HTTP path. Whenever the `tcp-service-port` configuration key is added to an ingress resource, incoming requests are processed as TCP requests and the listening port number is used to route requests, using a dedicated frontend in tcp mode. Optionally, the TLS SNI extension can also be used to route incoming request if the hostname is declared in the ingress spec.

Due to the limited data that can be inspected on TCP requests, a limited number of configuration keys work with TCP services:

* `Backend` and `Path` scoped configuration keys work, provided that they are not HTTP related - eg [Cors](#cors) and [HSTS](#hsts) are ignored by TCP services, on the other hand [balance algorithm](#balance-algorithm), [Allow list](#allowlist) and [Blue/green](#blue-green) work just like in the HTTP requests counterpart.
* All `Global` configuration keys related with the whole haproxy process will also be applied to TCP services, like max connections or syslog configurations.
* Regarding `Host` scoped configuration keys:
  * on v0.13, all `Host` scoped configuration keys are unsupported
  * on v0.14, [auth-tls](#auth-tls) are supported

TLS configuration is also applied to the TCP service if configured, making HAProxy to ssl offload requests on that port. Default certificate can be used by leaving `.spec.tls[].secretName` empty. Up to `v0.14.7`, a single certificate can be configured for all incoming requests. Since `v0.14.8`, distinct TLS hosts sections can configure distinct certificates for the TLS handshake, chosen based on the provided TLS SNI extension. The first declared secret act as the default certificate if an incoming SNI does not match any host entry. Distinct TLS related configurations, via annotations, can be applied to distinct secrets by splitting the TCP service configuration into distinct ingress resources.

{{< alert title="Note" >}}
Note that hostname based selection relies on SNI, so it works only on TLS requests. The encrypted content can be offloaded either by HAProxy, providing the hostname in `.spec.rules[].host` and `.spec.tls`, or offloaded by the backend server, providing the hostname only in `.spec.rules[].host`. Non TLS content cannot be multiplexed on the same TCP port for more than one backend.

Note also that, in the case a hostname does not match, HAProxy will select a backend only if `.spec.defaultBackend` or an empty `.spec.rules[].host` is configured; otherwise, the connection is closed without a response.
{{< /alert >}}

Every TCP service port creates a dedicated haproxy frontend that can be [customized](#configuration-snippet) in three distinct ways:

* `config-tcp-service` in the global ConfigMap, this will add the same configurations to all the TCP service frontends
* `config-tcp-service` as an Ingress annotation, this will add the snippet in one TCP service
* `config-proxy` in the global ConfigMap using `_front_tcp_<port-number>` as the proxy name, see in the [configuration snippet](#configuration-snippet) documentation how it works

{{< alert title="Note" >}}
The documentation continues to refer to the old, and now deprecated [`--tcp-services-configmap`]({{% relref "command-line#tcp-services-configmap" %}}) configuration options. Whenever we are talking about the deprecated option, we will refer it as the "ConfigMap based TCP".
{{< /alert >}}

See also:

* [`config-tcp-service`](#configuration-snippet) configuration key
* [`tcp-service-log-format`](#log-format) configuration key

---

### Timeout

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
| `timeout-stop`         | `Global`  | `10m`   |       |
| `timeout-tunnel`       | `Backend` | `1h`    |       |

Define timeout configurations. The unit defaults to milliseconds if missing, change the unit with `s`, `m`, `h`, ... suffix.

{{< alert title="Note" >}}
Since `v0.11`, `timeout-client` and `timeout-client-fin` are global configuration keys and cannot be configured per hostname.
{{< /alert >}}

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

* https://docs.haproxy.org/2.8/configuration.html#3.1-hard-stop-after (`timeout-stop`)
* https://docs.haproxy.org/2.8/configuration.html#2.5 (time suffix)

---

### TLS ALPN

| Configuration key | Scope    | Default       | Since |
|-------------------|----------|---------------|-------|
| `tls-alpn`        | `Host`   | `h2,http/1.1` | v0.8  |

Defines the TLS ALPN extension advertisement. The default value is `h2,http/1.1` which enables
HTTP/2 on the client side.

`tls-alpn` was `Global` scope up to v0.10.

See also:

* https://docs.haproxy.org/2.8/configuration.html#5.1-alpn

---

### Use HTX

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `use-htx`         | `Global` | `true`  | v0.9  |

Defines if the new HTX internal representation for HTTP elements should be used. The default value
is `true` since v0.10, it was `false` on v0.9. HTX should be used to enable HTTP/2 protocol to backends.

See also:

* [backend-protocol](#backend-protocol) configuration keys
* https://docs.haproxy.org/2.8/configuration.html#4-option%20http-use-htx

---

### Var namespace

| Configuration key | Scope    | Default | Since |
|-------------------|----------|---------|-------|
| `var-namespace`   | `Host`   | `false` | v0.8  |

If `var-namespace` is configured as `true`, a HAProxy var `txn.namespace` is created with the
kubernetes namespace owner of the service which is the target of the request. This variable is
useful on http logs. The default value is `false`. Usage: `k8s-namespace: %[var(txn.namespace)]`.

See also:

* [http-log](#log-format) configuration key

---

### WAF

| Configuration key | Scope  | Default | Since |
|-------------------|--------|---------|-------|
| `waf`             | `Path` |         |       |
| `waf-mode`        | `Path` | `deny`  | v0.9  |

Defines which web application firewall (WAF) implementation should be used
to validate requests. Currently the only supported value is `modsecurity`, which also supports Coraza endpoints when `modsecurity-use-coraza` is set to "true".

This configuration has no effect if the ModSecurity endpoints are not configured.

The `waf-mode` key defines whether the WAF should be `deny` or `detect` for that Backend.
If the WAF is in `detect` mode the requests are passed to ModSecurity and logged, but not denied.

The default behavior here is `deny` if `waf` is set to `modsecurity`.

See also:

* [Modsecurity](#modsecurity) configuration keys.
