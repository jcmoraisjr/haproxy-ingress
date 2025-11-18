---
title: "Command-line options"
linkTitle: "Command-line"
weight: 4
description: >
  Static command-line configuration options.
---

The following command-line options are supported:

| Name                                                    | Type                       | Default                 | Since |
|---------------------------------------------------------|----------------------------|-------------------------|-------|
| [`--acme-check-period`](#acme)                          | time                       | `24h`                   | v0.9  |
| [`--acme-election-id`](#acme)                           | [namespace]/configmap-name | `acme-leader`           | v0.9  |
| [`--acme-fail-initial-duration`](#acme)                 | time                       | `5m`                    | v0.9  |
| [`--acme-fail-max-duration`](#acme)                     | time                       | `8h`                    | v0.9  |
| [`--acme-secret-key-name`](#acme)                       | [namespace]/secret-name    | `acme-private-key`      | v0.9  |
| [`--acme-server`](#acme)                                | [true\|false]              | `false`                 | v0.9  |
| [`--acme-token-configmap-name`](#acme)                  | [namespace]/configmap-name | `acme-validation-tokens` | v0.9 |
| [`--acme-track-tls-annotation`](#acme)                  | [true\|false]              | `false`                 | v0.9  |
| [`--allow-cross-namespace`](#allow-cross-namespace)     | [true\|false]              | `false`                 |       |
| [`--annotations-prefix`](#annotations-prefix)           | prefix list without `/`    | `haproxy-ingress.github.io,ingress.kubernetes.io` | v0.8  |
| [`--apiserver-host`](#apiserver-host)                   | address of K8s API server  |                         |       |
| [`--backend-shards`](#backend-shards)                   | int                        | `0`                     | v0.11 |
| [`--buckets-response-time`](#buckets-response-time)     | float64 slice           | `.0005,.001,.002,.005,.01` | v0.10 |
| [`--configmap`](#configmap)                             | namespace/configmapname    |                         |       |
| [`--controller-class`](#ingress-class)                  | suffix                     | `""`                    | v0.12 |
| [`--default-backend-service`](#default-backend-service) | namespace/servicename      | haproxy's 404 page      |       |
| [`--default-ssl-certificate`](#default-ssl-certificate) | namespace/secretname       | fake, auto generated    |       |
| [`--disable-api-warnings`](#disable-api-warnings)       | [true\|false]              | `false`                 | v0.12 |
| [`--disable-config-keywords`](#disable-config-keywords) | comma-separated list of keywords | `""`              | v0.10 |
| [`--disable-external-name`](#disable-external-name)     | [true\|false]              | `false`                 | v0.10 |
| [`--disable-ingress-class-api`](#ingress-class)         | [true\|false]              | `false`                 | v0.16 |
| [`--disable-pod-list`](#disable-pod-list)               | [true\|false]              | `false`                 | v0.11 |
| [`--election-id`](#election-id)                         | identifier                 | `ingress-controller-leader` |   |
| [`--enable-endpointslices-api`](#enable-endpointslices-api) | [true\|false]          | `true`                  | v0.14 |
| [`--force-namespace-isolation`](#force-namespace-isolation) | [true\|false]          | `false`                 |       |
| [`--haproxy-grace-period`](#haproxy-grace-period)       | time                       | `20s`                   | v0.16 |
| [`--health-check-path`](#stats)                         | path                       | `/healthz`              |       |
| [`--healthz-addr`](#stats)                              | tcp address                | `:10254`                | v0.15 |
| [`--healthz-port`](#stats)                              | port number                | `10254`                 |       |
| [`--ingress-class`](#ingress-class)                     | name                       | `haproxy`               |       |
| [`--ingress-class-precedence`](#ingress-class)          | [true\|false]              | `false`                 | v0.13.5 |
| [`--kubeconfig`](#kubeconfig)                           | /path/to/kubeconfig        | in cluster config       |       |
| [`--local-filesystem-prefix`](#local-filesystem-prefix) | temporary base directory   |                         | v0.14 |
| [`--log-zap`](#logging)                                 | [true\|false]              | `false`                 | v0.14 |
| [`--log-dev`](#logging)                                 | [true\|false]              | `false`                 | v0.14 |
| [`--log-caller`](#logging)                              | [true\|false]              | `false`                 | v0.14 |
| [`--log-enable-stacktrace`](#logging)                   | [true\|false]              | `false`                 | v0.14 |
| [`--log-encoder`](#logging)                             | encoder name               | `json` (prod), `console` (dev) | v0.14 |
| [`--log-encode-time`](#logging)                         | encoder name               | `rfc3339nano` (prod), `iso8601` (dev) | v0.14 |
| [`--master-socket`](#master-socket)                     | socket path                | use embedded haproxy    | v0.12 |
| [`--master-worker`](#master-worker)                     | [true\|false]              | false                   | v0.14 |
| [`--max-old-config-files`](#max-old-config-files)       | num of files               | `0`                     |       |
| [`--profiling`](#stats)                                 | [true\|false]              | `true`                  |       |
| [`--publish-address`](#publish-address)                 | list of hostname/IP        |                         | v0.15 |
| [`--publish-service`](#publish-service)                 | namespace/servicename      |                         |       |
| [`--rate-limit-update`](#rate-limit-update)             | uploads per second (float) | `0.5`                   |       |
| [`--ready-check-path`](#stats)                          | path                       | `/readyz`               | v0.15 |
| [`--reload-interval`](#reload-interval)                 | time                       | `0`                     | v0.13 |
| [`--reload-retry`](#reload-retry)                       | time                       | `30s`                   | v0.15 |
| [`--reload-strategy`](#reload-strategy)                 | [native\|reusesocket]      | `reusesocket`           |       |
| [`--report-node-internal-ip-address`](#report-node-internal-ip-address) | [true\|false] | `false`              |       |
| [`--sort-backends`](#sort-backends)                     | [true\|false]              | `false`                 |       |
| [`--shutdown-timeout`](#shutdown-timeout)               | time                       | `25s`                   | v0.15 |
| [`--sort-endpoints-by`](#sort-endpoints-by)             | [endpoint\|ip\|name\|random] | `endpoint`            | v0.11 |
| [`--stats-collect-processing-period`](#stats)           | time                       | `500ms`                 | v0.10 |
| [`--stop-handler`](#stats)                              | [true\|false]              | `false`                 | v0.15 |
| [`--sync-period`](#sync-period)                         | time                       | `10m`                   |       |
| [`--tcp-services-configmap`](#tcp-services-configmap)   | namespace/configmapname    | no tcp svc              |       |
| [`--track-old-instances`](#track-old-instances)         | [true\|false]              | `false`                 | v0.14 |
| [`--update-status`](#update-status)                     | [true\|false]              | `true`                  |       |
| [`--update-status-on-shutdown`](#update-status-on-shutdown) | [true\|false]          | `true`                  |       |
| [`--v`](#logging)                                       | log level as integer       | `2`                     |       |
| [`--validate-config`](#validate-config)                 | [true\|false]              | `false`                 |       |
| [`--verify-hostname`](#verify-hostname)                 | [true\|false]              | `true`                  |       |
| [`--version`](#version)                                 | [true\|false]              | `false`                 |       |
| [`--wait-before-shutdown`](#wait-before-shutdown)       | seconds as integer         | `0`                     | v0.8  |
| [`--wait-before-update`](#wait-before-update)           | duration                   | `200ms`                 | v0.11 |
| [`--watch-gateway`](#watch-gateway)                     | [true\|false]              | `false`                 | v0.13 |
| [`--watch-ingress-without-class`](#ingress-class)       | [true\|false]              | `false`                 | v0.12 |
| [`--watch-namespace`](#watch-namespace)                 | namespace                  | all namespaces          |       |

---

## Acme

Configures the acme server and other static options used to authorize and sign certificates
against a server which implements the acme protocol, version 2.

Supported acme command-line options:

* `--acme-check-period`: interval between checks for expiring certificates. Defaults to `24h`.
* `--acme-election-id`: deprecated on v0.15, use [`--election-id`](#election-id) instead.
* `--acme-fail-initial-duration`: the starting time to wait and retry after a failed authorization and sign process. Defaults to `5m`.
* `--acme-fail-max-duration`: the time between retries of failed authorization will exponentially grow up to the max duration time. Defaults to `8h`.
* `--acme-secret-key-name`: secret name used to store the client private key. Defaults to `acme-private-key`. A new key, hence a new client, is created if the secret does not exist.
* `--acme-server`: mandatory, starts a local server used to answer challenges from the acme environment. This option should be provided on all haproxy-ingress instances to the certificate signing work properly.
* `--acme-token-configmap-name`: the ConfigMap name used to store temporary tokens generated during the challenge. Defaults to `acme-validation-tokens`. Such tokens need to be stored in k8s because any haproxy-ingress instance might receive the request from the acme environment.
* `--acme-track-tls-annotation`: defines if ingress objects with annotation `kubernetes.io/tls-acme: "true"` should also be tracked. Defaults to `false`.

See also:

* [acme configuration keys]({{% relref "keys/#acme" %}}) doc, which has also an overview on how acme works on haproxy-ingress

---

## allow-cross-namespace

* `--allow-cross-namespace`

`--allow-cross-namespace` argument, if added, will allow reading secrets from one namespace to an
ingress resource of another namespace. The default behavior is to deny such cross namespace reading.
This adds a breaking change from `v0.4` to `v0.5` on `haproxy-ingress.github.io/auth-tls-secret`
annotation, where cross namespace reading were allowed without any configuration.

See also:

* [cross namespace]({{% relref "keys#cross-namespace" %}}) configuration keys.

---

## annotations-prefix

* `--annotations-prefix`

Configures a comma-separated list of annotations prefix that the controller should look for when
parsing services and ingress objects. The default value is `haproxy-ingress.github.io,ingress.kubernetes.io`.
The default configuration means declare eg a SSL Redirect annotation with
`haproxy-ingress.github.io/ssl-redirect: "true"` or `ingress.kubernetes.io/ssl-redirect: "true"`.

The order of the declaration is used to prioritize one of them if the same configuration key is
declared twice - if two distinct prefix is used to configure the same key in the same ingress or
service resource, the value of the annotation with the prefix that was configured first in this
command-line option is used.

Annotations with other prefix or without any prefix are ignored. This allows to use HAProxy Ingress
with other ingress controllers that shares ingress and service resources without conflicting each
other.

---

## apiserver-host

* `--apiserver-host`

Allows you to specify an explicit host for the Kubernetes API server, in the format of
`protocol://address:port`, e.g., `http://localhost:8080`.  If this value isn't specified, the
assumption is that the binary is running inside a Kubernetes cluster and local discovery will be
attempted.

---

## backend-shards

* `--backend-shards`

Defines how many files should be used to configure the haproxy backends. The default value is
0 (zero) which uses one single file to configure the whole haproxy process. Values greater than
0 (zero) splits the backend configuration into separated files. Only files with changed backends
are parsed and written to disk, reducing io and cpu usage on big clusters - about 1000 or more
services.

---

## buckets-response-time

* `--buckets-response-time`

Configures the buckets of the histogram `haproxyingress_haproxy_response_time_seconds`, used to compute the response time of the haproxy's admin socket. The response time unit is in seconds. The default value is `.0005,.001,.002,.005,.01` (`500µs`, `1ms`, `2ms`, `5ms`, `10ms`) if not configured.

---

## configmap

* `--configmap`

The name of the ConfigMap that contains the custom configuration to use, in the format
`namespace/configmapname`.  Beware that in version 0.12 and below, an incorrect value here will
silently fail.  Version 0.13 and later will crash if the ConfigMap is unreadable or nonexistent.

See also:

* [custom-configuration example using `--configmap`](https://github.com/jcmoraisjr/haproxy-ingress/blob/master/examples/custom-configuration/README.md)

---

## default-backend-service

* `--default-backend-service`

Defines the `namespace/servicename` that should be used if the incoming request doesn't match any
hostname, or the requested path doesn't match any location within the desired hostname. An internal
404 error page is used if not declared.

---

## default-ssl-certificate

* `--default-ssl-certificate`

Defines the `namespace/secretname` of the default certificate that should be used if ingress
resources using TLS configuration doesn't provide its own certificate.  A filename prefixed
with `file://` can be used, containing both certificate and private key in PEM format, eg
`file:///dir/crt.pem`.

A self-signed fake certificate is used if not declared, the secret or the file is not found.

---

## disable-api-warnings

* `--disable-api-warnings`

Since v0.12.4

Disable warning logs sent from the API server. Most of the warnings are related with API
deprecation. The default behavior is to log all API server warnings.

---

## disable-config-keywords

* `--disable-config-keywords`

Since v0.10.9

Defines a comma-separated list of HAProxy keywords that should not be used on annotation based configuration snippets. Configuration snippets added as a global config does not follow this option. Use an asterisk `*` to disable configuration snippets using annotations.

Every keyword in the configuration will be compared with the first token of every configuration line, ignoring tabs and spaces. If a match occur, all the configuration snippet will be ignored and a warning is logged.

The default value is an empty string, enabling the configuration and accepting any HAProxy keyword.

---

## disable-external-name

* `--disable-external-name`

Since v0.10.9

Services of type ExternalName uses DNS lookup to define the target server IP list. Declare `--disable-external-name` to disable a DNS based target IP list, refusing services of type ExternalName.

---

## disable-pod-list

* `--disable-pod-list`

Since v0.11, deprecated since v0.15

Disables in memory pod list and also pod watch for changes. Pod list and watch is used by the `drain-support` and `assign-backend-server-id` options, which will not work if pod list is disabled. Blue/green and `session-cookie-value-strategy` set to `pod-uid` also use pod list if enabled; otherwise, k8s api is called if needed. The default value is `false`, which means pods will be watched and listed in memory. Since v0.15 all the listers are managed by controller-runtime, making this option deprecated.

---

## election-id

* `--election-id`

The ID to be used for electing ingress controller leader. A leader needs to be elected in the following use cases:

* Ingress Status update, see [`--update-status`](#update-status)
* Embedded Acme signer, see [acme](#acme)
* Gateway API, see [`--watch-gateway`](#watch-gateway)

Election ID configuration has no effect if none of Ingress Status update, Embedded Acme signer, or Gateway API are enabled.

Since v0.15 a `%s` placeholder is used to define where the IngressClass value should be added to the election ID. Up to v0.14 the IngressClass was concatenated in the end of the provided value to compose the real election ID value. Ingress class is added to the election ID name to avoid conflict when two or more HAProxy Ingress controllers are running in the same cluster.

Election ID defaults to `class-%s.haproxy-ingress.github.io` if not configured, which is rendered to `class-haproxy.haproxy-ingress.github.io` if the IngressClass is not changed from the default value.

---

## enable-endpointslices-api

* `--enable-endpointslices-api`

Since v0.14, deprecated since v0.16

Uses EndpointSlices API info, rather than Endpoints API, to fetch service endpoints info.

Endpoints API is deprecated since Kubernetes 1.33, and HAProxy Ingress only supports EndpointSlices API since v0.16. This option is ignored if configured.

---

## force-namespace-isolation

* `--force-namespace-isolation`

Deprecated since v0.15

Whether to force namespace isolation.  This flag is required to avoid the reference of secrets,
configmaps or the default backend service located in a different namespace than specified in the
flag `--watch-namespace` (which defaults to all namespaces, so you will probably want to set that
flag, too). Since v0.15 isolation is controlled by the [`--allow-cross-namespace`](#allow-cross-namespace)
and [`--watch-namespace`](#watch-namespace) command-line options, making `--force-namespace-isolation`
deprecated.

See also:

* [`--allow-cross-namespace`](#allow-cross-namespace) command-line option
* [`--watch-namespace`](#watch-namespace) command-line option

---

## haproxy-grace-period

* `--haproxy-grace-period`

Since v0.16

Defines the duration HAProxy should wait all requests to finish before terminates its process. This option is only used on embedded, master-worker configured proxy, see [`--master-worker`](#master-worker). Daemon mode cannot have grace period configured, and external mode should be configured directly on HAProxy container. Defaults to `20s`.

This option should be below the controller shutdown timeout, since it will terminate the controller process despite any other internal grace period.

On [External HAProxy]({{% relref "../examples/external-haproxy" %}}), its container already uses SIGUSR1 as the stop signal, which makes HAProxy to wait for active connections to finish, just need to configure the container's grace period if need to change from its default of 30s.

See also:

* [`--shutdown-timeout`](#shutdown-timeout) command-line option.

---

## Ingress Class

More than one ingress controller is supported per Kubernetes cluster. These options allow to
override the class of ingress resources that this instance of the controller should listen to.
Classes that match will be used in the HAProxy configuration, other classes will be ignored.
Ingress resources without class name and without class annotation is also ignored since v0.12,
add the command-line option `--watch-ingress-without-class` to also listen to these ingress.

These options have a new behavior since v0.12, see the corresponding documentation if using an
older controller version.

* `--ingress-class`: defines the value of `kubernetes.io/ingress.class` annotation this controller
should listen to. The default value is `haproxy` if not declared.
* `--controller-class`: by default, HAProxy Ingress will watch IngressClasses whose
`spec.controller` name is `haproxy-ingress.github.io/controller`. All ingress resources that
link to these IngressClasses will be added to the configuration. The `--controller-class`
command-line option customizes the controller name, allowing to run more than one HAProxy Ingress
in the same cluster. Configuring `--controller-class=staging` would listen to IngressClasses whose
controller name is `haproxy-ingress.github.io/controller/staging`.
* `--ingress-class-precedence`: defines if IngressClass resource should take precedence over
kubernetes.io/ingress.class annotation if both are defined and conflicting.
* `--watch-ingress-without-class`: defines if this controller should also listen to ingress resources
that doesn't declare neither the `kubernetes.io/ingress.class` annotation nor the
`<ingress>.spec.ingressClassName` field. The default since v0.12 is to ignore ingress without class
annotation and class name.
* `--disable-ingress-class-api`: Since v0.16. Configures controller to not list or watch IngressClass API, useful on deployments that cannot allow controller to have cluster permission. If configured, the only way to watch ingress resources is using the deprecated, but still supported `kubernetes.io/ingress.class` annotation, or use `--watch-ingress-without-class`.
* `--ignore-ingress-without-class`: this option is ignored since v0.12. Use
`--watch-ingress-without-class` instead.

See also:

* [Class matter]({{% relref "keys/#class-matter" %}}) in the Configuration Keys doc
* https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class

---

## kubeconfig

* `--kubeconfig`

Ingress controller will try to connect to the Kubernetes master using environment variables and a
service account. This behavior can be changed using `--kubeconfig` argument that reference a
kubeconfig file with master endpoint and credentials. This is a mandatory argument if the controller
is deployed outside of the Kubernetes cluster.

---

## local-filesystem-prefix

* `--local-filesystem-prefix`

Since v0.14

Enables HAProxy Ingress to run in local mode. Define `--local-filesystem-prefix` with a temporary
directory HAProxy Ingress should create and maintain all the configuration files. Useful for local
deployment. Start HAProxy Ingress in the root directory of the repository when using
`--local-filesystem-prefix`, or simply use via `make run`.

---

## Logging

Since v0.14

Logging configuration options.

* `--log-zap`: Configures [zap](https://pkg.go.dev/go.uber.org/zap) as the controller's logger sink. [klog](https://github.com/kubernetes/klog) output is used if not enabled. Most of the logging options need zap enabled.
* `--log-dev`: Defines if development style logging should be used. Defaults to production. Needs `--log-zap` enabled.
* `--log-caller`: Defines if the log output should add a reference of the caller with file name and line number. Defaults to not add. Needs `--log-zap` enabled.
* `--log-enable-stacktrace`: Defines if error output should add stracktraces. Defaults to not add. Needs `--log-zap` enabled.
* `--log-encoder`: Defines the log encoder. Options are: `console` or `json`. Defaults to `json` if `--log-dev` is disabled and `console` if `--log-dev` is enabled. Needs `--log-zap` enabled.
* `--log-encode-time`: Configures the encode time used in the logs. Options are: `rfc3339nano`, `rfc3339`, `iso8601`, `millis`, `nanos`. Defaults to `rfc3339nano` if `--log-dev` is disabled and `iso8601` if `--log-dev` is enabled. Needs `--log-zap` enabled.
* `--v`: Number of the log level verbosity. 1: info; 2: add low verbosity debug. Defaults to 2.

---

## master-socket

* `--master-socket`

Since v0.12

Configures HAProxy Ingress to use an external haproxy deployment in master-worker mode. This option
receives the unix socket of the master CLI. The default value is an empty string, which will
instruct the controller to start and manage the embedded haproxy instead of an external instance.

The following conditions should be satisfied in order to an external haproxy work properly:

1. The following paths should be shared between HAProxy Ingress and the external haproxy: `/etc/haproxy`, `/var/lib/haproxy`, `/var/run/haproxy`. HAProxy Ingress must have write access to all of them, external haproxy should have write access to `/var/run/haproxy`. This can be made using a sidecar container and k8s' emptyDir, or a remote file system provided that it updates synchronously and supports unix sockets
1. Start the external haproxy with:
  * `-S /var/run/haproxy/master.sock,mode,600`. `mode 600` isn't mandatory but recommended;
  * `-f /etc/haproxy`
1. HAProxy Ingress image has a `--init` command-line option which creates an initial valid configuration file, this allows the external haproxy to bootstraps successfully. This option can be used as an init container.

See also:

* [example]({{% relref "../examples/external-haproxy" %}}) page.
* [External]({{% relref "keys#external" %}}) and [Master-worker]({{% relref "keys#master-worker" %}}) configuration keys

---

## master-worker

* `--master-worker`

Since v0.14

Defines if haproxy should be configured in master-worker mode. If `false`, one single process
is forked in the background. If `true`, a master process is started in the foreground and can
be used to manage current and old worker processes. The default value is `false` in v0.14, which
preserves historical behavior of HAProxy Ingress. v0.15 and newer defaults to `true` if not
declared. External HAProxy deployment needs master-worker mode and will enforce
`--master-worker` as `true` if configured.

---

## max-old-config-files

* `--max-old-config-files`

Everytime a configuration change need to update HAProxy, a configuration file is rewritten even if
dynamic update is used. By default the same file is recreated and the old configuration is lost.
Use `--max-old-config-files` to configure after how much files Ingress controller should start to
remove old configuration files. If `0`, the default value, a single `haproxy.cfg` is used.

---

## publish-address

* `--publish-address`

Since v0.15

Defines a comma separated list of hostname or IP addresses that should be used to configure
ingress status. This option cannot be used if [`--publish-service`](#publish-service) is configured.

See also:

* [`--update-status`](#update-status) command-line option
* [`--publish-service`](#publish-service) command-line option

---

## publish-service

* `--publish-service`

Some infrastructure tools like `external-DNS` relay in the ingress status to created access routes to the services exposed with ingress object.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
...
status:
  loadBalancer:
    ingress:
    - hostname: <ingressControllerLoadbalancerFQDN>
```

Use `--publish-service=namespace/servicename` to indicate the services fronting the ingress controller. The controller mirrors the address of this service's endpoints to the load-balancer status of all Ingress objects it satisfies. This option cannot be used if [`--publish-address`](#publish-address) is configured.

See also:

* [`--update-status`](#update-status) command-line option
* [`--publish-address`](#publish-address) command-line option

---

## rate-limit-update

* `--rate-limit-update`

Use `--rate-limit-update` to change how much time to wait between two consecutive configuration updates.
A configuration update is the process of read all enqueued Kubernetes events, reflect in the HAProxy
model and immediately apply everything that does not need a reload, eg server certificate endpoint
updates. Note that the first configuration update is always immediate, the delay will only prevent
two or more consecutive updates in the same time frame - the second update will be enqueued and
processed later, satisfying the rate limit configuration. Moreover, updates will only happen if
Kubernetes reports changing events. The default value is `0.5` which means to wait two seconds between
two consecutive configuration changes.

Up to v0.12 this was the only way to limit how often HAProxy would be reloaded, but this also prevents
to dynamically update HAProxy as fast as possible. v0.13 adds [`--reload-interval`](#reload-interval),
which allows a higher rate limit update with a lower rate of reloads.

See also [`--reload-interval`](#reload-interval).

---

## reload-interval

* `--reload-interval`

Since v0.13

Configures the minimal time between two consecutive HAProxy reloads. The default value is `0`,
which means to always reload HAProxy just after a configuration change requires a reload. The
interval should be configured with a time suffix, e.g., `30s` means that if two distinct and
consecutive configuration changes enforce a reload, the second reload will be enqueued until 30
seconds have passed from the first one, applying every new configuration changes made between
this interval.

Higher values help to limit the number of active instances and save some memory on large clusters
with long connections. Note however that, if two consecutive updates require a reload, the second
one will delay up to the configured duration to be reflected by HAProxy.

---

## reload-retry

* `--reload-retry`

How long HAProxy Ingress should wait before trying to reload HAProxy if an error happens. Defaults to `30s`.

---

## reload-strategy

* `--reload-strategy`

The `--reload-strategy` command-line argument is used to select which reload strategy
HAProxy should use. The following options are available:

* `native`: Uses native HAProxy reload option `-sf`.
* `reusesocket`: (starting on v0.6) Uses HAProxy `-x` command-line option to pass the listening sockets between old and new HAProxy process, allowing hitless reloads. This is the default option since v0.8.
* `multibinder`: (deprecated on v0.6) Uses GitHub's [multibinder](https://github.com/github/multibinder). [GLB part 2: HAProxy zero-downtime, zero-delay reloads with multibinder](https://githubengineering.com/glb-part-2-haproxy-zero-downtime-zero-delay-reloads-with-multibinder/)
describes how it works.

---

## report-node-internal-ip-address

* `--report-node-internal-ip-address`

Sets whether the node's IP address returned in the ingress status should be the node's internal
instead of the external IP address. Defaults to `false`. This option is ignored if either [`--publish-service`](#publish-service) or [`--publish-address`](#publish-address) are configured.

See also:

* [`-update-status`](#update-status) command-line option

---

## shutdown-timeout

* `--shutdown-timeout`

Defines the amount of time the controller should wait, after receiving a SIGUSR1, SIGINT or SIGTERM, for all of its internal services to gracefully stop before shutting down the process. It starts to count after [`--wait-before-shutdown`](#wait-before-shutdown) has been passed, if configured. Defaults to `25s`.

If changing its default value, consider also to change [`--haproxy-grace-period`](#haproxy-grace-period) to at most `1s` less than the shutdown timeout. If changing the shutdown timeout to `30s` or more, remember to also configure controller's pod grace period to at least `1s` more than the sum of the `--wait-before-shutdown` and the `--shutdown-timeout`.

See also:

* [`--wait-before-shutdown`](#wait-before-shutdown) command-line option.
* [`--haproxy-grace-period`](#haproxy-grace-period) command-line option.

---

## sort-backends

* `--sort-backends`

Defines if backend's endpoints should be sorted by name. Since v0.8 the endpoints will stay in the
same order found in the Kubernetes' endpoint objects if `--sort-backends` is missing. This option
has less precedence than `--sort-endpoints-by` if both are declared.

In v0.7 and older version, if `--sort-backends` is missing, HAProxy Ingress randomly shuffle endpoints
on each reload in order to avoid requesting always the same backends just after haproxy reloads.

Sorting backends by name has a real effect only if using a distinct [backend-server-naming]({{% relref "keys#backend-server-naming" %}})
option, because the default value builds the server name using a numeric sequence.

See also:

* [backend-server-naming]({{% relref "keys#backend-server-naming" %}}) configuration key
* [sort-endpoints-by]({{% relref "#sort-endpoints-by" %}}) command-line option

---

## sort-endpoints-by

* `--sort-endpoints-by`

Since v0.11

Defines in which order the endpoints of a backend should be sorted.

* `endpoint`: this is the default value, uses the same order declared in the Kubernetes' Endpoint objects. `ep` is an alias to `endpoint`
* `ip`: sort endpoints by the IP and port of the destination server
* `name`: sort the endpoints by the name given to the server, see also [backend-server-naming]({{% relref "keys#backend-server-naming" %}})
* `random`: randomly shuffle the endpoints every time haproxy needs to be reloaded, this option avoids to always send requests to the same endpoints depending on the balancing algorithm

---

## Stats

Configures an endpoint with statistics, debugging and health checks. The following URIs are provided:

* `/healthz`: a healthz URI for the haproxy-ingress
* `/readyz`: a readiness URI for the haproxy-ingress
* `/metrics`: Prometheus compatible metrics exporter
* `/acme/check` (`POST`): starts check for missing, expiring or outdated certificates controlled by acme client. Should be issued in the leader.
* `/debug/pprof`: profiling tools
* `/build`: build information - controller name, version, git commit hash and repository
* `/stop`: stops haproxy-ingress controller

Options:
* `--health-check-path`: Defines the URL to be used as a health check for haproxy ingress. Defaults to `/healthz`.
* `--health-addr`: Defines the address haproxy-ingress should listen to. Defaults to `:10254`.
* `--healthz-port`: (deprecated since v0.15) Defines the port number haproxy-ingress should listen to. Use `--healthz-addr` instead. Defaults to `10254`.
* `--profiling`: Configures if the profiling URI should be enabled. Defaults to `true`.
* `--ready-check-path`: Defines the URL to be used as a readiness check for haproxy ingress. Defaults to `/readyz`.
* `--stats-collect-processing-period`: Defines the interval between two consecutive readings of haproxy's `Idle_pct`, used to generate `haproxy_processing_seconds_total` metric. haproxy updates Idle_pct every `500ms`, which makes that the best configuration value, and it's also the default if not configured. Values greater than `500ms` will produce a less accurate collect. Change to 0 (zero) to disable this metric.
* `--stop-handler`: Allows to stop the controller via a POST request to `<host>:<healthzport>/stop` endpoint. Default value is `false`.

---

## sync-period

* `--sync-period`

Configures the default resync period of the Kubernetes client's informer factory. Defaults to 10
minutes.

---

## tcp-services-configmap

* `--tcp-services-configmap`

Configure `--tcp-services-configmap` argument with `namespace/configmapname` resource with TCP
services and ports that HAProxy should listen to. Use the HAProxy's port number as the key of the
ConfigMap.

{{< alert title="Note" >}}
Starting on v0.13, `--tcp-services-configmap` is deprecated. Use [`tcp-service-port`]({{% relref "keys#tcp-services" %}}) configuration key instead.

The documentation refers to "ConfigMap based TCP" when taking about this configuration options, and it refers to "TCP Service" when talking about to the new, annotation based TCP configuration.
{{< /alert >}}

The value of the ConfigMap entry is a colon separated list of the following arguments:

1. `<namespace>/<service-name>`, mandatory, is the well known notation of the service that will receive incoming connections.
1. `<portnumber>`, mandatory, is the port number the upstream service is listening - this is not related to the listening port of HAProxy.
1. `<in-proxy>`, optional, should be defined as `PROXY` if HAProxy should expect requests using the [PROXY](https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt) protocol. Leave empty to not use PROXY protocol. This is usually used only if there is another load balancer in front of HAProxy which supports the PROXY protocol. PROXY protocol v1 and v2 are supported.
1. `<out-proxy>`, optional, should be defined as `PROXY` or `PROXY-V2` if the upstream service expect connections using the PROXY protocol v2. Use `PROXY-V1` instead if the upstream service only support v1 protocol. Leave empty to connect without using the PROXY protocol.
1. `<namespace/secret-name>`, optional, used to configure SSL/TLS over the TCP connection. Secret should have `tls.crt` and `tls.key` pair used on TLS handshake. Leave empty to not use ssl-offload. A filename prefixed with `file://` can be used containing both certificate and private key in PEM format, eg `file:///dir/crt.pem`.
1. `<check-interval>`, added in v0.10, optional and defaults to `2s`, configures a TCP check interval. Declare `-` (one single dash) as the time to disable it. Valid time is a number and a mandatory suffix: `us`, `ms`, `s`, `m`, `h` or `d`.
1. `<namespace/secret-name>`, added in v0.10, optional, used to configure SSL/TLS client verification over the TCP connection. Secret should have `ca.crt` and optional `ca.crl`. Leave empty to not use ssl client verification. A filename prefixed with `file://` can be used containing the CA bundle in PEM format, and optionally followed by a comma and the filename with the crl, eg `file:///dir/ca.pem` or `file:///dir/ca.pem,/dir/crl.pem`.

Optional fields can be skipped using consecutive colons.

In the example below:

```
...
data:
  "3306": "default/mysql:3306::::-"
  "5432": "default/pgsql:5432::::1s"
  "8000": "system-prod/http:8000::PROXY-V1"
  "9900": "system-prod/admin:9900:PROXY::system-prod/tcp-9900"
  "9990": "system-prod/admin:9999::PROXY-V2"
  "9995": "system-prod/admin:9900:::system-prod/tcp-9995::system-prod/tcp-9995-ca"
  "9999": "system-prod/admin:9999:PROXY:PROXY"
```

HAProxy will listen 7 new ports:

* `3306` will proxy to a `mysql` service on `default` namespace. Check interval is disabled.
* `5432` will proxy to a `pgsql` service on `default` namespace. Check interval is defined to run on every second.
* `8000` will proxy to `http` service, port `8000`, on the `system-prod` namespace. The upstream service will expect connections using the PROXY protocol but it only supports v1.
* `9900` will proxy to `admin` service, port `9900`, on the `system-prod` namespace. Clients should connect using the PROXY protocol v1 or v2. Upcoming connections should be encrypted, HAProxy will ssl-offload data using crt/key provided by `system-prod/tcp-9900` secret.
* `9990` and `9999` will proxy to the same `admin` service and `9999` port and the upstream service will expect connections using the PROXY protocol v2. The HAProxy frontend, however, will only expect PROXY protocol v1 or v2 on it's port `9999`.
* `9995` will proxy to `admin` service, port `9900`, on the `system-prod` namespace. Upcoming connections should be encrypted, HAProxy will ssl-offload data using crt/key provided by `system-prod/tcp-9995` secret. Furthermore, clients must present a certificate that will be valid under the certificate authority (and optional certificate revocation list) provided in the `system-prod/tcp-9995-ca` secret.

Note: Check interval was added in v0.10 and defaults to `2s`. All declared services has check interval enabled, except `3306` which disabled it.

See also:

* [TCP Services]({{% relref "keys#tcp-services" %}}) configuration keys

---

## track-old-instances

* `--track-old-instances`

Since v0.14

Creates an internal list of connections to old HAProxy instances. These connections are used to
read or send data to stopping instances, which is usually serving long lived connections like
TCP services or websockets.

Enabling this option will make old HAProxy instances to not stop before `timeout-stop` timeout,
even if all the remaining sessions finish, so only enable it if using a feature that requests
it.

See also:

* [`close-sessions-duration`]({{% relref "keys#close-sessions-duration" %}}) configuration key

---

## update-status

* `--update-status`

Indicates whether the ingress controller should update the `status` attribute of all the Ingress
resources that this controller is tracking. The default value is `true`. Ingress status is updated
with the external IPs of the ingress endpoints, and these IPs can be generated on distinct ways:

* Configuring [`--publish-service`](#publish-service) with a Kubernetes service resource name
fronting the ingress controller pods
* Configuring [`--publish-address`](#publish-address) with hostname and/or IP addresses of ingress hosts/pods
* Node IP where ingress controllers are running are used if neither `--publish-service` nor `--publish-address` are configured. Node's External IP is used by default, add [`--report-node-internal-ip-address`](#report-node-internal-ip-address) to use internal IP instead.

When enabled, `--update-status` enforces a leader election. A leader must be elected to update
Ingress API. See also [`--election-id`](#election-id).

See also:

* [`--publish-service`](#publish-service) command-line option
* [`--publish-address`](#publish-address) command-line option
* [`--report-node-internal-ip-address`](#report-node-internal-ip-address) command-line option
* [`--update-status-on-shutdown`](#update-status-on-shutdown) command-line option

---

## update-status-on-shutdown

* `--update-status-on-shutdown`

Indicates whether the ingress controller should update the `status` attribute of all the Ingress
resources that this controller is tracking when the controller is being stopped.  Defaults to
`true`.

See also:

* [`--update-status`](#update-status) command-line option

---

## validate-config

* `--validate-config`

Determines whether the resulting configuration files should be validated when a dynamic update was
applied. Default value is `false`, which means the validation will only happen when HAProxy needs to
be reloaded.

If validation fails, HAProxy Ingress will log the error and set the metric
`haproxyingress_update_success` to zero, indicating failure.

---

## verify-hostname

* `--verify-hostname`

Ingress resources has `spec/tls[]/secretName` attribute to override the default X509 certificate.
As a default behavior the certificates are validated against the hostname in order to match the
SAN extension or CN (CN only up to `v0.4`). Invalid certificates, ie certificates which doesn't
match the hostname are discarded and a warning is logged into the ingress controller logging.

Use `--verify-hostname=false` argument to bypass this validation. If used, HAProxy will provide
the certificate declared in the `secretName` ignoring if the certificate is or is not valid.

---

## version

* `--version`

Show release information about the ingress controller.

---

## wait-before-shutdown

* `--wait-before-shutdown`

If argument `--wait-before-shutdown` is defined, controller will wait defined time in seconds
before it starts shutting down components when SIGTERM was received. By default, it's 0, which means
the controller starts shutting down itself right after signal was sent.

This option, along with [`--shutdown-timeout`](#shutdown-timeout), should be less than the controller's pod grace period; otherwise, controller should be SIGKILLed before its timeout expires.

See also:

* [`--shutdown-timeout`](#shutdown-timeout) command-line option.

---

## wait-before-update

* `--wait-before-update`

Since v0.11

Defines the amount of time to wait before start a reconciliation event and update haproxy.
The purpose of this delay is to group all the notifications of a batch update and apply pending
changes in one single shot. The default value is `200ms`.

---

## watch-gateway

* `--watch-gateway`

Since v0.13

Enables Gateway API watch and parse. This option is enabled by default since v0.14 and controller
will start the listener only if the Gateway API CRDs are found. Add `--watch-gateway=false`
option to instruct the controller to not try to listen to the CRDs. The controller should be
restarted if the CRDs are installed after starting the controller. See also the Gateway API
configuration [doc]({{% relref "gateway-api" %}}).

When enabled, `--watch-gateway` enforces a leader election. A leader must be elected to update Gateway API status. See also [`--election-id`](#election-id).

---

## watch-namespace

* `--watch-namespace`

By default the proxy will be configured using all namespaces from the Kubernetes cluster. Use
`--watch-namespace` with the name of a namespace to watch and build the configuration of a
single namespace.
