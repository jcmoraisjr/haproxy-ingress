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
| [`--controller-class`](#ingress-class)                  | suffix                     | `""`                    | v0.12 |
| [`--default-backend-service`](#default-backend-service) | namespace/servicename      | haproxy's 404 page      |       |
| [`--default-ssl-certificate`](#default-ssl-certificate) | namespace/secretname       | fake, auto generated    |       |
| [`--disable-api-warnings`](#disable-api-warnings)       | [true\|false]              | `false`                 | v0.12 |
| [`--disable-pod-list`](#disable-pod-list)               | [true\|false]              | `false`                 | v0.11 |
| [`--healthz-port`](#stats)                              | port number                | `10254`                 |       |
| [`--ingress-class`](#ingress-class)                     | name                       | `haproxy`               |       |
| [`--kubeconfig`](#kubeconfig)                           | /path/to/kubeconfig        | in cluster config       |       |
| [`--master-socket`](#master-socket)                     | socket path                | use embedded haproxy    | v0.12 |
| [`--max-old-config-files`](#max-old-config-files)       | num of files               | `0`                     |       |
| [`--profiling`](#stats)                                 | [true\|false]              | `true`                  |       |
| [`--publish-service`](#publish-service)                 | namespace/servicename      |                         |       |
| [`--rate-limit-update`](#rate-limit-update)             | uploads per second (float) | `0.5`                   |       |
| [`--reload-strategy`](#reload-strategy)                 | [native\|reusesocket]      | `reusesocket`           |       |
| [`--sort-backends`](#sort-backends)                     | [true\|false]              | `false`                 |       |
| [`--sort-endpoints-by`](#sort-endpoints-by)             | [endpoint\|ip\|name\|random] | `endpoint`            | v0.11 |
| [`--stats-collect-processing-period`](#stats)           | time                       | `500ms`                 | v0.10 |
| [`--tcp-services-configmap`](#tcp-services-configmap)   | namespace/configmapname    | no tcp svc              |       |
| [`--verify-hostname`](#verify-hostname)                 | [true\|false]              | `true`                  |       |
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
* `--acme-election-id`: prefix of the ConfigMap name used to store the leader election data. Only the leader of a haproxy-ingress cluster should start the authorization and sign certificate process. Defaults to `acme-leader`.
* `--acme-fail-initial-duration`: the starting time to wait and retry after a failed authorization and sign process. Defaults to `5m`.
* `--acme-fail-max-duration`: the time between retries of failed authorization will exponentially grow up to the max duration time. Defaults to `8h`.
* `--acme-secret-key-name`: secret name used to store the client private key. Defaults to `acme-private-key`. A new key, hence a new client, is created if the secret does not exist.
* `--acme-server`: mandatory, starts a local server used to answer challenges from the acme environment. This option should be provided on all haproxy-ingress instances to the certificate signing work properly.
* `--acme-token-configmap-name`: the ConfigMap name used to store temporary tokens generated during the challenge. Defaults to `acme-validation-tokens`. Such tokens need to be stored in k8s because any haproxy-ingress instance might receive the request from the acme environment.
* `--acme-track-tls-annotation`: defines if ingress objects with annotation `kubernetes.io/tls-acme: "true"` should also be tracked. Defaults to `false`.

See also:

* [acme configuration keys]({{% relref "keys/#acme" %}}) doc, which has also an overview on how acme works on haproxy-ingress

---

## --allow-cross-namespace

`--allow-cross-namespace` argument, if added, will allow reading secrets from one namespace to an
ingress resource of another namespace. The default behavior is to deny such cross namespace reading.
This adds a breaking change from `v0.4` to `v0.5` on `haproxy-ingress.github.io/auth-tls-secret`
annotation, where cross namespace reading were allowed without any configuration.

See also:

* [cross namespace]({{% relref "keys#cross-namespace" %}}) configuration keys.

---

## --annotations-prefix

Configures a comma-separated list of annotations prefix that the controller should look for when
parsing services and ingress objects. The default value is `haproxy-ingress.github.io,ingress.kubernetes.io`.
The default configuration means declare eg a SSL Redirect annotation with
`haproxy-ingress.github.io/ssl-redirect: "true"` or `ingress.kubernetes.io/ssl-redirect: "true"`.

The order of the declaration is used to priorize one of them if the same configuration key is
declared twice - if two distinct prefix is used to configure the same key in the same ingress or
service resource, the value of the annotation with the prefix that was configured first in this
command-line option is used.

Annotations with other prefix or without any prefix are ignored. This allows to use HAProxy Ingress
with other ingress controllers that shares ingress and service resources without conflicting each
other.

---

## --apiserver-host

Allows you to specify an explicit host for the Kubernetes API server, in the format of
`protocol://address:port`, e.g., `http://localhost:8080`.  If this value isn't specified, the
assumption is that the binary is running inside a Kubernetes cluster and local discovery will be
attempted.

---

## --backend-shards

Defines how many files should be used to configure the haproxy backends. The default value is
0 (zero) which uses one single file to configure the whole haproxy process. Values greather than
0 (zero) splits the backend configuration into separated files. Only files with changed backends
are parsed and written to disk, reducing io and cpu usage on big clusters - about 1000 or more
services.

---

## --buckets-response-time

Configures the buckets of the histogram `haproxyingress_haproxy_response_time_seconds`, used to compute the response time of the haproxy's admin socket. The response time unit is in seconds.

---

## --default-backend-service

Defines the `namespace/servicename` that should be used if the incoming request doesn't match any
hostname, or the requested path doesn't match any location within the desired hostname. An internal
404 error page is used if not declared.

---

## --default-ssl-certificate

Defines the `namespace/secretname` of the default certificate that should be used if ingress
resources using TLS configuration doesn't provide it's own certificate.  A filename prefixed
with `file://` can be used, containing both certificate and private key in PEM format, eg
`file:///dir/crt.pem`.

A self-signed fake certificate is used if not declared, the secret or the file is not found.

## --disable-api-warnings

Since v0.12.4

Disable warning logs sent from the API server. Most of the warnings are related with API
deprecation. The default behavior is to log all API server warnings.

---

## --disable-pod-list

Since v0.11

Disables in memory pod list and also pod watch for changes. Pod list and watch is used by `drain-support` option, which will not work if pod list is disabled. Blue/green and `session-cookie-value-strategy` set to `pod-uid` also use pod list if enabled, otherwise k8s api is called if needed. The default value is `false`, which means pods will be watched and listed in memory.

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
* `--watch-ingress-without-class`: defines if this controller should also listen to ingress resources
that doesn't declare neither the `kubernetes.io/ingress.class` annotation nor the
`<ingress>.spec.ingressClassName` field. The default since v0.12 is to ignore ingress without class
annotation and class name.
* `--ignore-ingress-without-class`: this option is ignored since v0.12. Use
`--watch-ingress-without-class` instead.

See also:

* [Class matter]({{% relref "keys/#class-matter" %}}) in the Configuration Keys doc
* https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class

---

## --kubeconfig

Ingress controller will try to connect to the Kubernetes master using environment variables and a
service account. This behavior can be changed using `--kubeconfig` argument that reference a
kubeconfig file with master endpoint and credentials. This is a mandatory argument if the controller
is deployed outside of the Kubernetes cluster.

---

## --master-socket

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

## --max-old-config-files

Everytime a configuration change need to update HAProxy, a configuration file is rewritten even if
dynamic update is used. By default the same file is recreated and the old configuration is lost.
Use `--max-old-config-files` to configure after how much files Ingress controller should start to
remove old configuration files. If `0`, the default value, a single `haproxy.cfg` is used.

---

## --publish-service

Some infrastructure tools like `external-DNS` relay in the ingress status to created access routes to the services exposed with ingress object.

```
apiVersion: networking.k8s.io/v1
kind: Ingress
...
status:
  loadBalancer:
    ingress:
    - hostname: <ingressControllerLoadbalancerFQDN>
```

Use `--publish-service=namespace/servicename` to indicate the services fronting the ingress controller. The controller mirrors the address of this service's endpoints to the load-balancer status of all Ingress objects it satisfies.

---

## --rate-limit-update

Use `--rate-limit-update` to change how much time to wait between HAProxy reloads. Note that the first
update is always immediate, the delay will only prevent two or more updates in the same time frame.
Moreover reloads will only occur if the cluster configuration has changed, otherwise no reload will
occur despite of the rate limit configuration.

This argument receives the allowed reloads per second. The default value is `0.5` which means no more
than one reload will occur within `2` seconds. The lower limit is `0.05` which means one reload within
`20` seconds. The highest one is `10` which will allow ingress controller to reload HAProxy up to 10
times per second.

---

## --reload-strategy

The `--reload-strategy` command-line argument is used to select which reload strategy
HAProxy should use. The following options are available:

* `native`: Uses native HAProxy reload option `-sf`.
* `reusesocket`: (starting on v0.6) Uses HAProxy `-x` command-line option to pass the listening sockets between old and new HAProxy process, allowing hitless reloads. This is the default option since v0.8.
* `multibinder`: (deprecated on v0.6) Uses GitHub's [multibinder](https://github.com/github/multibinder). This [link](https://githubengineering.com/glb-part-2-haproxy-zero-downtime-zero-delay-reloads-with-multibinder/)
describes how it works.

---

## --sort-backends

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

## --sort-endpoints-by

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
* `/metrics`: Prometheus compatible metrics exporter
* `/acme/check` (`POST`): starts check for missing, expiring or outdated certificates controlled by acme client. Should be issued in the leader.
* `/debug/pprof`: profiling tools
* `/build`: build information - controller name, version, git commit hash and repository
* `/stop`: stops haproxy-ingress controller

Options:

* `--healthz-port`: Defines the port number haproxy-ingress should listen to. Defaults to `10254`.
* `--profiling`: Configures if the profiling URI should be enabled. Defaults to `true`.
* `--stats-collect-processing-period`: Defines the interval between two consecutive readings of haproxy's `Idle_pct`, used to generate `haproxy_processing_seconds_total` metric. haproxy updates Idle_pct every `500ms`, which makes that the best configuration value, and it's also the default if not configured. Values higher than `500ms` will produce a less accurate collect. Change to 0 (zero) to disable this metric.

---

## --tcp-services-configmap

Configure `--tcp-services-configmap` argument with `namespace/configmapname` resource with TCP
services and ports that HAProxy should listen to. Use the HAProxy's port number as the key of the
ConfigMap.

{{% alert title="Note" %}}
Starting on v0.13, `--tcp-services-configmap` is deprecated. Use [`tcp-service-port`]({{% relref "keys#tcp-services" %}}) configuration key instead.

The documentation refers to "ConfigMap based TCP" when taking about this configuration options, and it refers to "TCP Service" when talking about to the new, annotation based TCP configuration.
{{% /alert %}}

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
* `9995` will proxy to `admin` service, port `9900`, on the `system-prod` namespace. Upcoming connections should be encrypted, HAProxy will ssl-offload data using crt/key provided by `system-prod/tcp-9995` secret. Furthermore, clients must present a certificate that will be valid under the certificate authority (and optional certificate revocation list) provded in the `system-prod/tcp-9995-ca` secret.

Note: Check interval was added in v0.10 and defaults to `2s`. All declared services has check interval enabled, except `3306` which disabled it.

See also:

* [TCP Services]({{% relref "keys#tcp-services" %}}) configuration keys

---

## --verify-hostname

Ingress resources has `spec/tls[]/secretName` attribute to override the default X509 certificate.
As a default behavior the certificates are validated against the hostname in order to match the
SAN extension or CN (CN only up to `v0.4`). Invalid certificates, ie certificates which doesn't
match the hostname are discarded and a warning is logged into the ingress controller logging.

Use `--verify-hostname=false` argument to bypass this validation. If used, HAProxy will provide
the certificate declared in the `secretName` ignoring if the certificate is or is not valid.

---

## --wait-before-shutdown

If argument `--wait-before-shutdown` is defined, controller will wait defined time in seconds
before it starts shutting down components when SIGTERM was received. By default, it's 0, which means
the controller starts shutting down itself right after signal was sent.

---

## --wait-before-update

Since v0.11

Defines the amount of time to wait before start a reconciliation event and update haproxy.
The purpose of this delay is to group all the notifications of a batch update and apply pending
changes in one single shot. The default value is `200ms`.

---

## --watch-gateway

Since v0.13

Enables Gateway API watch and parse. The Gateway API CRDs should be installed before enable
this option. See also the Gateway API configuration [doc]({{% relref "gateway-api" %}}).

---

## --watch-namespace

By default the proxy will be configured using all namespaces from the Kubernetes cluster. Use
`--watch-namespace` with the name of a namespace to watch and build the configuration of a
single namespace.
