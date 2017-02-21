# HAProxy Ingress controller

[Ingress](https://kubernetes.io/docs/user-guide/ingress/) controller implementation for [HAProxy](http://www.haproxy.org/) loadbalancer.

# Usage

All docs are maintained on Ingress repository:

* Start with [deployment](https://github.com/kubernetes/ingress/tree/master/examples/deployment/haproxy) instructions
* See  [TLS termination](https://github.com/kubernetes/ingress/tree/master/examples/tls-termination/haproxy) on how to enable `https` url

# Configuration

HAProxy Ingress can be configured per ingress resource using annotations, or globally
using ConfigMap. It is also possible to change de default template mounting a new
template file at `/usr/local/etc/haproxy/haproxy.tmpl`.

## Annotations

The following annotation is supported:

|Name|Type|
|---|---|
|`ingress.kubernetes.io/whitelist-source-range`|CIDR|

Details about the supported options can be found at Ingress Controller
[annotations doc](https://github.com/kubernetes/ingress/blob/master/controllers/nginx/configuration.md#annotations).

## ConfigMap

If using ConfigMap to configure HAProxy Ingress, use
`--configmap=<namespace>/<configmap-name>` argument on HAProxy Ingress deployment.
A ConfigMap can be created with `kubectl create configmap`.

The following parameter is supported:

|Name|Type|
|---|---|
|[`syslog-endpoint`](#syslog-endpoint)|UDP IP:port|

### syslog-endpoint

Configure the UDP syslog endpoint where HAProxy should send access logs.
