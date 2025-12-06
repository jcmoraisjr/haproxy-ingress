---
title: "Gateway API"
linkTitle: "Gateway API"
weight: 2
description: >
  Configure HAProxy using Gateway API resources.
---

[Gateway API](https://gateway-api.sigs.k8s.io/) is a collection of Kubernetes resources that can be installed as [Custom Resource Definitions](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/). Just like Ingress resources, Gateway API resources are used to configure incoming HTTP/s, TLS and TCP requests to the in cluster applications. HAProxy Ingress v0.17 partially supports the Gateway API spec, `v1beta1` and `v1` versions.

## Installation

The following steps configure the Kubernetes cluster and HAProxy Ingress to read and parse Gateway API resources:

* Manually install the Gateway API CRDs from the experimental channel - HAProxy Ingress supports TCPRoute and TLSRoute, they are not included in the standard channel. See the Gateway API [documentation](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api)
    * ... or simply `kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.1/experimental-install.yaml`
* Start (or restart) the controller

See below the [getting started steps](#getting-started).

### Command-line tool

Gateway API has also a command-line tool, see how it works and installation instructions: https://github.com/kubernetes-sigs/gwctl

## Conformance

Most of the Gateway API `v1beta1` and `v1` specs are implemented in v0.17 release. The following list describes what is not supported:

* Target Services can be annotated with [Backend or Path scoped]({{% relref "keys#scope" %}}) configuration keys, this will continue to be supported.
* Gateway API resources don't support annotations, this should continue to be unsupported. Extensions to the Gateway API spec will be added in the extension points of the API.
* The controller doesn't implement partial parsing yet for Gateway API resources, changes should be a bit slow on clusters with thousands of Ingress, Gateway API resources or Services.
* Gateway's Addresses is not implemented - binding addresses use the global [bind-ip-addr]({{% relref "keys#bind-ip-addr" %}}) configuration.
* Gateway's Hostname only supports empty/absence of Hostname or a single `*`, any other string will override the HTTPRoute Hostnames configuration without any merging.
* HTTPRoute's Rules and BackendRefs don't support Filters.

## Ingress

A single HAProxy Ingress deployment can manage Ingress, and also `v1beta1` and `v1` Gateway API resources in the same Kubernetes cluster. If the same hostname and path with the same path type is declared in the Gateway API and Ingress, the Gateway API wins and a warning is logged. Ingress resources will continue to be supported in future controller versions, without side effects, and without the need to install the Gateway API CRDs.

## Getting started

Add the following steps to the [Getting Started guide]({{% relref "/docs/getting-started" %}}) in order to expose the echoserver service along with the Gateway API:

[Manually install](https://gateway-api.sigs.k8s.io/v1alpha2/guides/getting-started/#installing-gateway-api-crds-manually) the Gateway API CRDs:

```
$ kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.0.0/experimental-install.yaml
```

Restart HAProxy Ingress so it can find the just installed APIs:

```
$ kubectl --namespace ingress-controller delete pod -lapp.kubernetes.io/name=haproxy-ingress
```

A GatewayClass enables Gateways to be read and parsed by HAProxy Ingress. Create a GatewayClass with the following content:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: haproxy
spec:
  controllerName: haproxy-ingress.github.io/controller
```

### Deploy HTTP workload

Add the following deployment and service if echoserver isn't running yet:

```
$ kubectl --namespace default create deployment echoserver --image k8s.gcr.io/echoserver:1.3
$ kubectl --namespace default expose deployment echoserver --port=8080
```

Gateways create listeners and allow to configure hostnames for HTTP workloads. Create a Gateway with the following content:

Note: port and protocol attributes [have some limitations](#conformance).

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: echoserver
  namespace: default
spec:
  gatewayClassName: haproxy
  listeners:
  - name: echoserver-gw
    port: 80
    protocol: HTTP
```

HTTPRoutes configure the hostnames and target services. Create a HTTPRoute with the following content, changing `echoserver-from-gateway.local` to a hostname that resolves to a HAProxy Ingress node:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: echoserver
  namespace: default
spec:
  parentRefs:
  - name: echoserver
  hostnames:
  - echoserver-from-gateway.local
  rules:
  - backendRefs:
    - name: echoserver
      port: 8080
```

Send a request to our just configured route:

```
$ curl http://echoserver-from-gateway.local
$ wget -qO- http://echoserver-from-gateway.local
```

### Deploy TCP workload

Add the following deployment and service:

```
$ kubectl --namespace default create deployment redis --image docker.io/redis
$ kubectl --namespace default expose deployment redis --port=6379
```

A new port need to be added if HAProxy Ingress is not configured in the host network. If so, add the following snippet in `values.yaml` and apply it using Helm:

```yaml
controller:
  ...
  service:
    ...
    extraPorts:
    - port: 6379
      targetPort: 6379
```

Gateways create listeners and allow to configure the listening port for TCP workloads. Create a Gateway with the following content:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: redis
  namespace: default
spec:
  gatewayClassName: haproxy
  listeners:
  - name: redis-gw
    port: 6379
    protocol: TCP
```

TCPRoutes configure the target services. Create a TCPRoute with the following content:

```yaml
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: redis
  namespace: default
spec:
  parentRefs:
  - name: redis
  rules:
  - backendRefs:
    - name: redis
      port: 6379
```

Send a ping to the Redis server using `curl`. Change `192.168.106.2` below to the IP address of HAProxy Ingress:

```
$ curl -v telnet://192.168.106.2:6379
*   Trying 192.168.106.2:6379...
* Connected to 192.168.106.2 (192.168.106.2) port 6379
ping
+PONG
^C
```

Type `ping` and see a `+PONG` response. Press `^C` to close the connection.
