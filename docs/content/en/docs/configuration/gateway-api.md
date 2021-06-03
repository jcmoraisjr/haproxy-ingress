---
title: "Gateway API"
linkTitle: "Gateway API"
weight: 2
description: >
  Configure HAProxy using Gateway API resources.
---

[Gateway API](https://gateway-api.sigs.k8s.io/) is a collection of Kubernetes resources that can be installed as [Custom Resource Definitions](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/). Just like Ingress resources, Gateway API resources are used to configure incoming HTTP/s and TCP requests to the in cluster applications. HAProxy Ingress v0.13 partially supports the Gateway API spec.

## Installation

The following steps configure the Kubernetes cluster and HAProxy Ingress to read and parse Gateway API resources:

* Manually install the Gateway API CRDs, see the Gateway API [documentation](https://gateway-api.sigs.k8s.io/guides/getting-started/#installing-gateway-api-crds-manually)
    * ... or simply `kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd?ref=v0.3.0" | kubectl apply -f -`
* Add the controller's [`--watch-gateway`]({{% relref "command-line#watch-gateway" %}}) command-line option

See below the [getting started steps](#getting-started).

## Conformance

Gateway API spec is partially implemented in the v0.13 release. The following list describes what is (or is not) supported. All the items are already in the v0.14 backlog, except when stated otherwise:

* Target Services can be annotated with [Backend or Path scoped]({{% relref "keys#scope" %}}) configuration keys, this will continue to be supported.
* Gateway API resources doesn't support annotations, this will continue to be unsupported, extensions to the Gateway API spec will be added in the extension points of the API.
* Only the `GatewayClass`, `Gateway` and `HTTPRoute` resource definitions were implemented.
* The controller doesn't implement partial parsing yet for Gateway API resources, changes should be a bit slow on clusters with thousands of Ingress, Gateway API resources or Services.
* Gateway's Listener Port and Protocol wasn't implemented - Port uses the global [bind-port]({{% relref "keys#bind-port" %}}) configuration and Protocol is based on the presence or absence of the TLS attribute.
* Gateway's Route Namespace selector only supports `Same` or `All` namespaces.
* Gateway's Hostname only supports empty/absence of Hostname or a single `*`, any other string will override the HTTPRoute Hostnames configuration without any merging.
* HTTPRoute's Matches doesn't support Headers.
* HTTPRoute's Rules and ForwardTo doesn't support Filters.
* Resources status aren't updated.

## Ingress

A single HAProxy Ingress deployment can manage Ingress and Gateway API resources in the same Kubernetes cluster. If the same hostname and path is declared in the Gateway API and Ingress, the Gateway API wins and a warning is logged. Ingress resources will continue to be supported in future controller versions, without side effects, and without the need to install the Gateway API CRDs.

## Getting started

Add the following steps to the [Getting Started guide]({{% relref "/docs/getting-started" %}}) in order to expose the echoserver service along with the Gateway API:

[Manually install](https://gateway-api.sigs.k8s.io/guides/getting-started/#installing-gateway-api-crds-manually) the Gateway API CRDs:

```
kubectl kustomize\
 "github.com/kubernetes-sigs/gateway-api/config/crd?ref=v0.3.0" |\
 kubectl apply -f -
```

Add the [`--watch-gateway`]({{% relref "command-line#watch-gateway" %}}) command-line option in the `haproxy-ingress-values.yaml` file and [`helm upgrade ...`]({{% relref "/docs/getting-started#installation" %}}) the controller (or simply edit the deployment):

```yaml
controller:
  ...
  extraArgs:
    watch-gateway: "true"
```

A GatewayClass enables Gateways to be read and parsed by HAProxy Ingress. Create a GatewayClass with the following content:

```yaml
apiVersion: networking.x-k8s.io/v1alpha1
kind: GatewayClass
metadata:
  name: haproxy
spec:
  controller: haproxy-ingress.github.io/controller
```

Gateways create listeners and allow to configure hostnames. Create a Gateway with the following content:

Note: port and protocol attributes [have some limitations](#conformance).

```yaml
apiVersion: networking.x-k8s.io/v1alpha1
kind: Gateway
metadata:
  name: echoserver
  namespace: default
spec:
  gatewayClassName: haproxy
  listeners:
  - protocol: HTTP
    port: 80
    routes:
      kind: HTTPRoute
      selector:
        matchLabels:
          gateway: echo
```

HTTPRoutes configure the hostnames and target services. Create a HTTPRoute with the following content, changing to a hostname that resolves to a HAProxy Ingress node:

```yaml
apiVersion: networking.x-k8s.io/v1alpha1
kind: HTTPRoute
metadata:
  labels:
    gateway: echo
  name: echoserver
  namespace: default
spec:
  hostnames:
  - echoserver-from-gateway.192.168.1.11.nip.io
  rules:
  - forwardTo:
    - serviceName: echoserver
      port: 8080
```

Send a request to our just configured route:

```
curl http://echoserver-from-gateway.192.168.1.11.nip.io
wget -qO- http://echoserver-from-gateway.192.168.1.11.nip.io
```
