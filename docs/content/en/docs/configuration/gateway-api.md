---
title: "Gateway API"
linkTitle: "Gateway API"
weight: 2
description: >
  Configure HAProxy using Gateway API resources.
---

[Gateway API](https://gateway-api.sigs.k8s.io/) is a collection of Kubernetes resources that can be installed as [Custom Resource Definitions](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/). Just like Ingress resources, Gateway API resources are used to configure incoming HTTP/s and TCP requests to the in cluster applications. HAProxy Ingress v0.15 partially supports the Gateway API spec, `v1alpha2`, `v1beta1` and `v1` versions.

## Installation

The following steps configure the Kubernetes cluster and HAProxy Ingress to read and parse Gateway API resources:

* Manually install the Gateway API CRDs from the standard channel. See the Gateway API [documentation](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api)
    * ... or simply `kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.0.0/standard-install.yaml`
    * `v1.0.0` is just a reference for a fresh new deployment, Gateway API `v0.4.0` or any newer versions are supported.
* Start (or restart) the controller

See below the [getting started steps](#getting-started).

## Conformance

Gateway API `v1alpha2`, `v1beta1` and `v1` specs are partially implemented in v0.15 release. The following list describes what is (or is not) supported:

* Target Services can be annotated with [Backend or Path scoped]({{% relref "keys#scope" %}}) configuration keys, this will continue to be supported.
* Gateway API resources doesn't support annotations, this is planned to continue to be unsupported. Extensions to the Gateway API spec will be added in the extension points of the API.
* Only the `GatewayClass`, `Gateway` and `HTTPRoute` resource definitions are implemented.
* The controller doesn't implement partial parsing yet for Gateway API resources, changes should be a bit slow on clusters with thousands of Ingress, Gateway API resources or Services.
* Gateway's Listener Port and Protocol are not implemented - Port uses the global [bind-port]({{% relref "keys#bind-port" %}}) configuration and Protocol is based on the presence or absence of the TLS attribute.
* Gateway's Addresses is not implemented - binding addresses use the global [bind-ip-addr]({{% relref "keys#bind-ip-addr" %}}) configuration.
* Gateway's Hostname only supports empty/absence of Hostname or a single `*`, any other string will override the HTTPRoute Hostnames configuration without any merging.
* HTTPRoute's Rules and BackendRefs don't support Filters.
* Resources status are not updated.

### Roadmap

* Version `v1alpha1` support was dropped on v0.15.
* Versions `v1beta1` and `v1` support was added on v0.15.
* `v1alpha2`, `v1beta1` and `v1` versions will continue to be supported on future HAProxy Ingress releases.
* Spec conformance will be gradually incremented on newer HAProxy Ingress versions.

## Ingress

A single HAProxy Ingress deployment can manage Ingress, and also `v1alpha2`, `v1beta1` and `v1` Gateway API resources in the same Kubernetes cluster. If the same hostname and path with the same path type is declared in the Gateway API and Ingress, the Gateway API wins and a warning is logged. Ingress resources will continue to be supported in future controller versions, without side effects, and without the need to install the Gateway API CRDs.

## Getting started

Add the following steps to the [Getting Started guide]({{% relref "/docs/getting-started" %}}) in order to expose the echoserver service along with the Gateway API:

[Manually install](https://gateway-api.sigs.k8s.io/v1alpha2/guides/getting-started/#installing-gateway-api-crds-manually) the Gateway API CRDs:

```
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.0.0/standard-install.yaml
```

Add the following deployment and service if echoserver isn't running yet:

```
kubectl --namespace default create deployment echoserver --image k8s.gcr.io/echoserver:1.3
kubectl --namespace default expose deployment echoserver --port=8080
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

Gateways create listeners and allow to configure hostnames. Create a Gateway with the following content:

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
  labels:
    gateway: echo
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
curl http://echoserver-from-gateway.local
wget -qO- http://echoserver-from-gateway.local
```
