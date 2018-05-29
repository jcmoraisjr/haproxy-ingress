# HAProxy DNS Service Discovery

This example uses dns service discovery for service named *web*

## Prerequisites

This document has the following prerequisites:

* Deploy [HAProxy Ingress controller](/examples/deployment)

## Using DNS Service Discovery

Example - using internal kubernetes resources

* Update ingress [configmap](/examples/dns-service-discovery/1.haproxy-config-map.yml)

```console
$ kubectl apply -f haproxy-config-map.yml
```

* Install pods [replication-controler](/examples/dns-service-discovery/2.web-rc.yml)

```console
$ kubectl apply -f 2.web-rc.yml
```

* Install [service](/examples/dns-service-discovery/3.web-svc.yml)

```console
$ kubectl apply -f 3.web-svc.yml
```

Two important settings:
- `haproxy.kubernetes.io/use-resolver: kubernetes`: resolver with name kubernetes
- `clusterIP: None`: service must be **headless**


## Annotations

### configmap

DNS resolvers can be written in multiple ways:
* `resolver=ip`
* `resolver=ip:port`
* `resolver=ip[:port],ip[:port]` port is optional

### service

`haproxy.kubernetes.io/use-resolver: resolvername` 
