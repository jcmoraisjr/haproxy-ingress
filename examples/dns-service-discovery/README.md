# HAProxy DNS Service Discovery

This example uses dns service discovery for service named *web*

## Prerequisites

This document has the following prerequisites:

* Deploy [HAProxy Ingress controller](/examples/deployment)

## Using DNS Service Discovery

Example - using internal kubernetes resources

* Update ingress with simple [configmap](/examples/dns-service-discovery/haproxy-config-map.yml)

```console
$ kubectl apply -f haproxy-config-map.yml
```

* configmap with all options displayed [configmap](/examples/dns-service-discovery/all-options-haproxy-config-map.yml)

```console
$ kubectl apply -f all-options-haproxy-config-map.yml
```

* Install pods [replication-controler](/examples/dns-service-discovery/web-rc.yml)

```console
$ kubectl apply -f web-rc.yml
```

* Configure ingress 

```console
$ kubectl annotate ingress/app --overwrite ingress.kubernetes.io/use-resolver=kubernetes
```

Two important settings:
- `ingress.kubernetes.io/use-resolver: kubernetes`: resolver with name kubernetes
- `clusterIP: None`: service must be [**headless**](https://kubernetes.io/docs/concepts/services-networking/service/#headless-services). See also [dns headless doc](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/).


## Annotations

### configmap

DNS resolvers can be written in multiple ways:
* `resolver=ip`
* `resolver=ip:port`
* `resolver=ip[:port],ip[:port]` port is optional

### activating

`ingress.kubernetes.io/use-resolver: resolvername` 

### ingress

`ingress.kubernetes.io/cluster-dns-domain` can be used if kubedns does not points to cluster.local 
