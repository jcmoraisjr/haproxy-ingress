# HAProxy DNS Service Discovery

This example uses dns service discovery for service named *web*

## Prerequisites

This document has the following prerequisites:

* Deploy [HAProxy Ingress controller](/examples/deployment)

## Using DNS Service Discovery

Example - using internal kubernetes resources

*Note: Configure IP address of your cluster DNS server*

* Update ingress with simple [ConfigMap](/examples/dns-service-discovery/haproxy-config-map.yml)

```console
$ kubectl apply -f haproxy-config-map.yml
```

* ConfigMap with all options displayed [ConfigMap](/examples/dns-service-discovery/all-options-haproxy-config-map.yml)

```console
$ kubectl apply -f all-options-haproxy-config-map.yml
```

*Note: If using kube-dns, the cache ttl defaults to 30s. Add --max-ttl and --max-cache-ttl to the dns container to a proper value; otherwise, the HAProxy backend could take up to 30s to update*

* Install pods [replication-controller](/examples/dns-service-discovery/web-rc.yml)

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


## ConfigMap options

* `cluster-dns-domain` can be used if kubedns does not points to cluster.local
* `dns-resolvers` multiline list of DNS resolvers
  * DNS resolver can be written in multiple ways:
    * `resolver=ip`
    * `resolver=ip:port`
    * `resolver=ip[:port],ip[:port]` where port is optional

* `dns-timeout-retry` default: 1s
* `dns-hold-obsolete`default: 0s
* `dns-hold-valid` default: 1s
* `dns-accepted-payload-size` default: 8192

## Annotations

`ingress.kubernetes.io/use-resolver: resolvername` 
 
