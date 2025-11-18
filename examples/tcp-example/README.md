# tcp example

An example configuration to proxy a TCP service with haproxy-ingress.

## Setup

First, set up a kind cluster using the [example config](kind.yaml):

```sh
kind create cluster --config kind.yaml
```

The cluster config contains port-mappings to access services on 8080 (http), 8181 (https), 1936 (haproxy stats for verification) and a TCP service running at 1111.

## Configuration

Proceed to configure haproxy-ingress using the [helm chart](https://github.com/haproxy-ingress/) using the [values.yaml](values.yaml):

```yaml
controller:
  extraArgs:
    watch-ingress-without-class: "true"
    acme-server: "false"
    acme-track-tls-annotation: "false"
  ingressClassResource:
    enabled: false
  kind: DaemonSet
  daemonset:
    useHostPort: true
    hostPorts:
      tcp: ["1111"]
  tcp:
    "1111": "namespace/service:1111"
  service:
    type: ClusterIP
  stats:
    enabled: true
    port: 1936
    hostPort: 1936
```

Install with:

```sh
helm upgrade --install \
    --namespace ingress \
    --values values.yaml \
    my-release haproxy-ingress/haproxy-ingress
```

The configuration is as minimal as possible — e.g. ingress classes are disabled (any ingress will be picked up by haproxy-ingress) and for local development ACME is turned off as well.

The important parts:

- `controller.daemonset.useHortPort: true` enables the extra ports on the pod
- `controller.daemonset.hostPorts.tcp` is a (**string**) list of exposed TCP ports
- `controller.tcp` is a mapping of the exposed port to a service (within a namespace and target port)

## production

The list in `controller.tcp` is used to add ports to the service in front of your haproxy-ingress daemonset (or deployment).

In contrast to our example above, the service should not be of type `ClusterIP` and should to be backed by, e.g., a cloud loadbalancer.

You can inspect the service with `kubectl` to ensure all relevant ports are assigned:

```sh
$ kubectl describe svc/haproxy-ingress
Name:                     haproxy-ingress
Namespace:                ingress-controller
Labels:                   ...
Annotations:              ...
Selector:                 app.kubernetes.io/instance=haproxy-ingress,app.kubernetes.io/name=haproxy-ingress
Type:                     ...
IP:                       10.96.40.135
IPs:                      10.96.40.135
Port:                     http-80  80/TCP
TargetPort:               http/TCP
Endpoints:                10.244.0.31:80
Port:                     https-443  443/TCP
TargetPort:               https/TCP
Endpoints:                10.244.0.31:443
Port:                     1111-tcp  1111/TCP
TargetPort:               1111-tcp/TCP
Endpoints:                10.244.0.31:1111
Session Affinity:         None
Internal Traffic Policy:  Cluster
Events:                   <none>
```