---
title: "Getting Started"
linkTitle: "Getting Started"
weight: 2
description: >
  How to install HAProxy Ingress and expose the first service.
---

## Prerequisites

HAProxy Ingress needs a running Kubernetes cluster. Although it's recommended to always use an up-to-date one, it will also work on clusters version as old as 1.6. HAProxy Ingress also works fine on local k8s deployments like [minikube](https://minikube.sigs.k8s.io) or [kind](https://kind.sigs.k8s.io).

An ingress controller works exposing internal services to the external world, so another pre-requisite is that at least one cluster node is accessible externally. On cloud environments, a cloud load balancer can be configured to reach the ingress controller nodes.

HAProxy Ingress uses [TLS SNI extension](https://en.wikipedia.org/wiki/Server_Name_Indication) and the [Host header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) to associate requests and ingress' `host`s. The easiest way to accomplish this on local environment is using [nip.io](https://nip.io). A production environment should consider a [dynamic DNS](https://en.wikipedia.org/wiki/Dynamic_DNS) solution or a [wildcard DNS record](https://en.wikipedia.org/wiki/Wildcard_DNS_record).

## Installation

Following some installation options.

### Helm chart

See the HAProxy Ingress chart [documentation](https://github.com/helm/charts/tree/master/incubator/haproxy-ingress).

### The five minutes deployment

The following steps will deploy HAProxy Ingress with this configurations:

* Create and use `ingress-controller` namespace
* Create `ingress-controller` service account and rbac permissions
* Access Kubernetes API using the in-cluster configuration
* Default TLS certificate is self signed and created on the fly
* Deployed on every node labeled with `role=ingress-controller` via DaemonSet
* Use `hostNetwork`, so the node should not be using the following ports: `80`, `443`, `1936`, `10253` and `10254`

Create the resources:

```shell
$ kubectl create -f https://haproxy-ingress.github.io/resources/haproxy-ingress.yaml
```

The controller is not running yet. Time to edit any default value, eg the controller image version:

```shell
$ kubectl -n ingress-controller edit configmap haproxy-ingress
$ kubectl -n ingress-controller edit daemonset haproxy-ingress
```

Label at least one node:

```shell
$ kubectl get node
NAME                STATUS   ROLES    AGE   VERSION
cl1-control-plane   Ready    master   21m   v1.16.3
cl1-worker          Ready    <none>   21m   v1.16.3

$ kubectl label node cl1-control-plane role=ingress-controller
```

Now HAProxy Ingress should be up and running:

```shell
$ kubectl -n ingress-controller get daemonset
NAME              DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR             AGE
haproxy-ingress   1         1         1       1            1           role=ingress-controller   3m

$ kubectl -n ingress-controller get pod
NAME                    READY   STATUS    RESTARTS   AGE
haproxy-ingress-kwwnk   1/1     Running   0          3m
```

### Deployment from examples

{{% alert title="TODO" %}}
Copy and revise doc from the links below
{{% /alert %}}

* Start with [deployment](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/deployment) instructions
* See [TLS termination](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/tls-termination) on how to enable `https`

## Try it out!

The following steps deploy a `nginx:alpine` image and exposes it in the current namespace

1) Create the nginx's deployment and service:

```shell
$ kubectl create deployment nginx --image nginx:alpine
$ kubectl expose deployment nginx --port=80
```

2) Check if nginx is up and running:

```shell
$ kubectl get pod
NAME                     READY   STATUS    RESTARTS   AGE
nginx-5b6fb6dd96-68jwp   1/1     Running   0          27s
```

3) Make HAProxy Ingress exposes the nginx service. Change `HOST` value in the example below to a hostname that resolves to the ingress controller nodes.

Obs.: `nip.io` is a convenient service which converts a valid domain name to any IP, either public or local. See [here](https://nip.io) how it works.

```shell
$ HOST=nginx.192.168.1.1.nip.io
$ kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: nginx
spec:
  rules:
  - host: $HOST
    http:
      paths:
      - backend:
          serviceName: nginx
          servicePort: 80
        path: /
EOF
```

4) Browse to the configured `HOST`. The nginx default page should be there.

## What's next?

Learn more about ingress from the Kubernetes docs:

* [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) from Kubernetes docs

HAProxy Ingress has lots of configuration options. See the following tips to get started faster:

* Follow some configuration instruction from the [examples]({{% relref "../examples" %}}) page
* See how HAProxy Ingress uses ingress objects: [configuration keys]({{% relref "../configuration/keys" %}})
* Get started with all the configuration options: [configuration]({{% relref "../configuration" %}})
