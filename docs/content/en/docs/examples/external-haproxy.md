---
title: "External haproxy"
linkTitle: "External haproxy"
weight: 20
description: >
  Demonstrate how to configure HAProxy Ingress to use an external haproxy deployment.
---

This example demonstrates how to configure HAProxy Ingress to manage an external
haproxy instance deployed as a sidecar container. This approach decouple the
controller and the running haproxy version, allowing the sysadmin to update any
of them independently of the other.

## Prerequisites

This document requires only a Kubernetes cluster. HAProxy Ingress doesn't need to be
installed, and if so, the installation process should use the
[Helm chart]({{% relref "/docs/getting-started#installation" %}}).

## Configure the controller

The easiest and recommended way to configure an external haproxy is using the Helm
chart with a customized values file. Create the `haproxy-ingress-values.yaml` file with the
following content:

```yaml
controller:
  hostNetwork: false
  config:
    syslog-endpoint: stdout
    syslog-format: raw
  haproxy:
    enabled: true
    image:
      repository: haproxy
      tag: 2.3.4-alpine
```

Change the hostNetwork to `true` if your cluster doesn't provide a service loadbalancer.
These parameters are also configuring an external haproxy, version 2.3.4, and configuring
haproxy to log to stdout.

Add the HAProxy Ingress Helm repository if using HAProxy Ingress' chart for the first time:

```
$ helm repo add haproxy-ingress https://haproxy-ingress.github.io/charts
```

Install or upgrade HAProxy Ingress using the `haproxy-ingress-values.yaml` parameters:

Hint: change `install` to `upgrade` if HAProxy Ingress is already installed with Helm.

```
$ helm install haproxy-ingress haproxy-ingress/haproxy-ingress\
  --create-namespace --namespace=ingress-controller\
  --version 0.12.0-beta.1 --devel\
  -f haproxy-ingress-values.yaml
```

Check if the controller successfully starts or restarts:

```
$ kubectl --namespace ingress-controller get pod -w
```

## Test

Open two distinct terminals to follow `haproxy-ingress` and `haproxy` logs:

```
$ kubectl --namespace ingress-controller get pod
NAME                               READY   STATUS    RESTARTS   AGE
haproxy-ingress-6f8848d6fb-gxmrk   2/2     Running   0          13s

$ kubectl --namespace ingress-controller logs -f haproxy-ingress-6f8848d6fb-gxmrk -c haproxy-ingress
```

and

```
$ kubectl --namespace ingress-controller logs -f haproxy-ingress-6f8848d6fb-gxmrk -c haproxy
```

Do some `curl` to any exposed application, or just use the controller or service loadbalancer
IP like the example below:

```
$ curl 192.168.1.11
```

HAProxy Ingress and the external haproxy should be logging their own events:

`haproxy-ingress` container:

```
...
I0117 17:30:27.282701       6 controller.go:87] HAProxy Ingress successfully initialized
I0117 17:30:27.282743       6 leaderelection.go:243] attempting to acquire leader lease  ingress-controller/ingress-controller-leader-haproxy...
I0117 17:30:27.335674       6 status.go:177] new leader elected: haproxy-ingress-6f8848d6fb-cxb6w
I0117 17:30:27.392372       6 controller.go:321] starting haproxy update id=1
I0117 17:30:27.392463       6 ingress.go:153] using auto generated fake certificate
I0117 17:30:27.437047       6 instance.go:309] haproxy successfully reloaded (external)
I0117 17:30:27.437217       6 controller.go:353] finish haproxy update id=1: parse_ingress=0.143483ms write_maps=0.149637ms write_config=0.971026ms reload_haproxy=43.498718ms total=44.762864ms
I0117 17:30:58.066768       6 leaderelection.go:253] successfully acquired lease ingress-controller/ingress-controller-leader-haproxy
I0117 17:30:58.066867       6 status.go:177] new leader elected: haproxy-ingress-6f8848d6fb-gxmrk
```

`haproxy` container:

```
...
192.168.1.10:61116 [17/Jan/2021:17:32:36.050] _front_http _error404/<lua.send-404> 0/0/0/0/0 404 190 - - LR-- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
```

## What was changed?

The sections below have details of what changed in the deployment compared with a
default installation.

### Sidecar

This example configures 2 (two) new containers in the controllers' pod:

* `haproxy` is the external haproxy deployment with two mandatory arguments: `-S` with the master CLI unix socket, and `-f` with the configuration files path
* `init`, a Kubernetes' [initContainer](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/) used to create an initial and valid haproxy configuration.

The `haproxy` container references the official Alpine based image `haproxy:2.3.4-alpine`,
but can be any other. The only requisite is to be 2.0 or newer due to some new keywords
used by HAProxy Ingress.

The `init` container just copy a minimum and valid `haproxy.cfg`. This file is used
to properly starts haproxy and configures its master CLI that HAProxy Ingress uses
to manage the instance.

A new command-line `--master-socket` was also added to the HAProxy Ingress container.
This option enables an external haproxy instance, pointing to the unix socket path
of its master CLI.

### Shared filesystem

HAProxy Ingress sends configuration files to the haproxy instance using a shared
filesystem. A Kubernetes' [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)
works well.

The following directories must be shared:

* `/etc/haproxy`: configuration and map files - `init` and `haproxy-ingress` need write access, `haproxy` need read access.
* `/var/lib/haproxy`: mostly ssl related files - `haproxy-ingress` need write access, `haproxy` need read access.
* `/var/run/haproxy`: unix sockets - `haproxy-ingress` and `haproxy` need write access.

### Liveness probe

Default HAProxy Ingress deployment has a liveness probe to an haproxy's health
check URI. This example changes the liveness probe from the HAProxy Ingress
container to the haproxy one.
