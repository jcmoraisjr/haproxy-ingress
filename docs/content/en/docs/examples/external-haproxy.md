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
  config:
    syslog-endpoint: stdout
    syslog-format: raw
  haproxy:
    enabled: true
    securityContext:
      runAsUser: 0
```

These parameters are configuring an external haproxy and configuring haproxy to log
to stdout. Also, haproxy is configured as root so it has permission to bind ports `:80`
and `:443`. By default haproxy container is started as UID `99`.

### A word about security

haproxy historically started as root so it has the permissions needed to bind to privileged ports,
configure chroot, configure file descriptor limits, and other administrative tasks. haproxy then
drops its own privileges just before starting its event loop. See
[Security Considerations](https://docs.haproxy.org/2.8/management.html#13) from the documentation.

Since 2.4, haproxy container has been started as UID `99`. There are a few ways to give it
permissions to bind privileged port, none of them is provided by default by HAProxy Ingress Helm
chart because all of them has some sort of limitation. Choose one of the options below that best
suits the needs of your environment:

1. Configure haproxy to start as root, This is the configuration provided above, but it will not
work if cluster policies deny containers running as root.
1. Some container runtime engines, like Docker `20.10` or newer, or Containerd embedded in k3s,
reconfigure the starting of unprivileged ports so haproxy should work out of the box listening
to `:80` and `:443` without the need to run as root. Give it a try by removing the
`securityContext` configuration altogether:

    ```yaml
    controller:
      config:
        syslog-endpoint: stdout
        syslog-format: raw
      haproxy:
        enabled: true
    ```

1. Change haproxy listening port to unprivileged ports, like `8080` and `8443`:

    > Note that, if exposing haproxy via `hostNetwork`, end users would need to connect to `:8443` instead of the well known `:443`, so this is only an option if the cluster provides LoadBalancer services

    ```yaml
    controller:
      config:
        syslog-endpoint: stdout
        syslog-format: raw
        http-port: "8080"
        https-port: "8443"
      service:
        httpPorts:
        - port: 80
          targetPort: 8080
        httpsPorts:
        - port: 443
          targetPort: 8443
        type: LoadBalancer
      haproxy:
        enabled: true
    ```

1. Change the haproxy image by adding the `NET_BIND_SERVICE`
[capability](https://man7.org/linux/man-pages/man7/capabilities.7.html) to the haproxy binary:

    ```Dockerfile
    FROM haproxy:X.X-alpine
    USER root
    RUN apk add -U libcap-utils
    RUN setcap 'cap_net_bind_service=+ep' /usr/local/sbin/haproxy
    USER haproxy
    ```

1. Reconfigure the start of unprivileged port to `80` or below using the following configuration:

    > This configuration does not work if `hostNetwork` is configured as `true`, and does not work on Kernel versions older than 4.11.

    ```yaml
    controller:
      config:
        syslog-endpoint: stdout
        syslog-format: raw
      haproxy:
        enabled: true
        securityContext:
          sysctls:
            name: net.ipv4.ip_unprivileged_port_start
            value: "1"
    ```

## Install the controller

Add the HAProxy Ingress Helm repository if using HAProxy Ingress' chart for the first time:

```
$ helm repo add haproxy-ingress https://haproxy-ingress.github.io/charts
```

Install or upgrade HAProxy Ingress using the `haproxy-ingress-values.yaml` parameters:

```
$ helm upgrade haproxy-ingress haproxy-ingress/haproxy-ingress\
  --install --create-namespace --namespace=ingress-controller\
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
