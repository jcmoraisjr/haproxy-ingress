---
title: "External haproxy"
linkTitle: "External haproxy"
weight: 20
description: >
  Demonstrate how to configure HAProxy Ingress to use an external haproxy deployment.
---

{{% pageinfo %}}
This is a `v0.12` example and need HAProxy Ingress `v0.12-snapshot.1` or above
{{% /pageinfo %}}

This example demonstrates how to configure HAProxy Ingress to manage an external
haproxy instance deployed as a sidecar container. This approach decouple the
controller and the running haproxy version, allowing the sysadmin to update any
of them independently of the other.

## Prerequisites

This document has the following prerequisite:

* A Kubernetes cluster with a running HAProxy Ingress controller v0.12 or above.
Follow The five minutes deployment in the [getting started]({{% relref "/docs/getting-started" %}}) guide.
* A running and exposed application in the Kubernetes cluster, this getting started
[deployment]({{% relref "/docs/getting-started#try-it-out" %}}) does the job.

## Update the deployment

The following instruction patches the current HAProxy Ingress daemonset (this will also revert the command-line arguments to the default value):

```
$ kubectl --namespace ingress-controller patch daemonset haproxy-ingress \
-p "$(curl -sSL https://haproxy-ingress.github.io/v0.12/docs/examples/external-haproxy/daemonset-patch.yaml)"
```

Check if the controller restarts without any problem:

```
$ kubectl --namespace ingress-controller get pod -w
```

## What was changed?

The sections below have details of what changed in the deployment.

### Sidecar

This example configures 2 (two) new containers in the controllers' pod:

* `haproxy` is the external haproxy deployment with two mandatory arguments: `-S` with the master CLI unix socket, and `-f` with the configuration files path
* `init`, a Kubernetes' [initContainer](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/) used to create an initial and valid haproxy configuration.

The `haproxy` container references the official Alpine based image `haproxy:alpine`,
but can be any other customized image. The only requisite is to be 2.0 or newer due
to some new keywords used by HAProxy Ingress.

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
check URI. The patch of this example moves the liveness probe from the HAProxy
Ingress container to the haproxy one.

## Test

Open two distinct terminals to follow `haproxy-ingress` and `haproxy` logs:

```
$ kubectl --namespace ingress-controller get pod
NAME                    READY   STATUS    RESTARTS   AGE
haproxy-ingress-6bsvz   3/3     Running   0          17m

$ kubectl --namespace ingress-controller logs -f haproxy-ingress-6bsvz -c haproxy-ingress
```

and

```
$ kubectl --namespace ingress-controller logs -f haproxy-ingress-6bsvz -c haproxy
```

Update syslog configuration using another terminal, this will make haproxy use stdout:

```
$ kubectl --namespace ingress-controller patch configmap haproxy-ingress -p '{"data":{"syslog-endpoint":"stdout","syslog-format":"raw"}}'
```

Do some `curl` to an exposed application deployed in the cluster:

```
$ kubectl get ing
NAME    HOSTS                       ADDRESS   PORTS     AGE
nginx   nginx.192.168.1.11.nip.io             80, 443   21m

$ curl nginx.192.168.1.11.nip.io
```

During the ConfigMap update and the endpoint calls, HAProxy Ingress and the external
haproxy should be logging its own events:

`haproxy-ingress` container:

```
I0921 16:06:12.699201       6 controller.go:314] starting haproxy update id=8
I0921 16:06:12.710723       6 instance.go:322] updating 1 host(s): [*.sub.t002.app.domain]
I0921 16:06:12.710752       6 instance.go:339] updating 1 backend(s): [0_echoserver_8080]
I0921 16:06:12.726794       6 instance.go:387] updated main cfg and 1 backend file(s): [002]
I0921 16:06:12.788496       6 instance.go:301] haproxy successfully reloaded (external)
I0921 16:06:12.790696       6 controller.go:346] finish haproxy update id=8: parse_ingress=1.323253ms write_maps=10.101055ms write_config=16.320063ms reload_haproxy=63.587362ms total=91.331733ms
```

`haproxy` container:

```
192.168.100.1:58167 [21/Sep/2020:16:06:15.003] _front_https~ t015_echoserver_8080/srv001 0/0/2/0/2 200 485 - - ---- 1/1/0/0/0 0/0 "GET https://t004.app.domain/ HTTP/2.0"
```
