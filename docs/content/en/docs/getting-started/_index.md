---
title: "Getting Started"
linkTitle: "Getting Started"
weight: 2
description: >
  How to install HAProxy Ingress and expose the first service.
---

## Prerequisites

{{% alert title="TODO" %}}
Prerequisites to install HAProxy Ingress
{{% /alert %}}

## Installation

Following some installation options.

### Helm chart

See the HAProxy Ingress chart [documentation](https://github.com/helm/charts/tree/master/incubator/haproxy-ingress).

### The five minutes deployment

{{% alert title="TODO" %}}
Detailed instructions here, without links
{{% /alert %}}

```
kubectl create -f https://haproxy-ingress.github.io/resources/haproxy-ingress.yaml
kubectl label node <node-name> role=ingress-controller
```

### Deployment from examples

{{% alert title="TODO" %}}
Instructions here, without links
{{% /alert %}}

* Start with [deployment](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/deployment) instructions
* See [TLS termination](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/tls-termination) on how to enable `https`

## Try it out!

{{% alert title="TODO" %}}
Name some hello-world style [examples]({{% relref "../examples" %}}) after migrate or create them.
{{% /alert %}}
