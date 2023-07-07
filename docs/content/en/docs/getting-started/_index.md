---
title: "Getting Started"
linkTitle: "Getting Started"
weight: 2
description: >
  How to install HAProxy Ingress and expose the first service.
---

The following sections walk through steps to have HAProxy Ingress working, watching ingress resources and exposing services.

## Prerequisites

HAProxy Ingress needs a running Kubernetes cluster. Controller version v0.12 needs Kubernetes 1.18 or newer, see other supported versions in the [README](https://github.com/jcmoraisjr/haproxy-ingress/#use-haproxy-ingress) file. HAProxy Ingress also works fine on local k8s deployments like [minikube](https://minikube.sigs.k8s.io), [kind](https://kind.sigs.k8s.io) or [k3d](https://k3d.io).

An ingress controller works exposing internal services to the external world, so another pre-requisite is that at least one cluster node is accessible externally. On cloud environments, a cloud load balancer can be configured to reach the ingress controller nodes.

HAProxy Ingress uses [TLS SNI extension](https://en.wikipedia.org/wiki/Server_Name_Indication) and the [Host header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) to associate requests and ingress' `host`s. The easiest way to accomplish this on local environment is using [nip.io](https://nip.io). A production environment should consider a [dynamic DNS](https://en.wikipedia.org/wiki/Dynamic_DNS) solution or a [wildcard DNS record](https://en.wikipedia.org/wiki/Wildcard_DNS_record).

## Installation

HAProxy Ingress uses [Helm](https://helm.sh) chart to install and configure the controller. See below some deployment instructions:

1) Install `helm`, HAProxy Ingress requires version 3. See the installation instructions [here](https://helm.sh/docs/intro/install/).

2) Add the HAProxy Ingress' Helm repository. This will instruct Helm to find all available packages:

```shell
$ helm repo add haproxy-ingress https://haproxy-ingress.github.io/charts
```

3) Check if kubeconfig points to the right cluster:

```shell
$ kubectl cluster-info
```

The default cluster can be changed either via `kubectl config set-context <cluster-context>` or adding `--kube-context <cluster-context>` in the helm command-line options.

Note that the user needs administrative privileges in the cluster to properly installs the controller.

4) Create a `haproxy-ingress-values.yaml` file with custom parameters:

```yaml
controller:
  hostNetwork: true
```

HAProxy Ingress chart [documentation](https://github.com/haproxy-ingress/charts/blob/release-0.12/haproxy-ingress/README.md#configuration) has all the available options. See also further documentation in the [default values](https://github.com/haproxy-ingress/charts/blob/release-0.12/haproxy-ingress/values.yaml) file.

5) Install HAProxy Ingress using `haproxy-ingress` as the release name and `haproxy-ingress-values.yaml` file as the custom parameters:

```shell
$ helm install haproxy-ingress haproxy-ingress/haproxy-ingress\
  --create-namespace --namespace ingress-controller\
  --version 0.12.18\
  -f haproxy-ingress-values.yaml
```

{{% alert title="Note" %}}
The command `install` above can be changed to `upgrade` to start a rolling update of HAProxy Ingress version or configuration. `template` can be used instead to generate the manifests without installing them - add either a redirect `... >haproxy-ingress-install.yaml` to save the output, or `--output-dir output/` command line option to save one file per manifest.
{{% /alert %}}

The controller should be running in a few seconds. There are three important customizations made in the example above:

* version: a good practice, this will ensure that you'll have the same version installed even if a new release issued.
* namespace: we're instructing helm to install HAProxy Ingress in the `ingress-controller` namespace. This namespace will be created if it does not exist yet. The default behavior, if namespace is not provided, is to deploy the controller in the kubectl's current namespace.
* hostNetwork: we're configuring the deployment to expose haproxy in the host network, which means bind all haproxy ports, including but not limited to 80 and 443, in the node's IPs. Maybe this isn't a proper configuration for your production - it depends on the options you have to expose a Kubernetes' service, but doing so we'll be able to send http/s requests on local development environments, or even baremetal and on premise deployments that doesn't have a fronting router or load balancer to expose the controller. In any case a service is also configured in the `ingress-controller` namespace which tries to expose haproxy.

HAProxy Ingress' Helm chart has a few more configuration options, see all of them in the chart [documentation](https://github.com/haproxy-ingress/charts/blob/release-0.12/haproxy-ingress/README.md) and in the [default values](https://github.com/haproxy-ingress/charts/blob/release-0.12/haproxy-ingress/values.yaml) file.

## Deploy and expose

The following steps deploy an echoserver image and exposes it in the current namespace.

1) Create the echoserver's deployment and service:

```shell
$ kubectl create deployment echoserver --image k8s.gcr.io/echoserver:1.3
$ kubectl expose deployment echoserver --port=8080
```

2) Check if echoserver is up and running:

```shell
$ kubectl get pod -w
NAME                          READY   STATUS    RESTARTS   AGE
echoserver-5b6fb6dd96-68jwp   1/1     Running   0          27s
```

3) Make HAProxy Ingress exposes the echoserver service. Change `HOST` value in the example below to a hostname that resolves to an ingress controller node.

Obs.: `nip.io` is a convenient service which converts a valid domain name to any IP, either public or local. See [here](https://nip.io) how it works.

```shell
$ HOST=echoserver.192.168.1.11.nip.io
$ kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: haproxy
  name: echoserver
spec:
  rules:
  - host: $HOST
    http:
      paths:
      - backend:
          serviceName: echoserver
          servicePort: 8080
        path: /
  tls:
  - hosts:
    - $HOST
EOF
```

4) Send a request to our echoserver.

```shell
$ curl -k https://echoserver.192.168.1.11.nip.io
$ wget -qO- --no-check-certificate https://echoserver.192.168.1.11.nip.io
```

## What's next

Learn more about Ingress and IngressClass resources:

* [Ingress and IngressClass resources](https://kubernetes.io/docs/concepts/services-networking/ingress/) from Kubernetes docs

HAProxy Ingress has lots of configuration options. See the following tips to get started faster:

* Follow some configuration instruction from the [examples]({{% relref "../examples" %}}) page
* See how HAProxy Ingress uses ingress objects: [configuration keys]({{% relref "../configuration/keys" %}})
* Get started with all the configuration options: [configuration]({{% relref "../configuration" %}})
