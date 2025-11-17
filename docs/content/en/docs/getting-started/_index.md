---
title: "Getting Started"
linkTitle: "Getting Started"
weight: 2
description: >
  How to install HAProxy Ingress and expose the first service.
---

The following sections walk through steps to have HAProxy Ingress working, watching ingress resources and exposing services.

## Prerequisites

HAProxy Ingress needs a running Kubernetes cluster. Controller version v0.16 needs Kubernetes 1.21 or newer, see other supported versions in the [README](https://github.com/jcmoraisjr/haproxy-ingress/#use-haproxy-ingress) file. HAProxy Ingress also works fine on local k8s deployments like [minikube](https://minikube.sigs.k8s.io), [kind](https://kind.sigs.k8s.io), [k3s](https://k3s.io), [k3d](https://k3d.io) or [colima](https://github.com/abiosoft/colima).

An ingress controller works exposing internal services to the external world, so another prerequisite is that at least one cluster node is accessible externally. On cloud environments, a cloud load balancer can be configured to reach the ingress controller nodes.

HAProxy Ingress uses [TLS SNI extension](https://en.wikipedia.org/wiki/Server_Name_Indication) and the [Host header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) to associate requests and ingress' `host`s. The easiest way to accomplish this on local environment is using [nip.io](https://nip.io). A production environment should consider a [dynamic DNS](https://en.wikipedia.org/wiki/Dynamic_DNS) solution or a [wildcard DNS record](https://en.wikipedia.org/wiki/Wildcard_DNS_record).

## Installation

HAProxy Ingress uses [Helm](https://helm.sh) chart to install and configure the controller. See below some deployment instructions:

1. Install `helm`, HAProxy Ingress requires version 3. See the [installation instructions](https://helm.sh/docs/intro/install/).

1. Add the HAProxy Ingress' Helm repository. This will instruct Helm to find all available packages:

    ```
    $ helm repo add haproxy-ingress https://haproxy-ingress.github.io/charts
    ```

1. Check if kubeconfig points to the right cluster:

    ```
    $ kubectl cluster-info
    ```

    The default cluster can be changed either via `kubectl config set-context <cluster-context>` or adding `--kube-context <cluster-context>` in the helm command-line options.

    Note that the user needs administrative privileges in the cluster to properly install the controller.

1. Create a `haproxy-ingress-values.yaml` file with custom parameters:

    > Use the content below if HAProxy Ingress should expose HAProxy via a service loadbalancer, like ELB, kube-vip, ServiceLB (k3s), etc.

    ```yaml
    # Expose HAProxy via a service loadbalancer
    controller:
      ingressClassResource:
        enabled: true
    ```

    > Use the content below to expose HAProxy via host port on all cluster nodes.

    ```yaml
    # Expose HAProxy via host port on all cluster nodes
    controller:
      ingressClassResource:
        enabled: true
      kind: DaemonSet
      daemonset:
        useHostPort: true
      service:
        type: ClusterIP
    ```

    HAProxy Ingress chart [documentation](https://github.com/haproxy-ingress/charts/blob/release-0.16/haproxy-ingress/README.md#configuration) has all the available options. See also further documentation in the [default values](https://github.com/haproxy-ingress/charts/blob/release-0.16/haproxy-ingress/values.yaml) file.

1. Install HAProxy Ingress using `haproxy-ingress` as the release name and `haproxy-ingress-values.yaml` file as the custom parameters:

    ```
    $ helm upgrade haproxy-ingress haproxy-ingress/haproxy-ingress\
      --install\
      --create-namespace --namespace ingress-controller\
      --version 0.16.0-beta.1 --devel\
      -f haproxy-ingress-values.yaml
    ```

    > Note that the command `upgrade` above, along with the `--install` command-line option, starts a new HAProxy Ingress deployment if it is missing, or starts a rolling update if HAProxy Ingress is already installed. `template` can be used instead to generate the manifests without installing them - add either a redirect `... >haproxy-ingress-install.yaml` to save the output, or `--output-dir output/` command line option to save one file per manifest.

The controller should be running in a few seconds. There are four important customizations made in the example above:

* `--version`: a good practice, this will ensure that you'll have the same version installed even if a new release issued.
* `--namespace`: we're instructing helm to install HAProxy Ingress in the `ingress-controller` namespace. This namespace will be created if it does not exist yet. The default behavior, if namespace is not provided, is to deploy the controller in the kubectl's current namespace.
* `ingressClassResource.enabled`: This causes the helm chart to apply an [IngressClass](https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class) to your cluster. IngressClasses are how HAProxy Ingress knows which of your Ingresses it should control. IngressClasses replace the [kubernetes.io/ingress.class](https://kubernetes.io/docs/concepts/services-networking/ingress/#deprecated-annotation) annotation used in Kubernetes versions before v1.18.
* `kind`, `daemonset.useHostPort` and `service.type`, only used when service loadbalancer should not be used: disables service load balancer and exposes HAProxy via host port on all cluster nodes.

HAProxy Ingress' Helm chart has a few more configuration options, see all of them in the chart [documentation](https://github.com/haproxy-ingress/charts/blob/release-0.16/haproxy-ingress/README.md) and in the [default values](https://github.com/haproxy-ingress/charts/blob/release-0.16/haproxy-ingress/values.yaml) file.

## Deploy and expose

The following steps deploy an echoserver image and exposes it in the current namespace using an Ingress resource. Learn how to expose using [Gateway API]({{% relref "/docs/configuration/gateway-api" %}}).

1. Create the echoserver's deployment and service:

    ```
    $ kubectl --namespace default create deployment echoserver --image k8s.gcr.io/echoserver:1.3
    $ kubectl --namespace default expose deployment echoserver --port=8080
    ```

1. Check if echoserver is up and running:

    ```
    $ kubectl -n default get pod -w
    NAME                          READY   STATUS    RESTARTS   AGE
    echoserver-5b6fb6dd96-68jwp   1/1     Running   0          27s
    ```

1. Make HAProxy Ingress expose the echoserver service. Change `echoserver.local` value in the `--rule` option below to a hostname that resolves to an ingress controller node.

    > Obs.: [`nip.io`](https://nip.io) is a convenient service which converts a valid domain name to an IP, either public or local.

    ```
    $ kubectl --namespace default create ingress echoserver \
      --class=haproxy \
      --rule="echoserver.local/*=echoserver:8080,tls"
    ```

1. Send a request to our echoserver.

    ```
    $ curl -k https://echoserver.local
    $ wget -qO- --no-check-certificate https://echoserver.local
    ```

## What's next

Expose HAProxy Ingress metrics:

* See the [metrics example page]({{% relref "../examples/metrics" %}})

See what differs to expose services using Gateway API:

* [Gateway API introduction](https://gateway-api.sigs.k8s.io/) from Kubernetes' SIG-Network documentation
* [Getting started]({{% relref "/docs/configuration/gateway-api" %}}) with Gateway API and HAProxy Ingress

Learn more about Ingress and IngressClass resources:

* [Ingress and IngressClass resources](https://kubernetes.io/docs/concepts/services-networking/ingress/) from Kubernetes docs

HAProxy Ingress has lots of configuration options. See the following tips to get started faster:

* Follow some configuration instruction from the [examples]({{% relref "../examples" %}}) page
* See how HAProxy Ingress uses ingress objects: [configuration keys]({{% relref "../configuration/keys" %}})
* Get started with all the configuration options: [configuration]({{% relref "../configuration" %}})
