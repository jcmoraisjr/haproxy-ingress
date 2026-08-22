---
title: "Getting Started"
linkTitle: "Getting Started"
weight: 2
description: >
  How to install N42 Gateway and expose the first service.
---

The following sections walk through steps to have N42 Gateway working, watching Ingress or Gateway API resources and exposing services.

## Prerequisites

N42 Gateway needs a running Kubernetes cluster. Controller version v0.17 needs Kubernetes 1.21 or newer, see other supported versions in the [README](https://github.com/n42-gateway/n42-gateway/#use-n42-gateway) file. N42 Gateway also works fine on local k8s deployments like [minikube](https://minikube.sigs.k8s.io), [kind](https://kind.sigs.k8s.io), [k3s](https://k3s.io), [k3d](https://k3d.io) or [colima](https://github.com/abiosoft/colima).

An ingress controller works exposing internal services to the external world, so another prerequisite is that at least one cluster node is accessible externally. On cloud environments, a cloud load balancer can be configured to reach the ingress controller nodes.

N42 Gateway uses [TLS SNI extension](https://en.wikipedia.org/wiki/Server_Name_Indication) and the [Host header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) to associate requests and ingress' `host`s. The easiest way to accomplish this on local environment is using [nip.io](https://nip.io). A production environment should consider a [dynamic DNS](https://en.wikipedia.org/wiki/Dynamic_DNS) solution or a [wildcard DNS record](https://en.wikipedia.org/wiki/Wildcard_DNS_record).

## Installation

N42 Gateway uses [Helm](https://helm.sh) chart to install and configure the controller. See below some deployment instructions:

1. Install `helm`, N42 Gateway requires version 3. See the [installation instructions](https://helm.sh/docs/intro/install/).

1. Add the N42 Gateway' Helm repository. This will instruct Helm to find all available packages:

    ```
    $ helm repo add n42 https://n42-gateway.github.io/charts
    ```

1. Check if kubeconfig points to the right cluster:

    ```
    $ kubectl cluster-info
    ```

    The default cluster can be changed either via `kubectl config set-context <cluster-context>` or adding `--kube-context <cluster-context>` in the helm command-line options.

    Note that the user needs administrative privileges in the cluster to properly install the controller.

1. Create a `n42-gateway-values.yaml` file with custom parameters:

    > Use the content below if N42 Gateway should expose HAProxy via a service loadbalancer, like ELB, kube-vip, ServiceLB (k3s), etc.

    ```yaml
    # Expose HAProxy via a service loadbalancer.
    # You can configure gatewayClassResource.enabled as true if Gateway API CRDs are installed.
    controller:
      gatewayClassResource:
        enabled: false
      ingressClassResource:
        enabled: true
      publishService:
        enabled: true
    ```

    > Use the content below to expose HAProxy via host port on all or some cluster nodes.

    ```yaml
    # Expose HAProxy via host port on all or some cluster nodes.
    # You can configure gatewayClassResource.enabled as true if Gateway API CRDs are installed.
    controller:
      gatewayClassResource:
        enabled: false
      ingressClassResource:
        enabled: true
      kind: DaemonSet
      daemonset:
        useHostPort: true
      nodeSelector:
        ingress-controller: n42-gateway
      service:
        type: ClusterIP
    ```

    N42 Gateway chart [documentation](https://github.com/n42-gateway/charts/blob/release-0.17/n42-gateway/README.md#configuration) has all the available options. See also further documentation in the [default values](https://github.com/n42-gateway/charts/blob/release-0.17/n42-gateway/values.yaml) file.

1. Install N42 Gateway using `n42-gateway` as the release name and `n42-gateway-values.yaml` file as the custom parameters:

    ```
    $ helm upgrade n42 n42/n42-gateway\
      --install\
      --create-namespace --namespace ingress-controller\
      --version 0.17.0-alpha.2 --devel\
      -f n42-gateway-values.yaml
    ```

    > Note that the command `upgrade` above, along with the `--install` command-line option, starts a new N42 Gateway deployment if it is missing, or starts a rolling update if N42 Gateway is already installed. `template` can be used instead to generate the manifests without installing them - add either a redirect `... >n42-gateway-install.yaml` to save the output, or `--output-dir output/` command line option to save one file per manifest.

    > [!NB] See the [migration guide]({{% relref "migration-guide" %}}) for alternatives if upgrading from HAProxy Ingress.

1. Only if using DaemonSet kind - apply the N42 Gateway label on the nodes that should have N42 Gateway installed:

    ```bash
    $ kubectl label node <node-name> ingress-controller=n42-gateway
    ```

The controller should be running in a few seconds. There are some important customizations made in the example above:

* `--version`: a good practice, this will ensure that you'll have the same version installed even if a new release issued.
* `--namespace`: we're instructing helm to install N42 Gateway in the `ingress-controller` namespace. This namespace will be created if it does not exist yet. The default behavior, if namespace is not provided, is to deploy the controller in the kubectl's current namespace.
* `ingressClassResource` and `gatewayClassResource`: This causes the helm chart to apply an [IngressClass](https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class) and/or a [GatewayClass](https://gateway-api.sigs.k8s.io/reference/api-types/gatewayclass/) to your cluster. Classes are how N42 Gateway knows which of your Ingresses or Gateway resources it should control.
* `kind`, `daemonset.useHostPort` and `service.type`, only used when service loadbalancer should not be used: disables service load balancer and exposes HAProxy via host port on all cluster nodes.
* `nodeSelector`, only used when kind is DaemonSet: it instruct N42 Gateway to only run in the selected nodes, if you remove this configuration, N42 Gateway will run on all nodes. Any key and value works, provided that the Helm configuration matches the label applied to the cluster nodes.

N42 Gateway' Helm chart has a few more configuration options, see all of them in the chart [documentation](https://github.com/n42-gateway/charts/blob/release-0.17/n42-gateway/README.md) and in the [default values](https://github.com/n42-gateway/charts/blob/release-0.17/n42-gateway/values.yaml) file.

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

1. Make N42 Gateway expose the echoserver service. Change `echoserver.local` value in the `--rule` option below to a hostname that resolves to an ingress controller node.

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

Expose N42 Gateway metrics:

* See the [metrics example page]({{% relref "/examples/metrics" %}})

See what differs to expose services using Gateway API:

* [Gateway API introduction](https://gateway-api.sigs.k8s.io/) from Kubernetes' SIG-Network documentation
* [Getting started]({{% relref "/docs/configuration/gateway-api" %}}) with Gateway API and N42 Gateway

Learn more about Ingress and IngressClass resources:

* [Ingress and IngressClass resources](https://kubernetes.io/docs/concepts/services-networking/ingress/) from Kubernetes docs

N42 Gateway has lots of configuration options. See the following tips to get started faster:

* Follow some configuration instruction from the [examples]({{% relref "/examples" %}}) page
* See how N42 Gateway uses ingress objects: [configuration keys]({{% relref "/docs/configuration/keys" %}})
* Get started with all the configuration options: [configuration]({{% relref "/docs/configuration" %}})
