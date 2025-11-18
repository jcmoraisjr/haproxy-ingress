# HAProxy Ingress controller

[Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) controller
implementation for [HAProxy](http://www.haproxy.org/) loadbalancer.

[![build](https://img.shields.io/github/actions/workflow/status/jcmoraisjr/haproxy-ingress/build.yaml?branch=master&logo=github)](https://github.com/jcmoraisjr/haproxy-ingress/actions/workflows/build.yaml) [![helm](https://img.shields.io/badge/helm%20chart-ready-blue?logo=helm)](https://artifacthub.io/packages/helm/haproxy-ingress/haproxy-ingress)

HAProxy Ingress is a Kubernetes ingress controller: it configures a HAProxy instance
to route incoming requests from an external network to the in-cluster applications.
The routing configurations are built reading specs from the Kubernetes cluster.
Updates made to the cluster are applied on the fly to the HAProxy instance.

## Use HAProxy Ingress

**Documentation:**

* Getting started guide: [/docs/getting-started/](https://haproxy-ingress.github.io/docs/getting-started/)
* Global and per ingress/service configuration keys: [/docs/configuration/keys/](https://haproxy-ingress.github.io/docs/configuration/keys/)
* Command-line options: [/docs/configuration/command-line/](https://haproxy-ingress.github.io/docs/configuration/command-line/)

**Supported versions:**

| HAProxy Ingress                                      | Embedded<br/>HAProxy | Supported<br/>Kubernetes | External<br/>HAProxy (*) |
|------------------------------------------------------|----------------------|--------------------------|--------------------------|
| [`v0.16`](CHANGELOG/CHANGELOG-v0.16.md) (beta)       | `2.8`                | `1.21+`                  | `2.4+`                   |
| [`v0.15`](CHANGELOG/CHANGELOG-v0.15.md) **(latest)** | `2.6`                | `1.21+`                  | `2.2+`                   |
| [`v0.14`](CHANGELOG/CHANGELOG-v0.14.md)              | `2.4`                | `1.19+`                  | `2.2+`                   |
| [`v0.13`](CHANGELOG/CHANGELOG-v0.13.md) (critical fixes) | `2.3` up to `v0.13.10`<br/>`2.4` on `v0.13.11`+   | `1.19+`   | `2.2+`     |

* Beta quality versions (`beta` / `canary` tags) has some new, but battle tested features, usually running on some of our production clusters
* Development versions (`alpha` / `snapshot` tags) has major changes with few tests, usually not recommended for production
* (*) Minimum supported HAProxy version if using an [external HAProxy](https://haproxy-ingress.github.io/docs/examples/external-haproxy/) instance

**Community:**

* [Slack](https://kubernetes.slack.com/channels/haproxy-ingress): We're in the [#haproxy-ingress](https://kubernetes.slack.com/channels/haproxy-ingress) channel on Kubernetes Slack. Take an [invite](https://slack.k8s.io) if not subscribed yet
* [Users mailing list](https://groups.google.com/forum/#!forum/haproxy-ingress): Announcements and discussion on a mailing list
* [Stack Overflow](https://stackoverflow.com/questions/tagged/haproxy-ingress): Practical questions and curated answers

## Develop HAProxy Ingress

The instructions below are valid for v0.14 and newer. See [v0.13](https://github.com/jcmoraisjr/haproxy-ingress/blob/release-0.13/README.md#develop-haproxy-ingress) branch for older versions.

**Building and running locally:**

```
mkdir -p $GOPATH/src/github.com/jcmoraisjr
cd $GOPATH/src/github.com/jcmoraisjr
git clone https://github.com/jcmoraisjr/haproxy-ingress.git
cd haproxy-ingress
make run
```

Dependencies to run locally:

* Golang
* HAProxy compiled with `USE_OPENSSL=1` and `USE_LUA=1`
* Lua with `lua-json` (`luarocks install lua-json`) if using Auth External or OAuth
* Kubernetes network should be reachable from the local machine for a proper e2e test

**Building container image:**

Fast build - cross compile for linux (locally) and generate `localhost/haproxy-ingress:latest`:

```
make image
```

Official image - build in a multi-stage Dockerfile and generate `localhost/haproxy-ingress:latest`:

```
make docker-build
```

Deploy local image using Helm:

```
helm repo add haproxy-ingress https://haproxy-ingress.github.io/charts
helm install haproxy-ingress haproxy-ingress/haproxy-ingress\
  --create-namespace --namespace=ingress-controller\
  --set controller.image.repository=localhost/haproxy-ingress\
  --set controller.image.tag=latest\
  --set controller.image.pullPolicy=Never
```

**make options:**

The following `make` variables are supported:

* `CONTROLLER_TAG` (defaults to `localhost/haproxy-ingress:latest`): tag name for `make image` and `make docker-build`.
* `LOCAL_FS_PREFIX` (defaults to `/tmp/haproxy-ingress`): temporary directory for `make run`.
* `KUBECONFIG` (defaults to `$KUBECONFIG`, or `$(HOME)/.kube/config` if the former is empty): Kubernetes from where to read Ingress configurations.
* `CONTROLLER_CONFIGMAP`: `<namespace>/<name>` of the ConfigMap with global configurations.
* `CONTROLLER_ARGS`: space separated list of additional command-line arguments.

The following `make` targets are supported:

* `build` (default): Compiles HAProxy Ingress using the default OS and arch, and generates an executable at `bin/controller`.
* `run`: Runs HAProxy Ingress locally.
* `lint`: Runs [`golangci-lint`](https://golangci-lint.run/)
* `test`: Runs unit tests.
* `test-integration`: Runs integration tests, needs haproxy 2.2+ in the path.
* `linux-build`: Compiles HAProxy Ingress and generates an ELF (Linux) executable despite the source platform at `rootfs/haproxy-ingress-controller`. Used by `image` step.
* `image`: Compiles HAProxy Ingress locally and generates a Docker image.
* `docker-build`: Compiles HAProxy Ingress and generates a Docker image using a multi-stage Dockerfile.
