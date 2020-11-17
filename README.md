# HAProxy Ingress controller

[Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) controller
implementation for [HAProxy](http://www.haproxy.org/) loadbalancer.

[![Build Status](https://travis-ci.org/jcmoraisjr/haproxy-ingress.svg?branch=master)](https://travis-ci.org/jcmoraisjr/haproxy-ingress) [![Docker Repository on Quay](https://quay.io/repository/jcmoraisjr/haproxy-ingress/status "Docker Repository on Quay")](https://quay.io/repository/jcmoraisjr/haproxy-ingress)

HAProxy Ingress is a Kubernetes ingress controller: it configures a HAProxy instance
to route incoming requests from an external network to the in-cluster applications.
The routing configurations are built reading specs from the Kubernetes cluster.
Updates made to the cluster are applied on the fly to the HAProxy instance.

## Use HAProxy Ingress

**Documentation:**

* Getting started guide: [/docs/getting-started/](https://haproxy-ingress.github.io/docs/getting-started/)
* Global and per ingress/service configuration keys: [/docs/configuration/keys/](https://haproxy-ingress.github.io/docs/configuration/keys/)
* Command-line options: [/docs/configuration/command-line/](https://haproxy-ingress.github.io/docs/configuration/command-line/)
* Old single-page doc (up to v0.8): [/release-0.8/README.md](https://github.com/jcmoraisjr/haproxy-ingress/blob/release-0.8/README.md)

**Supported versions:**

| HAProxy Ingress        | HAProxy   | Kubernetes |
|------------------------|-----------|------------|
| `v0.12` (development)  | `2.2` (*) | `1.18+`    |
| `v0.11` **(latest)**   | `2.1`     | `1.14+`    |
| `v0.10`                | `2.0`     | `1.8+`     |
| `v0.9`                 | `1.9`     | `1.8+`     |
| `v0.8`                 | `1.8`     | `1.8+`     |

* Beta quality versions (`beta`/`canary` tags) has some new, but battle tested features, usually running on some of our production clusters
* Development versions (`snapshot` tags) has major changes with few tests, usually not recommended for production
* (*) Since `v0.12` HAProxy Ingress supports an external `2.0+` haproxy deployment

**Community:**

* [Slack](https://kubernetes.slack.com/channels/haproxy-ingress): We're in the [#haproxy-ingress](https://kubernetes.slack.com/channels/haproxy-ingress) channel on Kubernetes Slack. Take an invite [here](https://slack.k8s.io) if not subscribed yet
* [Users mailing list](https://groups.google.com/forum/#!forum/haproxy-ingress): Announcements and discussion on a mailing list
* [Stack Overflow](https://stackoverflow.com/questions/tagged/haproxy-ingress): Practical questions and curated answers

## Develop HAProxy Ingress

Building:

```
mkdir -p $GOPATH/src/github.com/jcmoraisjr
cd $GOPATH/src/github.com/jcmoraisjr
git clone https://github.com/jcmoraisjr/haproxy-ingress.git
cd haproxy-ingress
make
```

The following `make` targets are currently supported:

* `install`: run `go install` which saves some building time.
* `build` (default): compiles HAProxy Ingress and generates an ELF (Linux) executable at `rootfs/haproxy-ingress-controller` despite the source platform.
* `test`: run unit tests
* `image`: generates a Docker image tagged `localhost/haproxy-ingress:latest`
