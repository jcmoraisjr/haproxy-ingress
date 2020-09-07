# HAProxy Ingress controller

[Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/) controller
implementation for [HAProxy](http://www.haproxy.org/) loadbalancer.

[![Build Status](https://travis-ci.org/jcmoraisjr/haproxy-ingress.svg?branch=master)](https://travis-ci.org/jcmoraisjr/haproxy-ingress) [![Docker Repository on Quay](https://quay.io/repository/jcmoraisjr/haproxy-ingress/status "Docker Repository on Quay")](https://quay.io/repository/jcmoraisjr/haproxy-ingress)

HAProxy Ingress is a Kubernetes ingress controller: it configures a HAProxy instance
to route incoming requests from an external network to the in-cluster applications.
The routing configurations are built reading specs from the Kubernetes cluster.
Updates made to the cluster are applied on the fly to the HAProxy instance.

## Use HAProxy Ingress

Documentation:

* Home of HAProxy Ingress docs: [haproxy-ingress.github.io/docs](https://haproxy-ingress.github.io/docs/)
* Global ConfigMap options and ingress/service annotations, now named configuration keys: [haproxy-ingress.github.io/docs/configuration/keys/](https://haproxy-ingress.github.io/docs/configuration/keys/)
* Static command-line options: [haproxy-ingress.github.io/docs/configuration/command-line/](https://haproxy-ingress.github.io/docs/configuration/command-line/)
* Old single-page doc (up to v0.8): [/release-0.8/README.md](https://github.com/jcmoraisjr/haproxy-ingress/blob/release-0.8/README.md)

Community:

* [Slack](http://jitec.com.br/slack/): Chat and get support from other HAProxy Ingress users
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
