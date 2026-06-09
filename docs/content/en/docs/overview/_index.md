---
title: "Overview"
linkTitle: "Overview"
weight: 1
description: >
  What HAProxy Ingress is and how it works.
---

## HAProxy

> [!INFO] TODO
>
> About the HAProxy load balancer itself and why HAProxy.

## Ingress Controllers

> [!INFO] TODO
>
> About the Kubernetes' ingress controllers, what HAProxy Ingress watches in the k8s cluster and how it builds HAProxy configuration.

## Releases

HAProxy Ingress is released as a Docker image on top of Alpine's flavor of
[HAProxy image](https://hub.docker.com/_/haproxy).

See the [individual releases](https://github.com/n42-gateway/n42-gateway/releases)  to read the changelog per release.

Images are built by a [GitHub Workflow](https://github.com/n42-gateway/n42-gateway/actions/workflows/image.yaml)
and deployed to [ghcr.io](https://github.com/n42-gateway/n42-gateway/pkgs/container/n42-gateway) and
[quay.io](https://quay.io/repository/n42-gateway/n42-gateway) whenever a tag is applied.
The `latest` tag will always point to the latest stable version while `canary` tag will always
point to the latest beta-quality and release-candidate versions.

Before the beta-quality releases, the source code could also be tagged and images deployed.
The `snapshot` tag will always point to the latest tagged version, which could be a release,
a beta-quality or a development version.

## Where should I go next?

* [Getting Started]({{% relref "/docs/getting-started" %}}): Get started with HAProxy Ingress!
