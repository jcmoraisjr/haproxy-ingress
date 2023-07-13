# CHANGELOG v0.15 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.14!](#upgrade-notes)
  * [Deprecated command-line options](#deprecated-command-line-options)
  * [Upgrading with embedded Acme](#upgrading-with-embedded-acme)
  * [Upgrading with custom repositories](#upgrading-with-custom-repositories)
* [Contributors](#contributors)
* [v0.15.0-alpha.2](#v0150-alpha2)
  * [Reference](#reference-a2)
  * [Release notes](#release-notes-a2)
  * [Improvements](#improvements-a2)
  * [Fixes](#fixes-a2)
* [v0.15.0-alpha.1](#v0150-alpha1)
  * [Reference](#reference-a1)
  * [Release notes](#release-notes-a1)
  * [Improvements](#improvements-a1)
  * [Fixes](#fixes-a1)

## Major improvements

Highlights of this version

* Embedded HAProxy upgrade from 2.4 to 2.6.
* Change from a legacy controller engine component to [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime).
* Full Gateway API support (v0.15 feature, under development)

## Upgrade notes

Breaking backward compatibility from v0.14:

* HAProxy Ingress used to start as root by default up to v0.14. Starting on v0.15 the controller container starts as the non root user `haproxy`, UID `99`. This change should impact deployments that need to start as root, e.g. chroot enabled, binding on privileged TCP ports (1024 or below) on old container runtimes, etc. Workloads that need to run as root can, despite the security risk, configure the security context in the deployment resource or Helm chart to enforce starting user as root. See the [security doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#security) for configuration examples.
* Besides starting as non root, the `haproxy` user ID changed from `1001` to `99`. The former `1001` UID was chosen and created in a day `docker.io/haproxy` container image started as root (2.3 and older). Starting from 2.4 the `haproxy` user was added as UID `99`. In v0.15 we started to use the same UID, so file systems shared between controller and haproxy doesn't have permission issues.
* Election ID was changed, see the [documentation](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/#election-id) for customization options. Election ID is used by embedded Acme signer and status updater to, respectively, request certificates and update ingress status. A cluster of HAProxy Ingress controllers will elect two controllers at the same time during the rolling update from any other version to v0.15. Ingress status does not have an impact. See [Upgrading with embedded Acme](#upgrading-with-embedded-acme) below for details about upgrading with embedded Acme signer enabled.
* Helm chart has now a distinct field for the registry of an image, which should impact charts that configure custom repositories. See [Upgrading with custom repositories](#upgrading-with-custom-repositories) below for the details.
* Log debug level is enabled by default. HAProxy Ingress has a good balance between low verbosity and useful information on its debug level.
* Default image for the log sidecar changed from `whereisaaron/kube-syslog-sidecar` to `ghcr.io/crisu1710/kube-syslog-sidecar:0.2.0`. It is the same codebase, just adding support for multiple architectures.

### Deprecated command-line options

The following command-line options were deprecated on v0.15 and should be removed on a future version:

* `--acme-election-id`
* `--disable-pod-list`
* `--force-namespace-isolation`
* `--healthz-port`

See their documentation at the [command-line options documentation page](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/).

### Upgrading with embedded Acme

Embedded Acme signer uses leader election to request certificates just once, despite the size of the HAProxy Ingress cluster. When rolling update to v0.15, one controller from the older version and another controller from the new version will understand themselves as the leader at the same time, due to the change in the election ID.

The only drawback is that, if the expiring certificate check runs during the rolling update, the embedded Acme signer will call the Acme backend twice per certificate that needs to be issued. This behavior can be avoided by changing the global [`acme-terms-agreed`](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#acme) configuration key as false during the rolling update, updating to true as soon as the rolling update has finished.

### Upgrading with custom repositories

HAProxy Ingress Helm chart now uses distinct fields for the registry and the repository of a container image. If a Helm chart customizes `image.repository` of any container image, now it should consider the `image.registry` field as well.

v0.14 example:

```yaml
controller:
  haproxy:
    enabled: true
    image:
      repository: myhub.local/haproxy
```

Starting on v0.15, registry and repository should be placed on distinct attributes:

```yaml
controller:
  haproxy:
    enabled: true
    image:
      registry: myhub.local
      repository: haproxy
```

See the full syntax and default values in the [README.md](https://github.com/haproxy-ingress/charts/blob/release-0.15/haproxy-ingress/README.md#configuration) and in the [values.yaml](https://github.com/haproxy-ingress/charts/blob/release-0.15/haproxy-ingress/values.yaml) files of the HAProxy Ingress Helm chart.

## Contributors

* Andrej Baran ([andrejbaran](https://github.com/andrejbaran))
* Błażej Frydlewicz ([blafry](https://github.com/blafry))
* Chris Boot ([bootc](https://github.com/bootc))
* Dmitry Misharov ([quarckster](https://github.com/quarckster))
* genofire ([genofire](https://github.com/genofire))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Karan Chaudhary ([lafolle](https://github.com/lafolle))
* Mac Chaffee ([mac-chaffee](https://github.com/mac-chaffee))
* Manuel Rüger ([mrueg](https://github.com/mrueg))
* Michele Palazzi ([ironashram](https://github.com/ironashram))
* Robin Schneider ([Crisu1710](https://github.com/Crisu1710))
* Tomasz Zurkowski ([doriath](https://github.com/doriath))

# v0.15.0-alpha.2

## Reference (a2)

* Release date: `2023-07-13`
* Helm chart: `--version 0.15.0-alpha.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0-alpha.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.15.0-alpha.2`
* Embedded HAProxy version: `2.6.14`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.15.0-alpha.2`

## Release notes (a2)

This is the second tag of the v0.15 branch. Most of the changes are fixes or improvements merged to stable branches. We still have some refactors under development which are prerequisites for a better Gateway API support. Such refactors will also be applied as new configuration keys, benefiting also Ingress workloads.

Exclusive v0.15 changes include:

- Robin Schneider added a new default image for the log sidecar with multi architecture support
- Fix the notification of endpoint changes

Other changes already merged to the stable branches:

- Karan Chaudhary added EndpointSlices support. This option is disabled by default, enable it by adding `--enable-endpointslices-api` command-line option.
- HTTP redirect now has an option to skip some paths, the default configuration adds an exception to `/.well-known/acme-challenge`.
- External HAProxy was failing with the message "cannot open the file '/var/lib/haproxy/crt/default-fake-certificate.pem'.". This happened due to missing permission to read certificate and private key files when HAProxy container starts as non root, which is the default since HAProxy 2.4.
- An update to the External HAProxy example page adds options to fix permission failures to bind ports `:80` and `:443`, see the [example page](https://haproxy-ingress.github.io/v0.15/docs/examples/external-haproxy/#a-word-about-security).

Fixes merged to stable branches:

- ConfigMap based TCP services was randomly missing when the controller started, being reincluded only after the first reconciliation.
- An endless redirect might happen when configuring redirects on domains whose TLS secret declares two or more domains
- Configuration snippet was missing on backends in TCP mode
- ConfigMap based TCP services were making HAProxy to reload without need, depending on the order that service endpoints were being listed
- Unused HAProxy backends might leak in the configuration, depending on how the configuration is changed, when backend sharding is enabled
- A wildcard was not being accepted by the CORS Allowed Header configuration

Dependencies:

- embedded haproxy from 2.6.9 to 2.6.14
- client-go from v0.26.5 to v0.26.6
- controller-runtime from v0.14.4 to v0.14.6
- golang from 1.19.10 to 1.19.11

## Improvements (a2)

New features and improvements since `v0.15.0-alpha.1`:

* Adds support for EndpointSlices API in master [#959](https://github.com/jcmoraisjr/haproxy-ingress/pull/959) (lafolle) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/#enable-endpointslices-api)
  * Command-line options:
    * `--enable-endpointslices-api`
* Skip acme-challenge path on to/from redirects [#995](https://github.com/jcmoraisjr/haproxy-ingress/pull/995) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#redirect)
  * Configuration keys:
    * `no-redirect-locations`
* Ensure predictable tcp by sorting endpoints [#1003](https://github.com/jcmoraisjr/haproxy-ingress/pull/1003) (jcmoraisjr)
* Change owner of crt/key files to haproxy pid [#1004](https://github.com/jcmoraisjr/haproxy-ingress/pull/1004) (jcmoraisjr)
* Update dependencies [#1006](https://github.com/jcmoraisjr/haproxy-ingress/pull/1006) (mrueg)
* Prefer ingressClassName over annotations in docs [#986](https://github.com/jcmoraisjr/haproxy-ingress/pull/986) (mac-chaffee)
* Add endpointslice api on v0.15 handler [#1013](https://github.com/jcmoraisjr/haproxy-ingress/pull/1013) (jcmoraisjr)
* update golang from 1.19.10 to 1.19.11 [cec71c2](https://github.com/jcmoraisjr/haproxy-ingress/commit/cec71c2f495d31449114c0d2a1513ee826f9cd3f) (Joao Morais)
* update client-go from v0.26.5 to v0.26.6 [ce93e8a](https://github.com/jcmoraisjr/haproxy-ingress/commit/ce93e8a1c408304b3eac4539a0749304b1622153) (Joao Morais)
* update dependencies [925e6b1](https://github.com/jcmoraisjr/haproxy-ingress/commit/925e6b1739e9c9900ba7aca77363ee427e91bf3f) (Joao Morais)

Chart improvements since `v0.15.0-alpha.1`:

* improve log sidecar for multiple architectures [#62](https://github.com/haproxy-ingress/charts/pull/62) (Crisu1710)
* Enables endpointslicesapi [#66](https://github.com/haproxy-ingress/charts/pull/66) (lafolle)
* ignore PodSecurityPolicy on cluster v1.25 or newer [53c8373](https://github.com/haproxy-ingress/charts/commit/53c83735318da4d0dcbba706fdb06cd0a75258ce) (Joao Morais)
* Defaults securityContext to allow privileged ports [#68](https://github.com/haproxy-ingress/charts/pull/68) (jcmoraisjr)
* Revert default securityContext config [#70](https://github.com/haproxy-ingress/charts/pull/70) (jcmoraisjr)
* Add lifecycle hooks to external HAProxy container [#72](https://github.com/haproxy-ingress/charts/pull/72) (bootc)
* chore: update HorizontalPodAutoscaler apiVersion [#71](https://github.com/haproxy-ingress/charts/pull/71) (quarckster)
* add conditional PodDisruptionBudget [#73](https://github.com/haproxy-ingress/charts/pull/73) (jcmoraisjr)

## Fixes (a2)

* Fixes configmap based tcp sync [#1001](https://github.com/jcmoraisjr/haproxy-ingress/pull/1001) (jcmoraisjr)
* Redirect hosts only to domains with associated backends [#1010](https://github.com/jcmoraisjr/haproxy-ingress/pull/1010) (jcmoraisjr)
* fix: config-backend annotation also for TCP-Backends [#1009](https://github.com/jcmoraisjr/haproxy-ingress/pull/1009) (genofire)
* Create endpoints on a predictable order [#1011](https://github.com/jcmoraisjr/haproxy-ingress/pull/1011) (jcmoraisjr)
* Remove generation predicate on endpoints [#1012](https://github.com/jcmoraisjr/haproxy-ingress/pull/1012) (jcmoraisjr)
* Fix shard render when the last backend is removed [#1015](https://github.com/jcmoraisjr/haproxy-ingress/pull/1015) (jcmoraisjr)
* Add wildcard as a valid cors allowed header [#1016](https://github.com/jcmoraisjr/haproxy-ingress/pull/1016) (jcmoraisjr)

# v0.15.0-alpha.1

## Reference (a1)

* Release date: `2023-02-20`
* Helm chart: `--version 0.15.0-alpha.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0-alpha.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.15.0-alpha.1`
* Embedded HAProxy version: `2.6.9`

## Release notes (a1)

This is the first tag of the v0.15 branch, which brings most, if not all the breaking changes expected to the v0.15 release:

- Controller now starts as the non root `haproxy` user.
- `haproxy` user ID was changed from `1001` to `99`.
- ElectionID changed for leader election.
- Helm chart has now two separated fields for registry and repository of a container image.
- Log now uses level 2 by default, a low verbosity level with useful debugging info.

See [upgrade notes](https://github.com/jcmoraisjr/haproxy-ingress/blob/master/CHANGELOG/CHANGELOG-v0.15.md#upgrade-notes) for detailed info and before update your environment.

Besides that, the following areas had some improvement since v0.14:

- Embedded and default external HAProxy version was updated to 2.6 instead of the expected 2.5. Non-LTS HAProxy, just like 2.3 and 2.5, have a short lifecycle and we're a few cycles behind their releases. Our plan is to start to release about 2 minor versions per year again, following HAProxy Community Edition releases, so we should expect our v0.16 using HAProxy 2.6 as well. Future controller versions might start to use non LTS again in the future, provided that we're close enough to their release cycle and we don't have a newer LTS version to use instead.
- HTTP header match is a long awaited feature that needed a few internal refactors to work properly. This is one of the challenging implementations for the Gateway API, which's available for Ingress resources as well. See the [HTTP header match documentation](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#http-match) for usage examples.
- HAProxy Ingress now uses [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) as the engine that watches and notifies resource changes. This is a huge internal change that improves code quality and organization, but with almost no externally visible change. The most impacted feature is the Ingress Status Update, which should be rewritten from scratch in order to fit the new controller engine. Give this a few more attention and let us know if you found any problem via our Slack channel, mailing list, or opening a new GitHub issue.

## Improvements (a1)

New features and improvements since `v0.14.2`:

* update embedded haproxy from 2.4.18 to 2.5.8 [6b0a10a](https://github.com/jcmoraisjr/haproxy-ingress/commit/6b0a10a90bd099cf0d27735335b3b4b1b86c5cd4) (Joao Morais)
* update golang from 1.17.13 to 1.19.1 [781dd7e](https://github.com/jcmoraisjr/haproxy-ingress/commit/781dd7e5d20403bda73cfe8c2c47ca77e7f61ea2) (Joao Morais)
* update client-go from v0.23.10 to v0.25.0 [c7d8ae3](https://github.com/jcmoraisjr/haproxy-ingress/commit/c7d8ae39fe4d6e4850a3ef548f1059ee7a8b06c4) (Joao Morais)
* update go mod from 1.17 to 1.19 [2d2cb4e](https://github.com/jcmoraisjr/haproxy-ingress/commit/2d2cb4e247ab0b6af8d0b64377956c3bc23cc83c) (Joao Morais)
* Add http-header-match annotation [#944](https://github.com/jcmoraisjr/haproxy-ingress/pull/944) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#http-match)
  * Configuration keys:
    * `http-header-match`
    * `http-header-match-regex`
* Update gateway-api from v0.4.1 v0.5.0 [#947](https://github.com/jcmoraisjr/haproxy-ingress/pull/947) (jcmoraisjr)
* Update to hugo v0.110.0 and update node deps [#968](https://github.com/jcmoraisjr/haproxy-ingress/pull/968) (mac-chaffee)
* Add controller-runtime support [#933](https://github.com/jcmoraisjr/haproxy-ingress/pull/933) (jcmoraisjr)
* Add source IP related config keys [#987](https://github.com/jcmoraisjr/haproxy-ingress/pull/987) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#forwardfor)
  * Configuration keys:
    * `original-forwarded-for-hdr`
    * `real-ip-hdr`
* update client-go from v0.25.0 to v0.26.1 [1e2fc75](https://github.com/jcmoraisjr/haproxy-ingress/commit/1e2fc75beee9d44f808ae9c5a12b3b2f3fe8ed8b) (Joao Morais)
* update embedded haproxy from 2.5.8 to 2.6.9 [2842a74](https://github.com/jcmoraisjr/haproxy-ingress/commit/2842a74eb98672896a313a93c8e752fbb69f6f74) (Joao Morais)
* Add optional frontend based external authentication call [#988](https://github.com/jcmoraisjr/haproxy-ingress/pull/988) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#auth-external)
  * Configuration keys:
    * `auth-external-placement`
* update go from 1.19.1 to 1.19.6 [3a8edee](https://github.com/jcmoraisjr/haproxy-ingress/commit/3a8edee35e0a865f4d05bc5b38b2b5b79fe9e0e6) (Joao Morais)
* Change controller container to non root user [#992](https://github.com/jcmoraisjr/haproxy-ingress/pull/992) (jcmoraisjr)

Chart improvements since `v0.14.2`:

* Allow customFiles to be used without custom template [#57](https://github.com/haproxy-ingress/charts/pull/57) (ironashram)
* Add permissions for leases, needed by leaderelection [#58](https://github.com/haproxy-ingress/charts/pull/58) (mac-chaffee)
* Fix securityContext conditional in default backend [#60](https://github.com/haproxy-ingress/charts/pull/60) (doriath)
* Parameterize container port and add missing configs on default backend and prometheus [#59](https://github.com/haproxy-ingress/charts/pull/59) (blafry)
* Extracted registry value to a separate variable [#61](https://github.com/haproxy-ingress/charts/pull/61) (blafry)

## Fixes (a1)

* Skip status update when update-status is false [#991](https://github.com/jcmoraisjr/haproxy-ingress/pull/991) (jcmoraisjr)
