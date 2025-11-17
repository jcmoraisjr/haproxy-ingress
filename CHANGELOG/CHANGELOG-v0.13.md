# CHANGELOG v0.13 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.12!](#upgrade-notes)
* [Contributors](#contributors)
* [v0.13.19](#v01319)
  * [Reference](#reference-r19)
  * [Release notes](#release-notes-r19)
  * [Fixes and improvements](#fixes-and-improvements-r19)
* [v0.13.18](#v01318)
  * [Reference](#reference-r18)
  * [Release notes](#release-notes-r18)
  * [Fixes and improvements](#fixes-and-improvements-r18)
* [v0.13.17](#v01317)
  * [Reference](#reference-r17)
  * [Release notes](#release-notes-r17)
  * [Fixes and improvements](#fixes-and-improvements-r17)
* [v0.13.16](#v01316)
  * [Reference](#reference-r16)
  * [Release notes](#release-notes-r16)
  * [Fixes and improvements](#fixes-and-improvements-r16)
* [v0.13.15](#v01315)
  * [Reference](#reference-r15)
  * [Release notes](#release-notes-r15)
  * [Fixes and improvements](#fixes-and-improvements-r15)
* [v0.13.14](#v01314)
  * [Reference](#reference-r14)
  * [Release notes](#release-notes-r14)
  * [Fixes and improvements](#fixes-and-improvements-r14)
* [v0.13.13](#v01313)
  * [Reference](#reference-r13)
  * [Release notes](#release-notes-r13)
  * [Fixes and improvements](#fixes-and-improvements-r13)
* [v0.13.12](#v01312)
  * [Reference](#reference-r12)
  * [Release notes](#release-notes-r12)
  * [Fixes and improvements](#fixes-and-improvements-r12)
* [v0.13.11](#v01311)
  * [Reference](#reference-r11)
  * [Release notes](#release-notes-r11)
  * [Fixes and improvements](#fixes-and-improvements-r11)
* [v0.13.10](#v01310)
  * [Reference](#reference-r10)
  * [Release notes](#release-notes-r10)
  * [Fixes and improvements](#fixes-and-improvements-r10)
* [v0.13.9](#v0139)
  * [Reference](#reference-r9)
  * [Release notes](#release-notes-r9)
  * [Fixes and improvements](#fixes-and-improvements-r9)
* [v0.13.8](#v0138)
  * [Reference](#reference-r8)
  * [Release notes](#release-notes-r8)
  * [Fixes and improvements](#fixes-and-improvements-r8)
* [v0.13.7](#v0137)
  * [Reference](#reference-r7)
  * [Release notes](#release-notes-r7)
  * [Fixes and improvements](#fixes-and-improvements-r7)
* [v0.13.6](#v0136)
  * [Reference](#reference-r6)
  * [Release notes](#release-notes-r6)
  * [Fixes and improvements](#fixes-and-improvements-r6)
* [v0.13.5](#v0135)
  * [Reference](#reference-r5)
  * [Release notes](#release-notes-r5)
  * [Fixes and improvements](#fixes-and-improvements-r5)
* [v0.13.4](#v0134)
  * [Reference](#reference-r4)
  * [Release notes](#release-notes-r4)
  * [Fixes and improvements](#fixes-and-improvements-r4)
* [v0.13.3](#v0133)
  * [Reference](#reference-r3)
  * [Release notes](#release-notes-r3)
  * [Fixes and improvements](#fixes-and-improvements-r3)
* [v0.13.2](#v0132)
  * [Reference](#reference-r2)
  * [Release notes](#release-notes-r2)
  * [Fixes and improvements](#fixes-and-improvements-r2)
* [v0.13.1](#v0131)
  * [Reference](#reference-r1)
  * [Release notes](#release-notes-r1)
  * [Fixes and improvements](#fixes-and-improvements-r1)
* [v0.13.0](#v0130)
  * [Reference](#reference-r0)
  * [Release notes](#release-notes-r0)
  * [Fixes and improvements](#fixes-and-improvements-r0)
* [v0.13.0-beta.2](#v0130-beta2)
  * [Reference](#reference-b2)
  * [Release notes](#release-notes-b2)
  * [Improvements](#improvements-b2)
  * [Fixes](#fixes-b2)
* [v0.13.0-beta.1](#v0130-beta1)
  * [Reference](#reference-b1)
  * [Improvements](#improvements-b1)
  * [Fixes](#fixes-b1)
* [v0.13.0-snapshot.3](#v0130-snapshot3)
  * [Reference](#reference-s3)
  * [Improvements](#improvements-s3)
  * [Fixes](#fixes-s3)
* [v0.13.0-snapshot.2](#v0130-snapshot2)
  * [Reference](#reference-s2)
  * [Improvements](#improvements-s2)
  * [Fixes](#fixes-s2)
* [v0.13.0-snapshot.1](#v0130-snapshot1)
  * [Reference](#reference-s1)
  * [Improvements](#improvements-s1)
  * [Fixes](#fixes-s1)

## Major improvements

Highlights of this version

* HAProxy upgrade from 2.2 to 2.3.
* Add arm64 image
* Ingress API upgrade from `networking.k8s.io/v1beta1` to `networking.k8s.io/v1`.
* Partial implementation of Gateway API - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/gateway-api/)
* TCP services using ingress resources - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#tcp-services)
* External authentication - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#auth-external)
* Several new custom configurations - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#configuration-snippet)

## Upgrade notes

Breaking backward compatibility from v0.12

* Kubernetes minimal version changed from 1.18 to 1.19.
* External HAProxy minimal version changed from 2.0 to 2.2.
* Threads: by default HAProxy process will automatically configure `nbthread` to the number of available CPUs, instead of `2`, if `nbthread` is not declared and the platform supports CPU affinity. There is no change in the behavior if `nbthread` is declared.
* Global ConfigMap: a missing ConfigMap configured with `--configmap` used to be ignored, now the controller will crash if the resource does not exist.
* TLS configuration: v0.12 and older versions add hostnames to the HTTP and HTTPS maps despite the TLS attribute configuration. v0.13 will only add hostnames to the HTTPS map if the Ingress' TLS attribute lists the hostname, leading to 404 errors on misconfigured clusters. This behavior can be changed with `ssl-always-add-https` as a global or per hostname configuration, see the configuration [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#ssl-always-add-https).
* OAuth2: `auth-request.lua` was updated and also the haproxy variable name with user's email address. This update will have no impact if neither the Lua script nor the `oauth2-headers` configuration key were changed.
* OAuth2 with external HAProxy sidecar: the new Lua script has dependency with `lua-json4` which should be installed in the external instance.
* Basic Authentication: `auth-type` configuration key was deprecated and doesn't need to be used. This will only impact deployments that configures the `auth-secret` without configuring `auth-type` - in this scenario v0.12 won't configure Basic Authentication, but v0.13 will.
* SSL passthrough: Hostnames configured as `ssl-passthrough` will now add non root paths `/` of these hostnames to the HAProxy's HTTP port. v0.12 and older controller versions log a warning and ignore such configuration. HTTPS requests have no impact.

## Contributors

* Andrej Baran ([andrejbaran](https://github.com/andrejbaran))
* Andrew Rodland ([arodland](https://github.com/arodland))
* Bart Versluijs ([bartversluijs](https://github.com/bartversluijs))
* Chris Boot ([bootc](https://github.com/bootc))
* Dmitry Misharov ([quarckster](https://github.com/quarckster))
* genofire ([genofire](https://github.com/genofire))
* ironashram ([ironashram](https://github.com/ironashram))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Karan Chaudhary ([lafolle](https://github.com/lafolle))
* Maël Valais ([maelvls](https://github.com/maelvls))
* Mateusz Kubaczyk ([mkubaczyk](https://github.com/mkubaczyk))
* Michał Zielonka ([michal800106](https://github.com/michal800106))
* Neil Seward ([sealneaward](https://github.com/sealneaward))
* paul ([toothbrush](https://github.com/toothbrush))
* Ricardo Katz ([rikatz](https://github.com/rikatz))
* Roman Gherta ([rgherta](https://github.com/rgherta))
* ssanders1449 ([ssanders1449](https://github.com/ssanders1449))
* Wojciech Chojnowski ([DCkQ6](https://github.com/DCkQ6))

# v0.13.19

## Reference (r19)

* Release date: `2025-10-10`
* Helm chart: `--version 0.13.19`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.19`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.13.19`
* Embedded HAProxy version: `2.4.30`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.19`

## Release notes (r19)

This release updates the embedded haproxy version, which fixes CVE-2025-11230, see HAProxy release notes https://www.mail-archive.com/haproxy@formilux.org/msg46188.html . This CVE cannot be exploited on HAProxy Ingress because it does not use any of the vulnerable converters. A proxy without the fix can however be exploited by an internal user having access to the Ingress API, from a controller that does not deny configuration snippets via annotations.

Other issues were also found and fixed:

- Chitoku found a regression on some certificate related annotations not working with the `file://` protocol, after implementing global support on those annotations.
- Artyom found the fronting-proxy configuration overwriting the `X-Forwarded-Proto` header when both the fronting proxy and the regular HTTP shares the same TCP port number.

Dependencies:

- embedded haproxy from 2.4.29 to 2.4.30
- go from 1.23.11 to 1.23.12

## Fixes and improvements (r19)

Fixes and improvements since `v0.13.18`:

* fix reading backend ca certificate from file [#1297](https://github.com/jcmoraisjr/haproxy-ingress/pull/1297) (jcmoraisjr)
* fix xfp header on fronting proxy shared port [#1310](https://github.com/jcmoraisjr/haproxy-ingress/pull/1310) (jcmoraisjr)
* update go from 1.23.11 to 1.23.12 [5327d7d](https://github.com/jcmoraisjr/haproxy-ingress/commit/5327d7d8c50fb6b97249cb77766c4aff89ecec43) (Joao Morais)
* update haproxy from 2.4.29 to 2.4.30 [01ef489](https://github.com/jcmoraisjr/haproxy-ingress/commit/01ef489966f7488b5dff42114699b070fa547b45) (Joao Morais)

# v0.13.18

## Reference (r18)

* Release date: `2025-07-29`
* Helm chart: `--version 0.13.18`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.18`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.13.18`
* Embedded HAProxy version: `2.4.29`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.18`

## Release notes (r18)

This release updates the embedded haproxy version, dependencies, and fixes a vulnerability found in the v0.13 branch.

- An user with update ingress privilege can escalate their own privilege to the controller one, by exploring the config snippet annotation if it was not disabled via `--disable-config-keywords=*` command-line option. Mitigate this vulnerability by updating controller version, or disabling config snippet.

Dependencies:

- embedded haproxy from 2.4.28 to 2.4.29
- go from 1.23.7 to 1.23.11

## Fixes and improvements (r18)

Fixes and improvements since `v0.13.17`:

* block attempt to read cluster credentials [#1273](https://github.com/jcmoraisjr/haproxy-ingress/pull/1273) (jcmoraisjr)
* update embedded haproxy from 2.4.28 to 2.4.29 [7420ded](https://github.com/jcmoraisjr/haproxy-ingress/commit/7420deda97eda8b01a560b7dc756da3e75215e8a) (Joao Morais)
* update go from 1.23.7 to 1.23.11 [a8b369b](https://github.com/jcmoraisjr/haproxy-ingress/commit/a8b369b37462963bc41e3d95b84ee59492cf6cf3) (Joao Morais)
* update dependencies [1357b6b](https://github.com/jcmoraisjr/haproxy-ingress/commit/1357b6b15137ea8b5fafc20b575715b572eb1b76) (Joao Morais)

# v0.13.17

## Reference (r17)

* Release date: `2025-03-18`
* Helm chart: `--version 0.13.17`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.17`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.13.17`
* Embedded HAProxy version: `2.4.28`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.17`

## Release notes (r17)

This release updates the embedded haproxy version, and fixes vulnerable components found in the v0.13 branch.

Dependencies:

- embedded haproxy from 2.4.26 to 2.4.28
- go from 1.18.10 to 1.23.7, having `//go:debug default=go1.18` for backward compatibility

## Fixes and improvements (r17)

Fixes and improvements since `v0.13.16`:

* update embedded haproxy from 2.4.26 to 2.4.28 [873035d](https://github.com/jcmoraisjr/haproxy-ingress/commit/873035d521cac050f88141348f35a7efa2c6eb23) (Joao Morais)
* update go from 1.18.10 to 1.22.12 [ad83fed](https://github.com/jcmoraisjr/haproxy-ingress/commit/ad83fed49661f1ac2a9d7578c58dd500a3d67edb) (Joao Morais)
* bump vulnerable components [9b0536a](https://github.com/jcmoraisjr/haproxy-ingress/commit/9b0536ac12da17ad0f5ee29dae31f5dc246f4cb3) (Joao Morais)
* update go from 1.22.12 to 1.23.7 [8053abe](https://github.com/jcmoraisjr/haproxy-ingress/commit/8053abeeac276d860096e3b000d575a2efd1cbf6) (Joao Morais)

# v0.13.16

## Reference (r16)

* Release date: `2024-06-16`
* Helm chart: `--version 0.13.16`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.16`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.13.16`
* Embedded HAProxy version: `2.4.26`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.16`

## Release notes (r16)

This release updates the embedded haproxy version, and fixes some issues found in the v0.13 branch:

- Julien fixed the Vary response header, from Cors, when the backend server returns two or more headers
- Secure backend configuration, like backend protocol and client side mTLS, can now be configured globally for all ingress resources
- Make sure https redirect happens before path redirect when `app-root` is configured
- Auth external configuration can now be configured globally

Dependencies:

- embedded haproxy from 2.4.25 to 2.4.26
- go from 1.17.13 to 1.18.10

## Fixes and improvements (r16)

Fixes and improvements since `v0.13.15`:

* Keep all vary header values when adding Origin [#1083](https://github.com/jcmoraisjr/haproxy-ingress/pull/1083) (Jul13nT)
* Ensure https redirect happens before root redirect [#1117](https://github.com/jcmoraisjr/haproxy-ingress/pull/1117) (jcmoraisjr)
* Allows secure backend configuration from global [#1119](https://github.com/jcmoraisjr/haproxy-ingress/pull/1119) (jcmoraisjr)
* doc: add haproxy logging to stdout [#1138](https://github.com/jcmoraisjr/haproxy-ingress/pull/1138) (jcmoraisjr)
* update embedded haproxy from 2.4.25 to 2.4.26 [2fc8be1](https://github.com/jcmoraisjr/haproxy-ingress/commit/2fc8be138f229b81dbaf699c3ac75c547639d4a6) (Joao Morais)
* Allows to configure auth-url globally [#1120](https://github.com/jcmoraisjr/haproxy-ingress/pull/1120) (jcmoraisjr)
* update dependencies due to cve [710b0e7](https://github.com/jcmoraisjr/haproxy-ingress/commit/710b0e75265503b404b4452bf77f6af0d2df7a4b) (Joao Morais)
* update go from 1.17.13 to 1.18.10 as a x/net dependency [07ce388](https://github.com/jcmoraisjr/haproxy-ingress/commit/07ce38838f43c39fb9d3e94e999f282f9defdd62) (Joao Morais)

Chart improvements since `v0.13.15`:

* Fix install output message [#81](https://github.com/haproxy-ingress/charts/pull/81) (jcmoraisjr)

# v0.13.15

## Reference (r15)

* Release date: `2024-01-24`
* Helm chart: `--version 0.13.15`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.15`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.15`
* Embedded HAProxy version: `2.4.25`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.15`

## Release notes (r15)

This is a security release that updates the embedded HAProxy, the Alpine base image, and cryptographic related dependencies.

Dependencies:

- embedded haproxy from 2.4.24 to 2.4.25

## Fixes and improvements (r15)

Fixes and improvements since `v0.13.14`:

* update embedded haproxy from 2.4.24 to 2.4.25 [96e06f1](https://github.com/jcmoraisjr/haproxy-ingress/commit/96e06f13ca3b726fea5fb43ffb7556c3bd6bf24f) (Joao Morais)
* update dependencies [5ecf169](https://github.com/jcmoraisjr/haproxy-ingress/commit/5ecf169db703af2cc7972cebcf75926e8aa471d7) (Joao Morais)

# v0.13.14

## Reference (r14)

* Release date: `2023-09-01`
* Helm chart: `--version 0.13.14`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.14`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.14`
* Embedded HAProxy version: `2.4.24`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.14`

## Release notes (r14)

This release updates embedded HAProxy, which fixes some major issues regarding header parsing. See the full HAProxy changelog: https://www.mail-archive.com/haproxy@formilux.org/msg43901.html

Dependencies:

- embedded haproxy from 2.4.23 to 2.4.24

## Fixes and improvements (r14)

Fixes and improvements since `v0.13.13`:

* Bump haproxy 2.4.24 [#1021](https://github.com/jcmoraisjr/haproxy-ingress/pull/1021) (mrueg)

# v0.13.13

## Reference (r13)

* Release date: `2023-07-07`
* Helm chart: `--version 0.13.13`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.13`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.13`
* Embedded HAProxy version: `2.4.23`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.13`

## Release notes (r13)

This release fixes some issues found in the v0.13 branch:

- An endless redirect might happen when configuring redirects on domains whose TLS secret declares two or more domains
- A wildcard was not being accepted by the CORS Allowed Header configuration
- Unused HAProxy backends might leak in the configuration, depending on how the configuration is changed, when backend sharding is enabled
- Configuration snippet was missing on backends in TCP mode
- ConfigMap based TCP services were making HAProxy to reload without need, depending on the order that service endpoints were being listed

Dependencies:

- embedded haproxy from 2.4.22 to 2.4.23

## Fixes and improvements (r13)

Fixes and improvements since `v0.13.12`:

* Create endpoints on a predictable order [#1011](https://github.com/jcmoraisjr/haproxy-ingress/pull/1011) (jcmoraisjr)
* Redirect hosts only to domains with associated backends [#1010](https://github.com/jcmoraisjr/haproxy-ingress/pull/1010) (jcmoraisjr)
* Fix shard render when the last backend is removed [#1015](https://github.com/jcmoraisjr/haproxy-ingress/pull/1015) (jcmoraisjr)
* Add wildcard as a valid cors allowed header [#1016](https://github.com/jcmoraisjr/haproxy-ingress/pull/1016) (jcmoraisjr)
* update embedded haproxy from 2.4.22 to 2.4.23 [0d5826d](https://github.com/jcmoraisjr/haproxy-ingress/commit/0d5826d51a91395f1087c7d9058809434d94e8d0) (Joao Morais)
* fix: config-backend annotation also for TCP-Backends [#1009](https://github.com/jcmoraisjr/haproxy-ingress/pull/1009) (genofire)

Chart improvements since `v0.13.12`:

* Add lifecycle hooks to external HAProxy container [#72](https://github.com/haproxy-ingress/charts/pull/72) (bootc)
* chore: update HorizontalPodAutoscaler apiVersion [#71](https://github.com/haproxy-ingress/charts/pull/71) (quarckster)
* add conditional PodDisruptionBudget [#73](https://github.com/haproxy-ingress/charts/pull/73) (jcmoraisjr)

# v0.13.12

## Reference (r12)

* Release date: `2023-06-05`
* Helm chart: `--version 0.13.12`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.12`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.12`
* Embedded HAProxy version: `2.4.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.12`

## Release notes (r12)

This release fixes some issues found in the v0.13 branch:

- External HAProxy was failing with the message "cannot open the file '/var/lib/haproxy/crt/default-fake-certificate.pem'.". This happened due to missing permission to read certificate and private key files when HAProxy container starts as non root, which is the default since HAProxy 2.4.
- ConfigMap based TCP services was randomly missing when the controller started, being reincluded only after the first reconciliation.

Other notable changes include:

- An update to the External HAProxy example page adds options to fix permission failures to bind ports `:80` and `:443`, see the [example page](https://haproxy-ingress.github.io/v0.13/docs/examples/external-haproxy/#a-word-about-security).

Dependencies:

- Update client-go from v0.23.16 to v0.23.17

## Fixes and improvements (r12)

Fixes and improvements since `v0.13.11`:

* Fixes configmap based tcp sync [#1001](https://github.com/jcmoraisjr/haproxy-ingress/pull/1001) (jcmoraisjr)
* Ensure predictable tcp by sorting endpoints [#1003](https://github.com/jcmoraisjr/haproxy-ingress/pull/1003) (jcmoraisjr)
* Change owner of crt/key files to haproxy pid [#1004](https://github.com/jcmoraisjr/haproxy-ingress/pull/1004) (jcmoraisjr)
* update client-go from v0.23.16 to v0.23.17 [2f3abbb](https://github.com/jcmoraisjr/haproxy-ingress/commit/2f3abbb60f7008fd28600fd0f69b348fa10a4619) (Joao Morais)
* add security considerations on external haproxy [d21dc67](https://github.com/jcmoraisjr/haproxy-ingress/commit/d21dc6730f579bb0713a6f0600cca4d51c80bb38) (Joao Morais)

# v0.13.11

## Reference (r11)

* Release date: `2023-02-18`
* Helm chart: `--version 0.13.11`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.11`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.11`
* Embedded HAProxy version: `2.4.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.11`

## Release notes (r11)

This release fixes CVE-2023-25725 on HAProxy. See HAProxy's release notes regarding the issue and a possible work around: https://www.mail-archive.com/haproxy@formilux.org/msg43229.html

Note also that HAProxy Ingress v0.13 used to follow HAProxy 2.3 branch, which is already deprecated. This release also changes HAProxy branch from 2.3 to 2.4. HAProxy has a good history of preserving backward compatibility and, while we prefer to stick on a single branch of our main dependencies, we cannot ignore a known vulnerability.

Dependencies:

- Embedded HAProxy version was updated from 2.3.21 to 2.4.22.

## Fixes and improvements (r11)

New features and improvements since `v0.13.10`:

* update dependencies [ae47b5a](https://github.com/jcmoraisjr/haproxy-ingress/commit/ae47b5a22f722dae0e5a107a3a367ffe100f2bd9) (Joao Morais)
* update haproxy from 2.3.21 to 2.4.22 [f3c8850](https://github.com/jcmoraisjr/haproxy-ingress/commit/f3c88507de1b54ff6edd432344db6077499c77b2) (Joao Morais)

# v0.13.10

## Reference (r10)

* Release date: `2023-02-10`
* Helm chart: `--version 0.13.10`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.10`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.10`
* Embedded HAProxy version: `2.3.21`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.10`

## Release notes (r10)

Warning: due to the update of some old dependencies with vulnerability, the Go version used to compile this release was updated from 1.16 to 1.17, and client-go was updated from v0.20 to v0.23.

This release fixes the following issues:

- Service resources accept annotations just like ingress ones. However services annotated with path scoped annotations, like `haproxy-ingress.github.io/cors-enable` and `haproxy-ingress.github.io/auth-url`, were applying the configuration to just one of the paths pointing the service. So, considering `domain.local/path1` and `domain.local/path2` pointing to `svc1`, an annotation added to `svc1` would only be applied to one of the paths.
- A wrong named port configured on the external auth was being silently ignored. This update adds this information in the documentation and also adds a warning in the log. See auth external [documentation](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#auth-external).

Other notable changes include:

- Services of type External Name can now be configured without a port number. If the port is missing in the service, the port number declared in the ingress resource is used.
- Andrej Baran made `load-server-state` to work on HAProxy deployed as an external container.
- Some redirect configuration keys have the ability to send a request to another domain or path. This was happening with ACME validation as well. Now a redirect will only be effective if the request isn't an ACME validation.
- Auth headers, from the auth external configuration keys, used to break the configuration when declared empty. Now an empty value disables the copy of the HTTP headers.

Dependencies:

- Go updated from 1.16.15 to 1.17.13.
- Client-go updated from v0.20.15 to v0.23.16.

## Fixes and improvements (r10)

New features and improvements since `v0.13.9`:

* Add support for service external name without port [#946](https://github.com/jcmoraisjr/haproxy-ingress/pull/946) (jcmoraisjr)
* Enable Load Server State feature for external haproxy [#957](https://github.com/jcmoraisjr/haproxy-ingress/pull/957) (andrejbaran)
* Fix host redirects when acme is enabled [#971](https://github.com/jcmoraisjr/haproxy-ingress/pull/971) (jcmoraisjr)
* Makes auth-headers not copying on empty string [#972](https://github.com/jcmoraisjr/haproxy-ingress/pull/972) (jcmoraisjr)
* Fix path scoped annotation on service resources [#984](https://github.com/jcmoraisjr/haproxy-ingress/pull/984) (jcmoraisjr)
* Add warning if auth external svc isnt found [#982](https://github.com/jcmoraisjr/haproxy-ingress/pull/982) (jcmoraisjr)
* update go from 1.16.15 to 1.17.13 and dependencies [3319f97](https://github.com/jcmoraisjr/haproxy-ingress/commit/3319f97e67fa3d5b8871193b3234cb77e4e6cff8) (Joao Morais)

# v0.13.9

## Reference (r9)

* Release date: `2022-08-07`
* Helm chart: `--version 0.13.9`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.9`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.9`
* Embedded HAProxy version: `2.3.21`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.9`

## Release notes (r9)

This release updates dependencies with known vulnerabilities in the operating system packages, and also in the code dependencies.

Dependencies:

- Embedded HAProxy version was updated from 2.3.20 to 2.3.21. Although already unmaintained, the HAProxy team tagged a new version, and now it should really be the last one.
- Golang was updated from 1.15 branch to 1.16, in order to fix some known vulnerabilities.
- Several OS packages and golang dependencies were updated, including but not limited to pcre and libssl.

## Fixes and improvements (r9)

* Add apk upgrade on container building [#941](https://github.com/jcmoraisjr/haproxy-ingress/pull/941) (jcmoraisjr)
* update dependencies [6e9c709](https://github.com/jcmoraisjr/haproxy-ingress/commit/6e9c70949f248cd9e44b3c20754e5a01f36317cc) (Joao Morais)
* update embedded haproxy from 2.3.20 to 2.3.21 [617e123](https://github.com/jcmoraisjr/haproxy-ingress/commit/617e1239340769423ec366bbef9bd4fc1232871a) (Joao Morais)
* Documents the expected format for --configmap key [#940](https://github.com/jcmoraisjr/haproxy-ingress/pull/940) (lafolle)
* update golang from 1.15.15 to 1.16.15 [285ffb9](https://github.com/jcmoraisjr/haproxy-ingress/commit/285ffb9c85f0e3ca1c28dc6450c2c3e43a0de402) (Joao Morais)

# v0.13.8

## Reference (r8)

* Release date: `2022-07-03`
* Helm chart: `--version 0.13.8`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.8`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.8`
* Embedded HAProxy version: `2.3.20`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.8`

## Release notes (r8)

This release fixes the following issues:

- A possible typecast failure reported by monkeymorgan was fixed, which could happen on outages of the apiserver and some resources are removed from the api before the controller starts to watch the api again.
- A lock was added before checking for expiring certificates when the embedded acme client is configured. This lock prevents the check routine to read the internal model while another thread is modifying it to apply a configuration change.
- The external HAProxy now starts without a readiness endpoint configured. This avoids adding a just deployed controller as available before it has been properly configured. Starting liveness was raised in the helm chart, so that huge environments have time enough to start.

Other notable changes include:

- Metrics example now uses Prometheus Operator and the service monitor provided by the helm chart.

Dependencies:

- Embedded HAProxy version was updated from 2.3.19 to 2.3.20. This is the latest HAProxy change, 2.3 branch is now considered unmaintained.

## Fixes and improvements (r8)

* Change metrics example to use servicemonitor [#919](https://github.com/jcmoraisjr/haproxy-ingress/pull/919) (jcmoraisjr)
* Check type assertion on all informers [#934](https://github.com/jcmoraisjr/haproxy-ingress/pull/934) (jcmoraisjr)
* Add lock before call acmeCheck() [#935](https://github.com/jcmoraisjr/haproxy-ingress/pull/935) (jcmoraisjr)
* Remove readiness endpoint from starting config [#937](https://github.com/jcmoraisjr/haproxy-ingress/pull/937) (jcmoraisjr)
* update embedded haproxy from 2.3.19 to 2.3.20 [d435c7c](https://github.com/jcmoraisjr/haproxy-ingress/commit/d435c7c0ef0fed034cfea93b0e13bbef6dcfd7cb) (Joao Morais)

# v0.13.7

## Reference (r7)

* Release date: `2022-03-26`
* Helm chart: `--version 0.13.7`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.7`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.7`
* Embedded HAProxy version: `2.3.19`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.7`

## Release notes (r7)

This release fixes the match of the Prefix path type when the host is not declared (default host) and the pattern is a single slash. The configured service was not being selected if the incoming path doesn't finish with a slash.

Other notable changes include:

- Add compatibility with HAProxy 2.5 deployed as external/sidecar. Version 2.5 changed the lay out of the `show proc` command of the master API.
- Embedded HAProxy version was updated from 2.3.17 to 2.3.19.

## Fixes and improvements (r7)

* Upgrade crypto dependency [#895](https://github.com/jcmoraisjr/haproxy-ingress/pull/895) (rgherta)
* docs: include tuning of free backend slots in performance suggestions [#891](https://github.com/jcmoraisjr/haproxy-ingress/pull/891) (ssanders1449)
* Add haproxy 2.5 support for external haproxy [#905](https://github.com/jcmoraisjr/haproxy-ingress/pull/905) (jcmoraisjr)
* Fix match of prefix pathtype if using default host [#908](https://github.com/jcmoraisjr/haproxy-ingress/pull/908) (jcmoraisjr)
* Remove initial whitespaces from haproxy template [#910](https://github.com/jcmoraisjr/haproxy-ingress/pull/910) (ironashram)
* update embedded haproxy from 2.3.17 to 2.3.19 [5b99b0c](https://github.com/jcmoraisjr/haproxy-ingress/commit/5b99b0c2f3e44fb704d1d2ce461a334ac6076cea) (Joao Morais)

# v0.13.6

## Reference (r6)

* Release date: `2022-01-22`
* Helm chart: `--version 0.13.6`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.6`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.6`
* Embedded HAProxy version: `2.3.17`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.6`

## Release notes (r6)

This release fixes the following issues:

- Backend configuration snippets with blank lines were being rejected due to a wrong parsing of a missing `--disable-config-keywords` command-line option.
- Annotation based TCP services were incorrectly fetching the SNI extension of an encrypted connection that's deciphered by HAProxy. `req.ssl_sni` was being used instead of `ssl_fc_sni`.

Besides that, a few other improvements were made:

- All `var()` sample fetch now have the `-m str` match method. This fixes compatibility with HAProxy 2.5, which now enforces a match method when using `var()`. This however isn't enough to use HAProxy 2.5 as an external HAProxy due to incompatibility changes made in the master socket responses, hence the update in the [supported HAProxy versions](https://github.com/jcmoraisjr/haproxy-ingress/#use-haproxy-ingress). A future HAProxy Ingress release will make v0.12 and v0.13 branches compatible with HAProxy 2.5.
- A new configuration key `session-cookie-domain` was added due to how modern browsers parses the `domain` cookie attribute. Prefer to use this new configuration key instead of `session-cookie-shared`. Further information can be found in the [affinity documentation](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#affinity).
- Embedded HAProxy was updated from 2.3.16 to 2.3.17.
- client-go was updated from v0.20.14 to v0.20.15.

## Fixes and improvements (r6)

* Add disableKeywords only if defined [#876](https://github.com/jcmoraisjr/haproxy-ingress/pull/876) (jcmoraisjr)
* Add match method on all var() sample fetch method [#879](https://github.com/jcmoraisjr/haproxy-ingress/pull/879) (jcmoraisjr)
* Fix sni sample fetch on ssl deciphered tcp conns [#884](https://github.com/jcmoraisjr/haproxy-ingress/pull/884) (jcmoraisjr)
* Add session-cookie-domain configuration key [#889](https://github.com/jcmoraisjr/haproxy-ingress/pull/889) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#affinity)
  * Configuration keys:
    * `session-cookie-domain`
* update embedded haproxy from 2.3.16 to 2.3.17 [7ff2708](https://github.com/jcmoraisjr/haproxy-ingress/commit/7ff2708621d4535e007912f07e790e1cffe83ddc) (Joao Morais)
* update client-go from v0.20.14 to v0.20.15 [d16ba3e](https://github.com/jcmoraisjr/haproxy-ingress/commit/d16ba3e5d29c54acb7f3aba5d9279d8b5cc46789) (Joao Morais)

# v0.13.5

## Reference (r5)

* Release date: `2021-12-25`
* Helm chart: `--version 0.13.5`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.5`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.5`
* Embedded HAProxy version: `2.3.16`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.5`

## Release notes (r5)

This release fixes the following issues:

- An error message was missing in the controller doesn't have permission to update a secret. The update is needed when the embedded acme signer is used. Before this update, a missing permission would fail the update of the secret without notifying the failure in the logs.
- Michał Zielonka fixed the overwrite of the Vary header when Cors is used with two or more Allow Origin.

There is also a number of new features and improvements:

- Mateusz Kubaczyk added an option to allow change the precedence from class annotation to IngressClass resource when both are used to classify an ingress resource.
- Added a configuration that allows to change the default certificate chain issued by Let's Encrypt. The old behavior and currently the default option builds a bundle whose the topmost certificate is issued by `DST X3`, which will fail if the client has `DST X3` on its trust store and uses openssl 1.0.x. See the [Let's Encrypt documentation](https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/) about the `DST X3` expiration.
- Full Gateway API implementation was rescheduled to v0.15 (Q2'22), while v0.14 will be updated to support v1alpha2 version with similar limitations of v0.13. See the [Gateway API documentation](https://haproxy-ingress.github.io/v0.13/docs/configuration/gateway-api/).
- New target platforms: `arm/v7`, `arm/v6` and `s390x`, all of them for Linux.
- Embedded HAProxy was updated to 2.3.16.
- client-go was updated to v0.20.14.

## Fixes and improvements (r5)

Fixes and improvements since `v0.13.4`:

* Add --ingress-class-precedence to allow IngressClass taking precedence over annotation [#857](https://github.com/jcmoraisjr/haproxy-ingress/pull/857) (mkubaczyk) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/command-line/#ingress-class)
  * Command-line options:
    * `--ingress-class-precedence`
* Fix error message on secret/cm update failure [#863](https://github.com/jcmoraisjr/haproxy-ingress/pull/863) (jcmoraisjr)
* Add acme-preferred-chain config key [#864](https://github.com/jcmoraisjr/haproxy-ingress/pull/864) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#acme)
  * Configuration keys:
    * `acme-preferred-chain`
* Remove setting vary origin header always when multiple origins are set [#861](https://github.com/jcmoraisjr/haproxy-ingress/pull/861) (michal800106)
* docs: rescheduling gateway api implementation [ebfe0a2](https://github.com/jcmoraisjr/haproxy-ingress/commit/ebfe0a234bacd4554b2d8d9114fa922d2277fae0) (Joao Morais)
* Add new target platforms [#870](https://github.com/jcmoraisjr/haproxy-ingress/pull/870) (jcmoraisjr)
* update embedded haproxy from 2.3.14 to 2.3.16 [d996e22](https://github.com/jcmoraisjr/haproxy-ingress/commit/d996e223139b93db76fb51341f9400b86aae4ac2) (Joao Morais)
* update client-go from v0.20.10 to v0.20.14 [4b61fb8](https://github.com/jcmoraisjr/haproxy-ingress/commit/4b61fb8312191d1b5f831a16bba751ee31c333bf) (Joao Morais)

# v0.13.4

## Reference (r4)

* Release date: `2021-09-16`
* Helm chart: `--version 0.13.4`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.4`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.4`
* Embedded HAProxy version: `2.3.14`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.4`

## Release notes (r4)

This release fixes the following issues:

- a regression introduced in [#820](https://github.com/jcmoraisjr/haproxy-ingress/pull/820): a globally configured config-backend snippet wasn't being applied in the final configuration. Annotation based snippets weren't impacted;
- the event loop of the configuration parser was being blocked by certificate updates due to the missing of sending an end-of-command to the haproxy client socket, and also the missing of a read/write timeout.

## Fixes and improvements (r4)

Fixes and improvements since `v0.13.3`:

* Fix set ssl cert end-of-command [#828](https://github.com/jcmoraisjr/haproxy-ingress/pull/828) (jcmoraisjr)
* Add read and write timeout to the unix socket [#855](https://github.com/jcmoraisjr/haproxy-ingress/pull/855) (jcmoraisjr)
* Fix global config-backend snippet config [#856](https://github.com/jcmoraisjr/haproxy-ingress/pull/856) (jcmoraisjr)

# v0.13.3

## Reference (r3)

* Release date: `2021-09-08`
* Helm chart: `--version 0.13.3`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.3`
* Embedded HAProxy version: `2.3.14`

## Release notes (r3)

This release updates the embedded HAProxy version from `2.3.13` to `2.3.14`, which fixes a HAProxy's vulnerability with the Content-Length HTTP header. CVE-2021-40346 was assigned. The following announce from the HAProxy's mailing list has the details and possible workaround: https://www.mail-archive.com/haproxy@formilux.org/msg41114.html

## Fixes and improvements (r3)

Fixes and improvements since `v0.13.2`:

* update embedded haproxy from 2.3.13 to 2.3.14 [25caf65](https://github.com/jcmoraisjr/haproxy-ingress/commit/25caf65c35e21c5eceae40a30d66a6d62434ae8e) (Joao Morais)

# v0.13.2

## Reference (r2)

* Release date: `2021-09-05`
* Helm chart: `--version 0.13.2`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.2`
* Embedded HAProxy version: `2.3.13`

## Release notes (r2)

This release fixes a couple of issues found in the v0.13 branch:

* An ingress resource configuration could not be applied if an ingress resource starts to reference a service that was already being referenced by another ingress;
* An invalid configuration could be generated, preventing haproxy to reload, if an invalid oauth or auth external configuration is added (e.g. missing service name) to a fraction of the paths of a backend;
* Updates to endpoints of a ConfigMap based TCP service wasn't being updated to the haproxy listener;
* Maël Valais fixed Gateway API's certificateRef configuration - v1alpha1 requires the group field but HAProxy Ingress was refusing "core" as its content. The merge was done to master before v0.13.0 tag, but the merge to v0.13 branch was missing.

Also, Wojciech Chojnowski added a new configuration key that allows to use the value of a HTTP header as the source address used by allow and deny lists, making it possible to properly configure source headers when HAProxy is behind a reverse proxy.

## Fixes and improvements (r2)

Fixes and improvements since `v0.13.1`:

* Fix endpoint update of configmap based tcp services [#842](https://github.com/jcmoraisjr/haproxy-ingress/pull/842) (jcmoraisjr)
* Fix config parsing on misconfigured auth external [#844](https://github.com/jcmoraisjr/haproxy-ingress/pull/844) (jcmoraisjr)
* Fix validation if ca is used with crt and key [#845](https://github.com/jcmoraisjr/haproxy-ingress/pull/845) (jcmoraisjr)
* Fix ingress update to an existing backend [#847](https://github.com/jcmoraisjr/haproxy-ingress/pull/847) (jcmoraisjr)
* Feature/allowlist behind reverse proxy [#846](https://github.com/jcmoraisjr/haproxy-ingress/pull/846) (DCkQ6) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#allowlist)
  * Configuration keys:
    * `allowlist-source-header`
* Gateway API: when using v1alpha1, certificateRef.group now accepts "core" [#833](https://github.com/jcmoraisjr/haproxy-ingress/pull/833) (maelvls)

## Other

* docs: add modsec resource limits to controls V2 memory consumption [#841](https://github.com/jcmoraisjr/haproxy-ingress/pull/841) (sealneaward)

# v0.13.1

## Reference (r1)

* Release date: `2021-08-17`
* Helm chart: `--version 0.13.1`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.1`
* Embedded HAProxy version: `2.3.13`

## Release notes (r1)

This release updates the embedded HAProxy version from `2.3.12` to `2.3.13`, which fixes some HAProxy's HTTP/2 vulnerabilities. A malicious request can abuse the H2 `:method` pseudo-header to forge malformed HTTP/1 requests, which can be accepted by some vulnerable backend servers. The following announce from the HAProxy's mailing list has the details: https://www.mail-archive.com/haproxy@formilux.org/msg41041.html

## Fixes and improvements (r1)

Fixes and improvements since `v0.13.0`:

* update embedded haproxy from 2.3.12 to 2.3.13 [744445b](https://github.com/jcmoraisjr/haproxy-ingress/commit/744445b4db17000986f9b46d4d769cbe1e6e7302) (Joao Morais)

# v0.13.0

## Reference (r0)

* Release date: `2021-08-13`
* Helm chart: `--version 0.13.0`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.0`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.0`
* Embedded HAProxy version: `2.3.12`

## Release notes (r0)

This is the first v0.13 release graduated as GA. The following fixes have been made since the last beta version:

- A failure in the synchronization between the in memory HAProxy model and the state of the running HAProxy instance was fixed. The internal model reflects how HAProxy should be configured based on ingress resources. The states can be out of sync when new empty slots are added to backends that weren't in edit state, and only affects sharded backends (`--backend-shards` > 0).
- Dynamic server certificate update was fixed. A HAProxy reload was always being scheduled due to an unrelated change in the internal model

Other notable changes are:

- Images for arm64 will be generated for v0.13 and newer versions
- A FAQ section was added in the documentation
- Neil made some improvements to the ModSecurity example
- Golang was updated to a new patch (still 1.15 branch) and also client-go library (still v0.20 branch)

## Fixes and improvements (r0)

Fixes and improvements since `v0.13.0-beta.2`:

* docs: add section for AuditLog sidecar for ModSecurity daemonset [#825](https://github.com/jcmoraisjr/haproxy-ingress/pull/825) (sealneaward)
* Fix dynamic update of frontend crt [#829](https://github.com/jcmoraisjr/haproxy-ingress/pull/829) (jcmoraisjr)
* Fix change notification of backend shard [#835](https://github.com/jcmoraisjr/haproxy-ingress/pull/835) (jcmoraisjr)
* docs: changing NodeSelector to ClusterIP service for ModSecurity [#826](https://github.com/jcmoraisjr/haproxy-ingress/pull/826) (sealneaward)
* Add arm64 build [#836](https://github.com/jcmoraisjr/haproxy-ingress/pull/836) (jcmoraisjr)
* docs: add a faq [#837](https://github.com/jcmoraisjr/haproxy-ingress/pull/837) (jcmoraisjr)
* update golang from 1.15.13 to 1.15.15 [72282c6](https://github.com/jcmoraisjr/haproxy-ingress/commit/72282c6f89c2ff48ee19e8f75e26ade4670cb284) (Joao Morais)
* update client-go from v0.20.8 to v0.20.10 [0127cdd](https://github.com/jcmoraisjr/haproxy-ingress/commit/0127cddddac6a2579f98606c8df91df4d80f94b7) (Joao Morais)

# v0.13.0-beta.2

## Reference (b2)

* Release date: `2021-07-11`
* Helm chart: `--version 0.13.0-beta.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.0-beta.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.0-beta.2`
* Embedded HAProxy version: `2.3.12`

## Release notes (b2)

The number of changes is unusual for a beta quality update. Some of the new features were missed when the first beta was tagged, and some of them updated the upgrade notes / backward compatibility changes:

* The default number of threads isn’t 2 anymore. If not provided, HAProxy will configure it based on the number of CPUs it is allowed to use and this should happen on platforms that support CPU affinity. Deployments that configure nbthread will not be affected.
* A missing ConfigMap configured in the command-line option `--configmap` will now crash the controller. This misconfiguration used to be ignored. v0.12 and older will warn without crashing.

Other notable changes are:

* Improvement of the synchronization between the HAProxy state and the in-memory model that reflects that state. The controller used to trust that a state change sent to the admin socket is properly applied. Now every HAProxy response is parsed and the controller will enforce a reload if it doesn’t recognize the change as a valid one.
* auth-url was incorrectly parsing an URL whose domain doesn’t have a dot, depending on the number of paths. This is a common scenario when a Kubernetes’ service name is used as a domain name. Besides that, a misconfigured oauth or external authentication were ignoring the configuration, leading the backend without the authentication. Now the attempt to configure oauth or auth external will deny requests to the backend in the case of a misconfiguration.
* An invalid configuration file could be built if all the parsed ingress resources don’t configure a hostname.
* Andrew Rodland added `assign-backend-server-id` configuration key that assigns predictable IDs to backend servers, improving hash based balance algorithms to properly work if the list of servers is partially changed.
* A new command-line option `—reload-interval` adds the ability to distinguish between the frequency that the controller parses configuration changes and tries to apply dynamically, and the frequency that HAProxy should be reloaded. The former should be as fast as possible, the later, depending on the frequency, could lead to a high memory consumption depending on the long running connections timeout, like websockets.
* Two new security options were added: `--disable-external-name` can be used to not allow backend server discovery using an external domain, and `--disable-config-keywords` can be used to partially or completely disable configuration snippets via ingress or service annotations.
* The `auth-request.lua` script, used by oauth and external authentication, was updated to the official version from Tim’s repository. We were using a customized version due to the new external authentication options, waiting for the contributions to get merged to the main line. There were no visible changes in the functionality.
* Paul improved the command-line documentation, adding some undocumented options that the controller supports.

## Improvements (b2)

New features and improvements since `v0.13.0-beta.1`:

* Stable IDs for consistent-hash load balancing [#801](https://github.com/jcmoraisjr/haproxy-ingress/pull/801) (arodland) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#backend-server-id)
  * Configuration keys:
    * `assign-backend-server-id`
* Ensure that configured global ConfigMap exists [#804](https://github.com/jcmoraisjr/haproxy-ingress/pull/804) (jcmoraisjr)
* Update auth-request.lua script [#809](https://github.com/jcmoraisjr/haproxy-ingress/pull/809) (jcmoraisjr)
* Add log of reload error on every reconciliation [#811](https://github.com/jcmoraisjr/haproxy-ingress/pull/811) (jcmoraisjr)
* Add reload interval command-line option [#815](https://github.com/jcmoraisjr/haproxy-ingress/pull/815) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/command-line/#reload-interval)
  * Command-line options:
    * `--reload-interval`
* Add disable-external-name command-line option [#816](https://github.com/jcmoraisjr/haproxy-ingress/pull/816) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/command-line/#disable-external-name)
  * Command-line options:
    * `--disable-external-name`
* Add disable-config-keywords command-line options [#820](https://github.com/jcmoraisjr/haproxy-ingress/pull/820) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/command-line/#disable-config-keywords)
  * Command-line options:
    * `--disable-config-keywords`
* Updates to the help output of command-line options [#814](https://github.com/jcmoraisjr/haproxy-ingress/pull/814) (jcmoraisjr)
* Change nbthread to use all CPUs by default [#821](https://github.com/jcmoraisjr/haproxy-ingress/pull/821) (jcmoraisjr)
* update client-go from 0.20.7 to 0.20.8 [136026a](https://github.com/jcmoraisjr/haproxy-ingress/commit/136026a1d6c1558d4474a4286d1400fe8791a858) (Joao Morais)
* update embedded haproxy from 2.3.10 to 2.3.12 [38c0499](https://github.com/jcmoraisjr/haproxy-ingress/commit/38c04993293718147162f9ae342775e082ecad1c) (Joao Morais)

## Fixes (b2)

* Fix backend match if no ingress use host match [#802](https://github.com/jcmoraisjr/haproxy-ingress/pull/802) (jcmoraisjr)
* Reload haproxy if a backend server cannot be found [#810](https://github.com/jcmoraisjr/haproxy-ingress/pull/810) (jcmoraisjr)
* Fix auth-url parsing if hostname misses a dot [#818](https://github.com/jcmoraisjr/haproxy-ingress/pull/818) (jcmoraisjr)
* Always deny requests of failed auth configurations [#819](https://github.com/jcmoraisjr/haproxy-ingress/pull/819) (jcmoraisjr)

## Other

* docs: Add all command-line options to list. [#806](https://github.com/jcmoraisjr/haproxy-ingress/pull/806) (toothbrush)
* docs: update haproxy doc link to 2.2 [032db56](https://github.com/jcmoraisjr/haproxy-ingress/commit/032db56c78cd7d9db88de58b39e238fa66b18987) (Joao Morais)
* build: remove travis-ci configs [4ac3938](https://github.com/jcmoraisjr/haproxy-ingress/commit/4ac3938d8ee7bb242d8e6db1882eb378feb47762) (Joao Morais)

# v0.13.0-beta.1

## Reference (b1)

* Release date: `2021-06-16`
* Helm chart: `--version 0.13.0-beta.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.0-beta.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.0-beta.1`
* Embedded HAProxy version: `2.3.10`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.13.0-beta.1`

## Improvements (b1)

New features and improvements since `v0.13.0-snapshot.3`:

* update golang from 1.15.12 to 1.15.13 [7f8ddbf](https://github.com/jcmoraisjr/haproxy-ingress/commit/7f8ddbfb78ac4a251a07e923ff5e50604a68d2be) (Joao Morais)

## Fixes (b1)

* Fix reading of tls secret without crt or key [#799](https://github.com/jcmoraisjr/haproxy-ingress/pull/799) (jcmoraisjr)
* Fix typo in 'tcp-service-proxy-protocol' annotation [#800](https://github.com/jcmoraisjr/haproxy-ingress/pull/800) (bartversluijs)

## Other

* build: move from travis to github actions [80059ea](https://github.com/jcmoraisjr/haproxy-ingress/commit/80059eac3c923b7b698a529d83ac3bac43814e57) (Joao Morais)

# v0.13.0-snapshot.3

## Reference (s3)

* Release date: `2021-06-09`
* Helm chart: `--version 0.13.0-snapshot.3 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.3`
* Embedded HAProxy version: `2.3.10`

## Improvements (s3)

New features and improvements since `v0.13.0-snapshot.2`:

* Add Gateway API support (part 1) [#775](https://github.com/jcmoraisjr/haproxy-ingress/pull/775) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/gateway-api/)
* Allow more than 64k outgoing conn with source addr [#784](https://github.com/jcmoraisjr/haproxy-ingress/pull/784) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#source-address-intf)
  * Configuration keys:
    * `source-address-intf`
* Add option to disable API server warnings [#789](https://github.com/jcmoraisjr/haproxy-ingress/pull/789) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/command-line/#disable-api-warnings)
  * Command-line options:
    * `--disable-api-warnings`
* Add ssl-always-add-https config key [#793](https://github.com/jcmoraisjr/haproxy-ingress/pull/793) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#ssl-always-add-https)
  * Configuration keys:
    * `ssl-always-add-https`
* Add option to copy client method to auth-url [#794](https://github.com/jcmoraisjr/haproxy-ingress/pull/794) (jcmoraisjr)
* Add dynamic update for cross namespace reading [#795](https://github.com/jcmoraisjr/haproxy-ingress/pull/795) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#cross-namespace)
  * Configuration keys:
    * `cross-namespace-secrets-ca`
    * `cross-namespace-secrets-crt`
    * `cross-namespace-secrets-passwd`
    * `cross-namespace-services`
* Allow a list of origins in cors-allow-origin config [#797](https://github.com/jcmoraisjr/haproxy-ingress/pull/797) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#cors)

## Fixes (s3)

* Fix domain validation on secure backend keys [#791](https://github.com/jcmoraisjr/haproxy-ingress/pull/791) (jcmoraisjr)
* Use the port name on DNS resolver template [#796](https://github.com/jcmoraisjr/haproxy-ingress/pull/796) (jcmoraisjr)

# v0.13.0-snapshot.2

## Reference (s2)

* Release date: `2021-05-19`
* Helm chart: `--version 0.13.0-snapshot.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.2`
* Embedded HAProxy version: `2.3.10`

## Improvements (s2)

New features and improvements since `v0.13.0-snapshot.1`:

* Add non root path support on ssl-passthrough [#767](https://github.com/jcmoraisjr/haproxy-ingress/pull/767) (jcmoraisjr)
* Allow default crt on tcp service [#766](https://github.com/jcmoraisjr/haproxy-ingress/pull/766) (jcmoraisjr)
* Allow to configure a list of annotations prefix [#769](https://github.com/jcmoraisjr/haproxy-ingress/pull/769) (jcmoraisjr)
* Add new redirect options [#776](https://github.com/jcmoraisjr/haproxy-ingress/pull/776) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#redirect)
  * Configuration keys:
    * `redirect-from`
    * `redirect-from-code`
    * `redirect-from-regex`
    * `redirect-to`
    * `redirect-to-code`
* Accept header names in auth and oauth-headers [#780](https://github.com/jcmoraisjr/haproxy-ingress/pull/780) (jcmoraisjr)
* Add the ability to use the same host+path more than once [#779](https://github.com/jcmoraisjr/haproxy-ingress/pull/779) (jcmoraisjr)
* Add option to copy headers to and from auth external [#782](https://github.com/jcmoraisjr/haproxy-ingress/pull/782) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#auth-external)
  * Configuration keys:
    * `auth-headers-fail`
    * `auth-headers-request`
    * `auth-headers-succeed`
    * `auth-method`
* Update embedded haproxy from 2.3.9 to 2.3.10 [0a76276](https://github.com/jcmoraisjr/haproxy-ingress/commit/0a762765df04780b76e4d043739ca3b4a5bd965d) (Joao Morais)
* Update golang from 1.15.11 to 1.15.12 [2dc9af0](https://github.com/jcmoraisjr/haproxy-ingress/commit/2dc9af09d690f7d83fcad2c2e0897b51ece582bd) (Joao Morais)
* Update client-go from v0.20.2 to v0.20.7 [56a9328](https://github.com/jcmoraisjr/haproxy-ingress/commit/56a9328fb8490d3cc12e3462c12062ecfc032408) (Joao Morais)

## Fixes (s2)

* Fix reading of needFullSync status [#772](https://github.com/jcmoraisjr/haproxy-ingress/pull/772) (jcmoraisjr)
* Fix path-type conflict warning [#778](https://github.com/jcmoraisjr/haproxy-ingress/pull/778) (jcmoraisjr)
* Fix per path filter of default host rules [#777](https://github.com/jcmoraisjr/haproxy-ingress/pull/777) (jcmoraisjr)

# v0.13.0-snapshot.1

## Reference (s1)

* Release date: `2021-04-16`
* Helm chart: `--version 0.13.0-snapshot.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.1`
* Embedded HAProxy version: `2.3.9`

## Improvements (s1)

New features and improvements since `v0.12-beta.1`:

* Use field converter to remove port from hdr host [#729](https://github.com/jcmoraisjr/haproxy-ingress/pull/729) (jcmoraisjr)
* Add sni and verifyhost to secure connections [#730](https://github.com/jcmoraisjr/haproxy-ingress/pull/730) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#secure-backend)
  * Configuration keys:
    * `secure-sni`
    * `secure-verify-hostname`
* Add support for native redirection of default backend [#731](https://github.com/jcmoraisjr/haproxy-ingress/pull/731) (rikatz) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#default-redirect)
  * Configuration keys:
    * `default-backend-redirect`
    * `default-backend-redirect-code`
* Update to networking.k8s.io/v1 api [#726](https://github.com/jcmoraisjr/haproxy-ingress/pull/726) (jcmoraisjr)
* Improve crt validation with ssl_c_verify [#743](https://github.com/jcmoraisjr/haproxy-ingress/pull/743) (jcmoraisjr)
* Add protocol to allow content sources other than secret [#735](https://github.com/jcmoraisjr/haproxy-ingress/pull/735) (jcmoraisjr)
* Add dynamic update of frontend's TLS certificate [#734](https://github.com/jcmoraisjr/haproxy-ingress/pull/734) (jcmoraisjr)
* Add custom-sections global option [#749](https://github.com/jcmoraisjr/haproxy-ingress/pull/749) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#configuration-snippet)
  * Configuration keys:
    * `config-sections`
* Add custom-proxy configuration [#755](https://github.com/jcmoraisjr/haproxy-ingress/pull/755) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#configuration-snippet)
  * Configuration keys:
    * `config-proxy`
* Add external authentication [#748](https://github.com/jcmoraisjr/haproxy-ingress/pull/748) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#auth-external)
  * Configuration keys:
    * `auth-headers`
    * `auth-log-format`
    * `auth-proxy`
    * `auth-signin`
    * `auth-url`
* Add custom-tcp configuration [#757](https://github.com/jcmoraisjr/haproxy-ingress/pull/757) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#configuration-snippet)
  * Configuration keys:
    * `config-tcp`
* Add server redirect options [#754](https://github.com/jcmoraisjr/haproxy-ingress/pull/754) (jcmoraisjr)
* Add ingress based TCP service option [#750](https://github.com/jcmoraisjr/haproxy-ingress/pull/750) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#tcp-services)
  * Configuration keys:
    * `config-tcp-service`
    * `tcp-service-log-format`
    * `tcp-service-port`
    * `tcp-service-proxy-protocol`

## Fixes (s1)

* Fix path precedence of distinct match types [#728](https://github.com/jcmoraisjr/haproxy-ingress/pull/728) (jcmoraisjr)
* Fix shrinking of prioritized paths [#736](https://github.com/jcmoraisjr/haproxy-ingress/pull/736) (jcmoraisjr)
* Read the whole input when the response fills the buffer [#739](https://github.com/jcmoraisjr/haproxy-ingress/pull/739) (jcmoraisjr)
* Remove unix socket before start acme server [#740](https://github.com/jcmoraisjr/haproxy-ingress/pull/740) (jcmoraisjr)
* Fix initial weight configuration [#742](https://github.com/jcmoraisjr/haproxy-ingress/pull/742) (jcmoraisjr)
* Fix incorrect reload if endpoint list grows [#746](https://github.com/jcmoraisjr/haproxy-ingress/pull/746) (jcmoraisjr)
* Fix prefix path type if the path matches a domain [#756](https://github.com/jcmoraisjr/haproxy-ingress/pull/756) (jcmoraisjr)
* Fix default host if configured as ssl-passthrough [#764](https://github.com/jcmoraisjr/haproxy-ingress/pull/764) (jcmoraisjr)

## Other

* Duplicate Travis CI to GitHub Actions [#732](https://github.com/jcmoraisjr/haproxy-ingress/pull/732) (rikatz)
