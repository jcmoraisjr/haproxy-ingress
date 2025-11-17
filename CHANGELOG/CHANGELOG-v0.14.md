# CHANGELOG v0.14 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.13!](#upgrade-notes)
* [Contributors](#contributors)
* [v0.14.10](#v01410)
  * [Reference](#reference-r10)
  * [Release notes](#release-notes-r10)
  * [Fixes and improvements](#fixes-and-improvements-r10)
* [v0.14.9](#v0149)
  * [Reference](#reference-r9)
  * [Release notes](#release-notes-r9)
  * [Fixes and improvements](#fixes-and-improvements-r9)
* [v0.14.8](#v0148)
  * [Reference](#reference-r8)
  * [Release notes](#release-notes-r8)
  * [Fixes and improvements](#fixes-and-improvements-r8)
* [v0.14.7](#v0147)
  * [Reference](#reference-r7)
  * [Release notes](#release-notes-r7)
  * [Fixes and improvements](#fixes-and-improvements-r7)
* [v0.14.6](#v0146)
  * [Reference](#reference-r6)
  * [Release notes](#release-notes-r6)
  * [Fixes and improvements](#fixes-and-improvements-r6)
* [v0.14.5](#v0145)
  * [Reference](#reference-r5)
  * [Release notes](#release-notes-r5)
  * [Fixes and improvements](#fixes-and-improvements-r5)
* [v0.14.4](#v0144)
  * [Reference](#reference-r4)
  * [Release notes](#release-notes-r4)
  * [Fixes and improvements](#fixes-and-improvements-r4)
* [v0.14.3](#v0143)
  * [Reference](#reference-r3)
  * [Release notes](#release-notes-r3)
  * [Fixes and improvements](#fixes-and-improvements-r3)
* [v0.14.2](#v0142)
  * [Reference](#reference-r2)
  * [Release notes](#release-notes-r2)
  * [Fixes and improvements](#fixes-and-improvements-r2)
* [v0.14.1](#v0141)
  * [Reference](#reference-r1)
  * [Release notes](#release-notes-r1)
  * [Fixes and improvements](#fixes-and-improvements-r1)
* [v0.14.0](#v0140)
  * [Reference](#reference-r0)
  * [Release notes](#release-notes-r0)
  * [Fixes and improvements](#fixes-and-improvements-r0)
* [v0.14.0-beta.3](#v0140-beta3)
  * [Reference](#reference-b3)
  * [Release notes](#release-notes-b3)
  * [Improvements](#improvements-b3)
  * [Fixes](#fixes-b3)
* [v0.14.0-beta.2](#v0140-beta2)
  * [Reference](#reference-b2)
  * [Release notes](#release-notes-b2)
  * [Improvements](#improvements-b2)
  * [Fixes](#fixes-b2)
* [v0.14.0-beta.1](#v0140-beta1)
  * [Reference](#reference-b1)
  * [Release notes](#release-notes-b1)
  * [Improvements](#improvements-b1)
  * [Fixes](#fixes-b1)
* [v0.14.0-alpha.2](#v0140-alpha2)
  * [Reference](#reference-a2)
  * [Release notes](#release-notes-a2)
  * [Improvements](#improvements-a2)
  * [Fixes](#fixes-a2)
* [v0.14.0-alpha.1](#v0140-alpha1)
  * [Reference](#reference-a1)
  * [Improvements](#improvements-a1)
  * [Fixes](#fixes-a1)

## Major improvements

Highlights of this version

* Embedded HAProxy upgrade from 2.3 to 2.4.
* Partial Gateway API v1alpha2 support, see the [Gateway API getting started page](https://haproxy-ingress.github.io/v0.14/docs/configuration/gateway-api/).
* [Coraza](https://coraza.io/) added as a Web Application Firewall (WAF) backend option, see the [example page](https://haproxy-ingress.github.io/v0.14/docs/examples/modsecurity/#using-coraza-instead-of-modsecurity).
* Option to customize the response payload for any of the status codes managed by HAProxy or HAProxy Ingress, see the [HTTP Responses](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#http-response) configuration key documentation.
* Option to run the embedded HAProxy as Master Worker. Running HAProxy as Master Worker enables [worker-max-reloads](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#master-worker) option without the need to configure as an external deployment, enables HAProxy logging to stdout, and also has a better management of the running process. This option is not enabled by default, see the [master worker documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#master-worker) for further information.
* HAProxy Ingress can now be easily launched in the development environment with the help of the `--local-filesystem-prefix` command-line option. See also the command-line option [documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#local-filesystem-prefix) and the new `make` variables and targets in the [README](https://github.com/jcmoraisjr/haproxy-ingress/#develop-haproxy-ingress) file.

## Upgrade notes

Breaking backward compatibility from v0.13:

* Default `auth-tls-strict` configuration key value changed from `false` to `true`. This update will change the behavior of misconfigured client auth configurations: when `false` misconfigured mTLS send requests to the backend without any authentication, when `true` misconfigured mTLS will always fail the request. See also the [auth TLS documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#auth-tls).
* `auth-tls-verify-client`, when configured as `optional_no_ca`, used to validate client certificates against the configured CA bundle. This happens on controller versions from v0.8 to v0.13. Since v0.14 `optional_no_ca` will bypass certificate validation. Change `auth-tls-verify-client` to `optional` in order to preserve the old behavior.
* Default `--watch-gateway` command-line option changed from `false` to `true`. On v0.13 this option can only be enabled if the Gateway API CRDs are installed; otherwise, the controller would refuse to start. Since v0.14 the controller will always check if the CRDs are installed. This will change the behavior on clusters that has Gateway API resources and doesn't declare the command-line option: v0.13 would ignore the resources and v0.14 would find and apply them. See also the [watch gateway documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#watch-gateway).
* All the response payload managed by the controller using Lua script was rewritten in a backward compatible behavior, however deployments that overrides the `services.lua` script might break. See the [HTTP Responses](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#http-response) documentation on how to customize HTTP responses using controller's configuration keys.
* Two frontends changed their names, which can break deployments that uses the frontend name on metrics, logging, or in the `config-proxy` global configuration key. Frontends changed are: `_front_https`, changed its name to `_front_https__local` if at least one ssl-passthrough is configured, and `_front__auth`, changed its default value to `_front__auth__local`. These changes were made to make the metric's dashboard consistent despite the ssl-passthrough configuration. See the new [metrics example page](https://haproxy-ingress.github.io/v0.14/docs/examples/metrics/) and update your dashboard if using HAProxy Ingress' one.

## Contributors

* Ameya Lokare ([juggernaut](https://github.com/juggernaut))
* Andrej Baran ([andrejbaran](https://github.com/andrejbaran))
* Andrew Rodland ([arodland](https://github.com/arodland))
* Chris Boot ([bootc](https://github.com/bootc))
* Dmitry Misharov ([quarckster](https://github.com/quarckster))
* genofire ([genofire](https://github.com/genofire))
* Gerald  Barker ([gezb](https://github.com/gezb))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Josh Soref ([jsoref](https://github.com/jsoref))
* Jurriaan Wijnberg ([jr01](https://github.com/jr01))
* Karan Chaudhary ([lafolle](https://github.com/lafolle))
* Mac Chaffee ([mac-chaffee](https://github.com/mac-chaffee))
* Maël Valais ([maelvls](https://github.com/maelvls))
* Manuel Rüger ([mrueg](https://github.com/mrueg))
* Marvin Rösch ([PaleoCrafter](https://github.com/PaleoCrafter))
* Mateusz Kubaczyk ([mkubaczyk](https://github.com/mkubaczyk))
* Matt Low ([mlow](https://github.com/mlow))
* Michał Zielonka ([michal800106](https://github.com/michal800106))
* Michele Palazzi ([ironashram](https://github.com/ironashram))
* Neil Seward ([sealneaward](https://github.com/sealneaward))
* paul ([toothbrush](https://github.com/toothbrush))
* Roman Gherta ([rgherta](https://github.com/rgherta))
* ssanders1449 ([ssanders1449](https://github.com/ssanders1449))
* Wojciech Chojnowski ([DCkQ6](https://github.com/DCkQ6))
* wolf-cosmose ([wolf-cosmose](https://github.com/wolf-cosmose))

# v0.14.10

## Reference (r10)

* Release date: `2025-10-10`
* Helm chart: `--version 0.14.10`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.10`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.14.10`
* Embedded HAProxy version: `2.4.30`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.10`

## Release notes (r10)

This release updates the embedded haproxy version, which fixes CVE-2025-11230, see HAProxy release notes https://www.mail-archive.com/haproxy@formilux.org/msg46188.html . This CVE cannot be exploited on HAProxy Ingress because it does not use any of the vulnerable converters. A proxy without the fix can however be exploited by an internal user having access to the Ingress API, from a controller that does not deny configuration snippets via annotations.

Other issues were also found and fixed:

- Chitoku found a regression on some certificate related annotations not working with the `file://` protocol, after implementing global support on those annotations.
- Artyom found the fronting-proxy configuration overwriting the `X-Forwarded-Proto` header when both the fronting proxy and the regular HTTP shares the same TCP port number.

Dependencies:

- embedded haproxy from 2.4.29 to 2.4.30
- go from 1.23.11 to 1.23.12

## Fixes and improvements (r10)

Fixes and improvements since `v0.14.9`:

* fix reading backend ca certificate from file [#1297](https://github.com/jcmoraisjr/haproxy-ingress/pull/1297) (jcmoraisjr)
* fix xfp header on fronting proxy shared port [#1310](https://github.com/jcmoraisjr/haproxy-ingress/pull/1310) (jcmoraisjr)
* update go from 1.23.11 to 1.23.12 [6fcdcc9](https://github.com/jcmoraisjr/haproxy-ingress/commit/6fcdcc94204d701ab14ce15be776b27471d0f377) (Joao Morais)
* update haproxy from 2.4.29 to 2.4.30 [b0a68e4](https://github.com/jcmoraisjr/haproxy-ingress/commit/b0a68e4d1e5eaa27ab861e953aca2f3920648af5) (Joao Morais)

# v0.14.9

## Reference (r9)

* Release date: `2025-07-29`
* Helm chart: `--version 0.14.9`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.9`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.14.9`
* Embedded HAProxy version: `2.4.29`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.9`

## Release notes (r9)

This release updates the embedded haproxy version, dependencies, and fixes issues and vulnerabilities found in the v0.14 branch.

- An user with update ingress privilege can escalate their own privilege to the controller one, by exploring the config snippet annotation if it was not disabled via `--disable-config-keywords=*` command-line option. Mitigate this vulnerability by updating controller version, or disabling config snippet.
- Fixes a panic on controller shutdown due to closing the same connection twice, if its startup failed the very first reconciliation.
- Fixes a race during haproxy reload, when the controller connects fast enough via the master socket, finds the old instance still running and thinks it's the new one already. If this happens, it might lead to problems in the synchronization of the in-memory model to the running instance, sometimes making haproxy to reflect an older state.

Dependencies:

- embedded haproxy from 2.4.28 to 2.4.29
- go from 1.23.7 to 1.23.11

## Fixes and improvements (r9)

Fixes and improvements since `v0.14.8`:

* check if haproxy reloaded already [#1265](https://github.com/jcmoraisjr/haproxy-ingress/pull/1265) (jcmoraisjr)
* ensure that embedded haproxy starts just once [#1266](https://github.com/jcmoraisjr/haproxy-ingress/pull/1266) (jcmoraisjr)
* block attempt to read cluster credentials [#1273](https://github.com/jcmoraisjr/haproxy-ingress/pull/1273) (jcmoraisjr)
* update embedded haproxy from 2.4.28 to 2.4.29 [dda1554](https://github.com/jcmoraisjr/haproxy-ingress/commit/dda1554ca95831cda9e934d17bda0077baca1c5c) (Joao Morais)
* update go from 1.23.7 to 1.23.11 [d8a7712](https://github.com/jcmoraisjr/haproxy-ingress/commit/d8a77122ba72b6166864d238f555c33abb377f53) (Joao Morais)
* update dependencies [752b502](https://github.com/jcmoraisjr/haproxy-ingress/commit/752b5026acd392832e57ffe3396c42e0ea8acd16) (Joao Morais)

Chart improvements since `v0.14.8`:

* Allow custom labels to be added to the controllers DaemonSet/Deployment [#93](https://github.com/haproxy-ingress/charts/pull/93) (gezb)

# v0.14.8

## Reference (r8)

* Release date: `2025-03-18`
* Helm chart: `--version 0.14.8`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.8`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.14.8`
* Embedded HAProxy version: `2.4.28`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.8`

## Release notes (r8)

This release updates the embedded haproxy version, and fixes issues and vulnerable components found in the v0.14 branch.

- Robson, Moacir and Fabio found a memory leak on Gateway API reconciliation. Depending on the changes being applied, an older in memory representation of the load balancer state is referenced by the new one, creating a chain of old representations not having a chance to be collected by GC.
- rdavyd found an endpoint configuration overwrite in the case the same service, or a distinct service with the same endpoints are added in a single rule of a single HTTPRoute on Gateway API.
- Controller now retries to apply a haproxy reload in the case of a failure. Older controller versions didn't retry because all the failures are related with misconfiguration, but since master-worker and external modes are options, other network or socket related issues might happen.
- TCP services now supports a list of TLS certificates.
- All known vulnerable components were updated, like go's stdlib and `golang.org/x/crypto`

Dependencies:

- embedded haproxy from 2.4.26 to 2.4.28
- go from 1.19.13 to 1.23.7, having `//go:debug default=go1.19` for backward compatibility

## Fixes and improvements (r8)

Fixes and improvements since `v0.14.7`:

* bump vulnerable components [0668bf5](https://github.com/jcmoraisjr/haproxy-ingress/commit/0668bf5c4d02aa5cf5a519e779b639a56d0629f6) (Joao Morais)
* update embedded haproxy from 2.4.26 to 2.4.28 [2ba342c](https://github.com/jcmoraisjr/haproxy-ingress/commit/2ba342c15061217f2229ec22db22c3f568060906) (Joao Morais)
* Support list of server crt on tls tcp service [#1171](https://github.com/jcmoraisjr/haproxy-ingress/pull/1171) (jcmoraisjr)
* ingress tcp test improvement [37ba454](https://github.com/jcmoraisjr/haproxy-ingress/commit/37ba454ba118444859670936dc53e7fa718a9dd1) (Joao Morais)
* fix memory leak on gateway reconciliation [#1212](https://github.com/jcmoraisjr/haproxy-ingress/pull/1212) (jcmoraisjr)
* fix lint [b6b9e24](https://github.com/jcmoraisjr/haproxy-ingress/commit/b6b9e249d6c223772f2244d97ddfa829f3fd3562) (Joao Morais)
* retry reload haproxy if failed [#1214](https://github.com/jcmoraisjr/haproxy-ingress/pull/1214) (jcmoraisjr)
* bump vulnerable components [91c51f6](https://github.com/jcmoraisjr/haproxy-ingress/commit/91c51f6b8b508de43ea385e40bcf571f84dd2ca6) (Joao Morais)
* update go from 1.23.6 to 1.23.7 [e8e8129](https://github.com/jcmoraisjr/haproxy-ingress/commit/e8e8129518f92b64ad26b33e3e63d7e747417fc3) (Joao Morais)
* add endpoints even if duplicated [#1224](https://github.com/jcmoraisjr/haproxy-ingress/pull/1224) (jcmoraisjr)
* adjust backward compatible debug default version [5830c78](https://github.com/jcmoraisjr/haproxy-ingress/commit/5830c78d7ad4232bb243e6a276957821c7d9b9e2) (Joao Morais)

Chart improvements since `v0.14.7`:

* Allow adding annotations on the ServiceAccount [#82](https://github.com/haproxy-ingress/charts/pull/82) (fredrik-w)
* Set securityContext for haproxy init container [#84](https://github.com/haproxy-ingress/charts/pull/84) (phihos)
* update registry of default backend image [#87](https://github.com/haproxy-ingress/charts/pull/87) (jcmoraisjr)
* Enable deploying external HPA [#89](https://github.com/haproxy-ingress/charts/pull/89) (gdziwoki)
* Add controller.extraServices list [#86](https://github.com/haproxy-ingress/charts/pull/86) (hedgieinsocks)

# v0.14.7

## Reference (r7)

* Release date: `2024-06-16`
* Helm chart: `--version 0.14.7`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.7`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.14.7`
* Embedded HAProxy version: `2.4.26`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.7`

## Release notes (r7)

This release updates the embedded haproxy version, and fixes some issues found in the v0.14 branch:

- Julien fixed the Vary response header, from Cors, when the backend server returns two or more headers
- tomklapka and Jan implemented a more fine-grained response from Coraza WAF
- HAProxy process, when embedded and in master-worker mode, was being prematurely stopped on rolling updates because it was configured in the same pid group of the controller
- Fix backend selection, when a more generic wildcard hostname was being incorrectly chosen, and it collides with a more specific one which uses mTLS
- Secure backend configuration, like backend protocol and client side mTLS, can now be configured globally for all ingress resources
- Auth external configuration can now be configured globally
- Make sure https redirect happens before path redirect when `app-root` is configured
- Added the steps to configure the embedded HAProxy process to log to stdout, along with controller, useful on dev or small test environments. See [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#syslog)
- Added two distinct helm configurations on the getting started guide: one that uses a service load balancer, another one that uses http(s) ports assigned to the cluster nodes. See [doc](https://haproxy-ingress.github.io/v0.14/docs/getting-started/)

Dependencies:

- embedded haproxy from 2.4.25 to 2.4.26

## Fixes and improvements (r7)

Fixes and improvements since `v0.14.6`:

* Keep all vary header values when adding Origin [#1083](https://github.com/jcmoraisjr/haproxy-ingress/pull/1083) (Jul13nT)
* Fix coraza configuration to use the action variable [#1094](https://github.com/jcmoraisjr/haproxy-ingress/pull/1094) (tomklapka,JanHolger)
* Ensure https redirect happens before root redirect [#1117](https://github.com/jcmoraisjr/haproxy-ingress/pull/1117) (jcmoraisjr)
* Add ssl-always-follow-redirect option [#1118](https://github.com/jcmoraisjr/haproxy-ingress/pull/1118) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#ssl-always-add-https)
  * Configuration keys:
    * `ssl-always-follow-redirect`
* Allows secure backend configuration from global [#1119](https://github.com/jcmoraisjr/haproxy-ingress/pull/1119) (jcmoraisjr)
* Allows to configure auth-url globally [#1120](https://github.com/jcmoraisjr/haproxy-ingress/pull/1120) (jcmoraisjr)
* Remove dedicated maps for SNI match [#1133](https://github.com/jcmoraisjr/haproxy-ingress/pull/1133) (jcmoraisjr)
* Move embedded haproxy process to a distinct pid group [#1136](https://github.com/jcmoraisjr/haproxy-ingress/pull/1136) (jcmoraisjr)
* Local building improvements [#1135](https://github.com/jcmoraisjr/haproxy-ingress/pull/1135) (jcmoraisjr)
* Update linter [#1104](https://github.com/jcmoraisjr/haproxy-ingress/pull/1104) (jcmoraisjr)
* doc: add haproxy logging to stdout [#1138](https://github.com/jcmoraisjr/haproxy-ingress/pull/1138) (jcmoraisjr)
* doc: reorg items and improve helm values in getting started [#1145](https://github.com/jcmoraisjr/haproxy-ingress/pull/1145) (jcmoraisjr)
* update embedded haproxy from 2.4.25 to 2.4.26 [5d51114](https://github.com/jcmoraisjr/haproxy-ingress/commit/5d511144f605671c0117dadd591a23ec826d3a7a) (Joao Morais)
* update dependencies due to cve [b454bfd](https://github.com/jcmoraisjr/haproxy-ingress/commit/b454bfd9b9f9c63cb77e655f477c9dc99c607278) (Joao Morais)

Chart improvements since `v0.14.6`:

* Fix install output message [#81](https://github.com/haproxy-ingress/charts/pull/81) (jcmoraisjr)

# v0.14.6

## Reference (r6)

* Release date: `2024-01-24`
* Helm chart: `--version 0.14.6`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.6`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.6`
* Embedded HAProxy version: `2.4.25`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.6`

## Release notes (r6)

This is a security release that updates the embedded HAProxy, the Alpine base image, and cryptographic related dependencies.

Dependencies:

- embedded haproxy from 2.4.24 to 2.4.25
- golang from 1.19.12 to 1.19.13

## Fixes and improvements (r6)

Fixes and improvements since `v0.14.5`:

* update dependencies [bd475a0](https://github.com/jcmoraisjr/haproxy-ingress/commit/bd475a04356a9bb95a86475f641259ef4b0f6e79) (Joao Morais)
* update embedded haproxy from 2.4.24 to 2.4.25 [2fb1da1](https://github.com/jcmoraisjr/haproxy-ingress/commit/2fb1da14a2a87aa78cb151fc4fafe7750f272dcc) (Joao Morais)
* update go from 1.19.12 to 1.19.13 [f8ad9b0](https://github.com/jcmoraisjr/haproxy-ingress/commit/f8ad9b0796a4c29699497b298dec3222dd9fd295) (Joao Morais)

Chart improvements since `v0.14.5`:

* Allow setting the spec.loadBalancerClass of created Services [#77](https://github.com/haproxy-ingress/charts/pull/77) (mlow)

# v0.14.5

## Reference (r5)

* Release date: `2023-09-01`
* Helm chart: `--version 0.14.5`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.5`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.5`
* Embedded HAProxy version: `2.4.24`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.5`

## Release notes (r5)

This release updates embedded HAProxy, which fixes some major issues regarding header parsing. See the full HAProxy changelog: https://www.mail-archive.com/haproxy@formilux.org/msg43901.html

Jurriaan added support for automount service account token.

Dependencies:

- embedded haproxy from 2.4.23 to 2.4.24
- client-go from v0.24.15 to v0.24.17
- golang from 1.19.10 to 1.19.12

## Fixes and improvements (r5)

Fixes and improvements since `v0.14.4`:

* Bump haproxy to 2.4.24, golang to 1.19.2 [#1022](https://github.com/jcmoraisjr/haproxy-ingress/pull/1022) (mrueg)
* update client-go from v0.24.15 to v0.24.17 [ae927ee](https://github.com/jcmoraisjr/haproxy-ingress/commit/ae927ee78eb8a21d4453477fabc390e4582d6d88) (Joao Morais)

Chart improvements since `v0.14.4`:

* Add support to disable automountServiceAccountToken [#74](https://github.com/haproxy-ingress/charts/pull/74) (jr01)
* Use of automount service account on v1.22 and newer [#75](https://github.com/haproxy-ingress/charts/pull/75) (jcmoraisjr)

# v0.14.4

## Reference (r4)

* Release date: `2023-07-07`
* Helm chart: `--version 0.14.4`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.4`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.4`
* Embedded HAProxy version: `2.4.23`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.4`

## Release notes (r4)

This release fixes some issues found in the v0.14 branch:

- An endless redirect might happen when configuring redirects on domains whose TLS secret declares two or more domains
- A wildcard was not being accepted by the CORS Allowed Header configuration
- Unused HAProxy backends might leak in the configuration, depending on how the configuration is changed, when backend sharding is enabled
- Configuration snippet was missing on backends in TCP mode
- ConfigMap based TCP services were making HAProxy to reload without need, depending on the order that service endpoints were being listed

Dependencies:

- embedded haproxy from 2.4.22 to 2.4.23
- client-go from v0.24.14 to v0.24.15
- golang from 1.19.9 to 1.19.10

## Fixes and improvements (r4)

Fixes and improvements since `v0.14.3`:

* Update dependencies [#1007](https://github.com/jcmoraisjr/haproxy-ingress/pull/1007) (mrueg)
* fix: config-backend annotation also for TCP-Backends [#1009](https://github.com/jcmoraisjr/haproxy-ingress/pull/1009) (genofire)
* Create endpoints on a predictable order [#1011](https://github.com/jcmoraisjr/haproxy-ingress/pull/1011) (jcmoraisjr)
* Redirect hosts only to domains with associated backends [#1010](https://github.com/jcmoraisjr/haproxy-ingress/pull/1010) (jcmoraisjr)
* Prefer ingressClassName over annotations in docs [#986](https://github.com/jcmoraisjr/haproxy-ingress/pull/986) (mac-chaffee)
* Fix shard render when the last backend is removed [#1015](https://github.com/jcmoraisjr/haproxy-ingress/pull/1015) (jcmoraisjr)
* Add wildcard as a valid cors allowed header [#1016](https://github.com/jcmoraisjr/haproxy-ingress/pull/1016) (jcmoraisjr)
* update client-go from v0.24.14 to v0.24.15 [30723e2](https://github.com/jcmoraisjr/haproxy-ingress/commit/30723e2845272074b909a491262e01efb205720c) (Joao Morais)

Chart improvements since `v0.14.3`:

* Add lifecycle hooks to external HAProxy container [#72](https://github.com/haproxy-ingress/charts/pull/72) (bootc)
* chore: update HorizontalPodAutoscaler apiVersion [#71](https://github.com/haproxy-ingress/charts/pull/71) (quarckster)
* add conditional PodDisruptionBudget [#73](https://github.com/haproxy-ingress/charts/pull/73) (jcmoraisjr)

# v0.14.3

## Reference (r3)

* Release date: `2023-06-05`
* Helm chart: `--version 0.14.3`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.3`
* Embedded HAProxy version: `2.4.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.3`

## Release notes (r3)

This release fixes some issues found in the v0.14 branch:

- External HAProxy was failing with the message "cannot open the file '/var/lib/haproxy/crt/default-fake-certificate.pem'.". This happened due to missing permission to read certificate and private key files when HAProxy container starts as non root, which is the default since HAProxy 2.4.
- ConfigMap based TCP services was randomly missing when the controller started, being reincluded only after the first reconciliation.
- Gateway API v1alpha2 was missing delete events, which means that the controller wasn't updating the configuration when a Gateway API resource was removed.

Other notable changes include:

- Karan Chaudhary added EndpointSlices support. v0.14 branch has this option disabled by default, enable it by adding `--enable-endpointslices-api` command-line option.
- HTTP redirect now has an option to skip some paths, the default configuration adds an exception to `/.well-known/acme-challenge`.
- An update to the External HAProxy example page adds options to fix permission failures to bind ports `:80` and `:443`, see the [example page](https://haproxy-ingress.github.io/v0.14/docs/examples/external-haproxy/#a-word-about-security).

Dependencies:

- Update client-go from v0.23.16 to v0.24.14
- Update golang from 1.18.10 to 1.19.9

## Fixes and improvements (r3)

Fixes and improvements since `v0.14.2`:

* Skip acme-challenge path on to/from redirects [#995](https://github.com/jcmoraisjr/haproxy-ingress/pull/995) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#redirect)
  * Configuration keys:
    * `no-redirect-locations`
* Fixes configmap based tcp sync [#1001](https://github.com/jcmoraisjr/haproxy-ingress/pull/1001) (jcmoraisjr)
* Adds support for EndpointSlices API in master [#959](https://github.com/jcmoraisjr/haproxy-ingress/pull/959) (lafolle) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#enable-endpointslices-api)
  * Command-line options:
    * `--enable-endpointslices-api`
* Fix gw-v1alpha2 delete notifications [#1002](https://github.com/jcmoraisjr/haproxy-ingress/pull/1002) (jcmoraisjr)
* Ensure predictable tcp by sorting endpoints [#1003](https://github.com/jcmoraisjr/haproxy-ingress/pull/1003) (jcmoraisjr)
* Change owner of crt/key files to haproxy pid [#1004](https://github.com/jcmoraisjr/haproxy-ingress/pull/1004) (jcmoraisjr)
* update client-go from v0.23.16 to v0.24.14 [3246e19](https://github.com/jcmoraisjr/haproxy-ingress/commit/3246e196c28a17e9bc58c9b0cdaa3ee37c8d98b2) (Joao Morais)
* add security considerations on external haproxy [61e1df7](https://github.com/jcmoraisjr/haproxy-ingress/commit/61e1df776aad8dd4d8c68e42719d46f61a7b3646) (Joao Morais)
* update golang from 1.18.10 to 1.19.9 [52ede0f](https://github.com/jcmoraisjr/haproxy-ingress/commit/52ede0f8e10979e36838f3525da2afda5fe283c7) (Joao Morais)

# v0.14.2

## Reference (r2)

* Release date: `2023-02-14`
* Helm chart: `--version 0.14.2`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.2`
* Embedded HAProxy version: `2.4.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.2`

## Release notes (r2)

This release fixes CVE-2023-25725 on HAProxy. See HAProxy's release notes regarding the issue and a possible work around: https://www.mail-archive.com/haproxy@formilux.org/msg43229.html

Dependencies:

- Embedded HAProxy version was updated from 2.4.21 to 2.4.22.

## Fixes and improvements (r2)

New features and improvements since `v0.14.1`:

* update dependencies [0efcd77](https://github.com/jcmoraisjr/haproxy-ingress/commit/0efcd77c8395792e81b4272458ac488fdedd8d45) (Joao Morais)
* update embedded haproxy from 2.4.21 to 2.4.22 [a8c942b](https://github.com/jcmoraisjr/haproxy-ingress/commit/a8c942b7c3f21475c3e090896a4d8f11199fd274) (Joao Morais)

# v0.14.1

## Reference (r1)

* Release date: `2023-02-10`
* Helm chart: `--version 0.14.1`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.1`
* Embedded HAProxy version: `2.4.21`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.1`

## Release notes (r1)

This release fixes the following issues:

- Service resources accept annotations just like ingress ones. However services annotated with path scoped annotations, like `haproxy-ingress.github.io/cors-enable` and `haproxy-ingress.github.io/auth-url`, were applying the configuration to just one of the paths pointing the service. So, considering `domain.local/path1` and `domain.local/path2` pointing to `svc1`, an annotation added to `svc1` would only be applied to one of the paths.
- A wrong named port configured on the external auth was being silently ignored. This update adds this information in the documentation and also adds a warning in the log. See auth external [documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#auth-external).

Other notable changes include:

- Mutual TLS authentication (mTLS, Auth TLS) was being skipped on v0.14 if all the domains that configure mTLS are configured with `optional_no_ca`.

Dependencies:

- Embedded HAProxy version was updated from 2.4.20 to 2.4.21.
- Go updated from 1.18.9 to 1.18.10.
- Client-go updated from v0.23.15 to v0.23.16.

## Fixes and improvements (r1)

New features and improvements since `v0.14.0`:

* Fix path scoped annotation on service resources [#984](https://github.com/jcmoraisjr/haproxy-ingress/pull/984) (jcmoraisjr)
* Fix mTLS when all hosts are optional_no_ca [#977](https://github.com/jcmoraisjr/haproxy-ingress/pull/977) (jcmoraisjr)
* Add warning if auth external svc isnt found [#982](https://github.com/jcmoraisjr/haproxy-ingress/pull/982) (jcmoraisjr)
* update embedded haproxy from 2.4.20 to 2.4.21 [2b503d6](https://github.com/jcmoraisjr/haproxy-ingress/commit/2b503d6c029074703f04586fcff687254bc6d47c) (Joao Morais)
* update go from 1.18.9 to 1.18.10 [717eea3](https://github.com/jcmoraisjr/haproxy-ingress/commit/717eea3a7cccb9130a4a4726623cad52393476e7) (Joao Morais)
* update dependencies [a8da9b8](https://github.com/jcmoraisjr/haproxy-ingress/commit/a8da9b80af265a2f80453d2b72223dc3c4ba958a) (Joao Morais)

# v0.14.0

## Reference (r0)

* Release date: `2022-12-26`
* Helm chart: `--version 0.14.0`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.0`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.0`
* Embedded HAProxy version: `2.4.20`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.0`

## Release notes (r0)

This is the first v0.14 release graduated as GA, which adds these major improvements since v0.13:

- [Coraza](https://coraza.io/) Web Application Firewall (WAF) support, see the [example page](https://haproxy-ingress.github.io/v0.14/docs/examples/modsecurity/#using-coraza-instead-of-modsecurity).
- Customization of all [HAProxy generated response payload](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#http-response).
- [Gateway API support improvement](https://haproxy-ingress.github.io/v0.14/docs/configuration/gateway-api/) - although we're not fully compliant yet.

The following improvements have been made since the last beta version:

- Michele Palazzi added a new configuration snippet that allows to add customized configurations before any builtin frontend logic.
- Ability to configure mutual TLS authentication without validating the client certificate. This adds a breaking backward compatibility from v0.13: `auth-tls-verify-client` configured as `optional_no_ca` used to make client certificate validation, now that validation is bypassed.

Dependencies:

- Embedded HAProxy version was updated from 2.4.19 to 2.4.20.
- Golang updated from 1.17.13 to 1.18.9
- Client-go updated from v0.23.14 to v0.23.15.

## Fixes and improvements (r0)

New features and improvements since `v0.14.0-beta.3`:

* Move CustomFrontend before any http-req in haproxy template [#951](https://github.com/jcmoraisjr/haproxy-ingress/pull/951) (ironashram) [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#configuration-snippet)
  * Configuration keys:
    * `config-frontend-early`
    * `config-frontend-late`
* Make optional_no_ca bypass proxy side validations [#976](https://github.com/jcmoraisjr/haproxy-ingress/pull/976) (jcmoraisjr)

# v0.14.0-beta.3

## Reference (b3)

* Release date: `2022-12-10`
* Helm chart: `--version 0.14.0-beta.3 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.0-beta.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.0-beta.3`
* Embedded HAProxy version: `2.4.19`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.0-beta.3`

## Release notes (b3)

This is the third and last beta version of the v0.14 release branch. It fixed some minor issues:

- Embedded Acme signer can now sign certificates for hosts used on redirects
- `auth-headers-*` configuration keys, from Auth External, used to break the HAProxy configuration if declared empty. Now an empty value makes none of the headers being copied.

Other visible improvements include:

- Andrej Baran added support for Load Server State on external HAProxy
- Mac Chaffee added [Coraza WAF](https://coraza.io) support, see the [example page](https://haproxy-ingress.github.io/v0.14/docs/examples/modsecurity/#using-coraza-instead-of-modsecurity) on how to configure it.
- Zap added as an optional logger sink, which adds the ability to control a few more logging options. See the [logging command-line options doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#logging).

Dependencies:

- Embedded HAProxy version was updated from 2.4.18 to 2.4.19.
- Client-go updated from v0.23.10 to v0.23.14.

## Improvements (b3)

New features and improvements since `v0.14.0-beta.2`:

* Change klog.Fatal to klog.Exit [#955](https://github.com/jcmoraisjr/haproxy-ingress/pull/955) (jcmoraisjr)
* Enable Load Server State feature for external haproxy [#957](https://github.com/jcmoraisjr/haproxy-ingress/pull/957) (andrejbaran)
* Add Zap as a logger sink option [#967](https://github.com/jcmoraisjr/haproxy-ingress/pull/967) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#logging)
  * Command-line options:
    * `--log-zap`
    * `--log-dev`
    * `--log-caller`
    * `--log-enable-stacktrace`
    * `--log-encoder`
    * `--log-encode-time`
* Allow ability to customize modsecurity args [#948](https://github.com/jcmoraisjr/haproxy-ingress/pull/948) (mac-chaffee) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#modsecurity)
  * Configuration keys:
    * `modsecurity-args`
* Coraza support [#964](https://github.com/jcmoraisjr/haproxy-ingress/pull/964) (mac-chaffee) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#modsecurity)
  * Configuration keys:
    * `modsecurity-use-coraza`

## Fixes (b3)

* Fix host redirects when acme is enabled [#971](https://github.com/jcmoraisjr/haproxy-ingress/pull/971) (jcmoraisjr)
* Makes auth-headers not copying on empty string [#972](https://github.com/jcmoraisjr/haproxy-ingress/pull/972) (jcmoraisjr)

# v0.14.0-beta.2

## Reference (b2)

* Release date: `2022-09-07`
* Helm chart: `--version 0.14.0-beta.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.0-beta.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.0-beta.2`
* Embedded HAProxy version: `2.4.18`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.0-beta.2`

## Release notes (b2)

This is the second beta release of the v0.14 version, which fixes a small regression added in v0.8. Up to version v0.7 HAProxy Ingress accepted services of type External Name without port declaration, in this case the same port number configured in the ingress resource was used to configure the backend. Since the v0.8 refactor, a port configuration became mandatory in the service resource. This update brings the v0.7 behavior again, so services of type External Name have port declaration optional.

Other visible improvements include:

- Image generation now updates OS dependencies added by the upstream image, which avoids to release images with known vulnerabilities
- Manuel Rüger updated some old and deprecated dependency versions

Dependencies:

- Embedded HAProxy version was updated from 2.4.17 to 2.4.18.
- Golang updated from 1.17.11 to 1.17.13.
- Client-go updated from v0.23.8 to v0.23.10.

## Improvements (b2)

New features and improvements since `v0.14.0-beta.1`:

* Documents the expected format for --configmap key [#940](https://github.com/jcmoraisjr/haproxy-ingress/pull/940) (lafolle)
* Add apk upgrade on container building [#941](https://github.com/jcmoraisjr/haproxy-ingress/pull/941) (jcmoraisjr)
* Update client-go from v0.23.8 to v0.23.9 and indirect dependencies [#943](https://github.com/jcmoraisjr/haproxy-ingress/pull/943) (jcmoraisjr)
* Migrate to new versions / off deprecated packages. [#945](https://github.com/jcmoraisjr/haproxy-ingress/pull/945) (mrueg)
* update client-go from v0.23.9 to v0.23.10 [e290714](https://github.com/jcmoraisjr/haproxy-ingress/commit/e290714025da1b35b3b93763e12ded688663ca68) (Joao Morais)
* update embedded haproxy from 2.4.17 to 2.4.18 [d2a88db](https://github.com/jcmoraisjr/haproxy-ingress/commit/d2a88db9f1c255d3f43597833818c53c0d0ff334) (Joao Morais)
* update golang from 1.17.11 to 1.17.13 [0de7ef6](https://github.com/jcmoraisjr/haproxy-ingress/commit/0de7ef6234a067c99b993f2a9ae1c027e0033053) (Joao Morais)

## Fixes (b2)

* Fix go lint issues [#942](https://github.com/jcmoraisjr/haproxy-ingress/pull/942) (jcmoraisjr)
* Add support for service external name without port [#946](https://github.com/jcmoraisjr/haproxy-ingress/pull/946) (jcmoraisjr)

# v0.14.0-beta.1

## Reference (b1)

* Release date: `2022-07-03`
* Helm chart: `--version 0.14.0-beta.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.0-beta.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.0-beta.1`
* Embedded HAProxy version: `2.4.17`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.0-beta.1`

## Release notes (b1)

This is the first beta release of the v0.14 version, which fixes some issues from the previous tag:

- A possible typecast failure reported by monkeymorgan was fixed, which could happen on outages of the apiserver and some resources are removed from the api before the controller starts to watch the api again.
- A lock was added before checking for expiring certificates when the embedded acme client is configured. This lock prevents the check routine to read the internal model while another thread is modifying it to apply a configuration change.
- The external HAProxy now starts without a readiness endpoint configured. This avoids adding a just deployed controller as available before it has been properly configured. Starting liveness was raised in the helm chart, so that huge environments have time enough to start.

Other visible improvements include:

- Josh Soref fixed a lot of typos in the documentation and comments.
- wolf-cosmose implemented a regex based Cors Allow Origin option.
- Metrics example now uses Prometheus Operator and the service monitor provided by the helm chart.
- Some internal frontend names were changed to allow consistent metrics despite the ssl-passthrough configuration, see the [upgrade notes](#upgrade-notes).

Dependencies:

- Embedded HAProxy version was updated from 2.4.15 to 2.4.17.
- Golang updated from 1.17.8 to 1.17.11.
- Client-go updated from v0.23.5 to v0.23.8.

## Improvements (b1)

New features and improvements since `v0.14.0-alpha.2`:

* Change metrics example to use servicemonitor [#919](https://github.com/jcmoraisjr/haproxy-ingress/pull/919) (jcmoraisjr)
* Add suffix to name of local frontend proxies [#922](https://github.com/jcmoraisjr/haproxy-ingress/pull/922) (jcmoraisjr)
* Spelling [#928](https://github.com/jcmoraisjr/haproxy-ingress/pull/928) (jsoref)
* Add cors-allow-origin-regex annotation [#927](https://github.com/jcmoraisjr/haproxy-ingress/pull/927) (wolf-cosmose) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#cors)
  * Configuration keys:
    * `cors-allow-origin-regex`
* update embedded haproxy from 2.4.15 to 2.4.17 [1958457](https://github.com/jcmoraisjr/haproxy-ingress/commit/1958457420b808dc154ee690d5e8f8cb9c6c212b) (Joao Morais)
* update golang from 1.17.8 to 1.17.11 [801a425](https://github.com/jcmoraisjr/haproxy-ingress/commit/801a425576a3be25e98429fe19ea04f7562123f1) (Joao Morais)
* update client-go from v0.23.5 to v0.23.8 [200f885](https://github.com/jcmoraisjr/haproxy-ingress/commit/200f885cf83b88d3c4ae27c95530a7326786f981) (Joao Morais)

## Fixes (b1)

* Check type assertion on all informers [#934](https://github.com/jcmoraisjr/haproxy-ingress/pull/934) (jcmoraisjr)
* Add lock before call acmeCheck() [#935](https://github.com/jcmoraisjr/haproxy-ingress/pull/935) (jcmoraisjr)
* Remove readiness endpoint from starting config [#937](https://github.com/jcmoraisjr/haproxy-ingress/pull/937) (jcmoraisjr)

# v0.14.0-alpha.2

## Reference (a2)

* Release date: `2022-04-07`
* Helm chart: `--version 0.14.0-alpha.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.0-alpha.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.0-alpha.2`
* Embedded HAProxy version: `2.4.15`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.14.0-alpha.2`

## Release notes (a2)

This is the second and last alpha release of v0.14, which fixes the following issues:

- The configured service was not being selected if the incoming path doesn't finish with a slash, the host is not declared in the ingress resource (using default host), the path type is Prefix, and the pattern is a single slash.
- Marvin Rösch fixed a delay of 5 seconds to connect to a server using a TCP service. Such delay happens whenever a host is used in the ingress resource and the SSL offload is made by HAProxy.

Other visible improvements include:

- Add compatibility with HAProxy 2.5 deployed as external/sidecar. Version 2.5 changed the lay out of the `show proc` command of the master API.
- Add the ability to overwrite any of the HAProxy generated response payloads, see the [HTTP Response documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#http-response)
- Add `ssl-fingerprint-sha2-bits` configuration key which adds a HTTP header with the SHA-2 fingerprint of client certificates.
- Update to the latest version of golang 1.17, client-go v0.23 and haproxy 2.4

There is also a few other internal and non visible improvements. First beta version should be tagged within a week or so, after finish some exploratory tests.

## Improvements (a2)

New features and improvements since `v0.14.0-alpha.1`:

* Replace glog with klog/v2 [#904](https://github.com/jcmoraisjr/haproxy-ingress/pull/904) (mrueg)
* Remove initial whitespaces from haproxy template [#910](https://github.com/jcmoraisjr/haproxy-ingress/pull/910) (ironashram)
* Add haproxy 2.5 support for external haproxy [#905](https://github.com/jcmoraisjr/haproxy-ingress/pull/905) (jcmoraisjr)
* Add ssl-fingerprint-sha2-bits configuration key [#911](https://github.com/jcmoraisjr/haproxy-ingress/pull/911) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#auth-tls)
  * Configuration keys:
    * `ssl-fingerprint-sha2-bits`
* Add http-response configuration keys [#915](https://github.com/jcmoraisjr/haproxy-ingress/pull/915) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#http-response)
  * Configuration keys:
    * `http-response-<code>`
    * `http-response-prometheus-root`
* update embedded haproxy from 2.4.12 to 2.4.15 [c29ddf5](https://github.com/jcmoraisjr/haproxy-ingress/commit/c29ddf5a10d9a843a0ab83f62a85a42c95248bea) (Joao Morais)
* update client-go from v0.23.3 to v0.23.5 [a507389](https://github.com/jcmoraisjr/haproxy-ingress/commit/a507389acc4bbffb5358e03a446622b1d77dd60c) (Joao Morais)
* update golang from 1.17.6 to 1.17.8 [5b78816](https://github.com/jcmoraisjr/haproxy-ingress/commit/5b78816c9a013919df12161b1b614724f4764d62) (Joao Morais)

## Fixes (a2)

* Fix match of prefix pathtype if using default host [#908](https://github.com/jcmoraisjr/haproxy-ingress/pull/908) (jcmoraisjr)
* Only inspect SSL handshake for SNI routing for SSL passthrough [#914](https://github.com/jcmoraisjr/haproxy-ingress/pull/914) (PaleoCrafter)
* Fix reload failure detection on 2.5+ [#916](https://github.com/jcmoraisjr/haproxy-ingress/pull/916) (jcmoraisjr)

# v0.14.0-alpha.1

## Reference (a1)

* Release date: `2022-02-13`
* Helm chart: `--version 0.14.0-alpha.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.14.0-alpha.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.14.0-alpha.1`
* Embedded HAProxy version: `2.4.12`

## Improvements (a1)

New features and improvements since `v0.13-beta.1`:

* update client-go from v0.20.7 to v0.21.1 [9e8f75b](https://github.com/jcmoraisjr/haproxy-ingress/commit/9e8f75b6d549cf0be89beb1be1cb14179fd0a8a7) (Joao Morais)
* update gateway api from v0.2.0 to v0.3.0 [97abfa9](https://github.com/jcmoraisjr/haproxy-ingress/commit/97abfa99954a892cc89af929570134f296f836a5) (Joao Morais)
* update golang from 1.15.13 to 1.16.15 [2f48838](https://github.com/jcmoraisjr/haproxy-ingress/commit/2f48838526ddcfea68f6013dc0c34a13a2e0700e) (Joao Morais)
* update embedded haproxy from 2.3.10 to 2.4.0 [23e2418](https://github.com/jcmoraisjr/haproxy-ingress/commit/23e24182b243020976a5582af655c76f3d4fa6a5) (Joao Morais)
* Stable IDs for consistent-hash load balancing [#801](https://github.com/jcmoraisjr/haproxy-ingress/pull/801) (arodland) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#backend-server-id)
  * Configuration keys:
    * `assign-backend-server-id`
* Ensure that configured global ConfigMap exists [#804](https://github.com/jcmoraisjr/haproxy-ingress/pull/804) (jcmoraisjr)
* Update auth-request.lua script [#809](https://github.com/jcmoraisjr/haproxy-ingress/pull/809) (jcmoraisjr)
* Add log of reload error on every reconciliation [#811](https://github.com/jcmoraisjr/haproxy-ingress/pull/811) (jcmoraisjr)
* Add disable-external-name command-line option [#816](https://github.com/jcmoraisjr/haproxy-ingress/pull/816) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#disable-external-name)
  * Command-line options:
    * `--disable-external-name`
* Add reload interval command-line option [#815](https://github.com/jcmoraisjr/haproxy-ingress/pull/815) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#reload-interval)
  * Command-line options:
    * `--reload-interval`
* Updates to the help output of command-line options [#814](https://github.com/jcmoraisjr/haproxy-ingress/pull/814) (jcmoraisjr)
* Add disable-config-keywords command-line options [#820](https://github.com/jcmoraisjr/haproxy-ingress/pull/820) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#disable-config-keywords)
  * Command-line options:
    * `--disable-config-keywords`
* Change nbthread to use all CPUs by default [#821](https://github.com/jcmoraisjr/haproxy-ingress/pull/821) (jcmoraisjr)
* Option to use client and master socket in keep alive mode [#824](https://github.com/jcmoraisjr/haproxy-ingress/pull/824) (jcmoraisjr)
* Add close-sessions-duration config key [#827](https://github.com/jcmoraisjr/haproxy-ingress/pull/827) (jcmoraisjr)
  * Configuration keys:
    * `close-sessions-duration` - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#close-sessions-duration)
  * Command-line options:
    * `--track-old-instances` - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#track-old-instances)
* Add arm64 build [#836](https://github.com/jcmoraisjr/haproxy-ingress/pull/836) (jcmoraisjr)
* Feature/allowlist behind reverse proxy [#846](https://github.com/jcmoraisjr/haproxy-ingress/pull/846) (DCkQ6) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#allowlist)
  * Configuration keys:
    * `allowlist-source-header`
* Refactor tracker to an abstract implementation [#850](https://github.com/jcmoraisjr/haproxy-ingress/pull/850) (jcmoraisjr)
* Add read and write timeout to the unix socket [#855](https://github.com/jcmoraisjr/haproxy-ingress/pull/855) (jcmoraisjr)
* Add --ingress-class-precedence to allow IngressClass taking precedence over annotation [#857](https://github.com/jcmoraisjr/haproxy-ingress/pull/857) (mkubaczyk) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#ingress-class)
  * Command-line options:
    * `--ingress-class-precedence`
* Add acme-preferred-chain config key [#864](https://github.com/jcmoraisjr/haproxy-ingress/pull/864) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#acme)
  * Configuration keys:
    * `acme-preferred-chain`
* Add new target platforms [#870](https://github.com/jcmoraisjr/haproxy-ingress/pull/870) (jcmoraisjr)
* Add local deployment configuration [#878](https://github.com/jcmoraisjr/haproxy-ingress/pull/878) (jcmoraisjr)
* Add master-worker mode on embedded haproxy [#880](https://github.com/jcmoraisjr/haproxy-ingress/pull/880) (jcmoraisjr)
* Add session-cookie-domain configuration key [#889](https://github.com/jcmoraisjr/haproxy-ingress/pull/889) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#affinity)
  * Configuration keys:
    * `session-cookie-domain`
* Upgrade crypto dependency [#895](https://github.com/jcmoraisjr/haproxy-ingress/pull/895) (rgherta)
* Bump dependencies [#874](https://github.com/jcmoraisjr/haproxy-ingress/pull/874) (mrueg)
* Add auth-tls configurations to tcp services [#883](https://github.com/jcmoraisjr/haproxy-ingress/pull/883) (jcmoraisjr)
* Change auth-tls-strict from false to true [#885](https://github.com/jcmoraisjr/haproxy-ingress/pull/885) (jcmoraisjr)
* Check by default if gateway api crds are installed [#898](https://github.com/jcmoraisjr/haproxy-ingress/pull/898) (jcmoraisjr)
* Add starting implementation of Gateway API v1alpha2 [#900](https://github.com/jcmoraisjr/haproxy-ingress/pull/900) (jcmoraisjr)
* update embedded haproxy from 2.4.0 to 2.4.12 [93adbb9](https://github.com/jcmoraisjr/haproxy-ingress/commit/93adbb9f58be8913dd4967b1f364743682871b1a) (Joao Morais)

## Fixes (a1)

* Fix backend match if no ingress use host match [#802](https://github.com/jcmoraisjr/haproxy-ingress/pull/802) (jcmoraisjr)
* Reload haproxy if a backend server cannot be found [#810](https://github.com/jcmoraisjr/haproxy-ingress/pull/810) (jcmoraisjr)
* Fix auth-url parsing if hostname misses a dot [#818](https://github.com/jcmoraisjr/haproxy-ingress/pull/818) (jcmoraisjr)
* Always deny requests of failed auth configurations [#819](https://github.com/jcmoraisjr/haproxy-ingress/pull/819) (jcmoraisjr)
* Gateway API: when using v1alpha1, certificateRef.group now accepts "core" [#833](https://github.com/jcmoraisjr/haproxy-ingress/pull/833) (maelvls)
* Fix set ssl cert end-of-command [#828](https://github.com/jcmoraisjr/haproxy-ingress/pull/828) (jcmoraisjr)
* Fix dynamic update of frontend crt [#829](https://github.com/jcmoraisjr/haproxy-ingress/pull/829) (jcmoraisjr)
* Fix change notification of backend shard [#835](https://github.com/jcmoraisjr/haproxy-ingress/pull/835) (jcmoraisjr)
* Fix ingress update to an existing backend [#847](https://github.com/jcmoraisjr/haproxy-ingress/pull/847) (jcmoraisjr)
* Fix endpoint update of configmap based tcp services [#842](https://github.com/jcmoraisjr/haproxy-ingress/pull/842) (jcmoraisjr)
* Fix config parsing on misconfigured auth external [#844](https://github.com/jcmoraisjr/haproxy-ingress/pull/844) (jcmoraisjr)
* Fix validation if ca is used with crt and key [#845](https://github.com/jcmoraisjr/haproxy-ingress/pull/845) (jcmoraisjr)
* Fix global config-backend snippet config [#856](https://github.com/jcmoraisjr/haproxy-ingress/pull/856) (jcmoraisjr)
* Fix global config-backend snippet config [#856](https://github.com/jcmoraisjr/haproxy-ingress/pull/856) (jcmoraisjr)
* Remove setting vary origin header always when multiple origins are set [#861](https://github.com/jcmoraisjr/haproxy-ingress/pull/861) (michal800106)
* Fix error message on secret/cm update failure [#863](https://github.com/jcmoraisjr/haproxy-ingress/pull/863) (jcmoraisjr)
* Fix typo: distinct [#867](https://github.com/jcmoraisjr/haproxy-ingress/pull/867) (juggernaut)
* Add disableKeywords only if defined [#876](https://github.com/jcmoraisjr/haproxy-ingress/pull/876) (jcmoraisjr)
* Add match method on all var() sample fetch method [#879](https://github.com/jcmoraisjr/haproxy-ingress/pull/879) (jcmoraisjr)
* Fix sni sample fetch on ssl deciphered tcp conns [#884](https://github.com/jcmoraisjr/haproxy-ingress/pull/884) (jcmoraisjr)
* Fix docker-build target name [#896](https://github.com/jcmoraisjr/haproxy-ingress/pull/896) (rgherta)

## Other

* docs: Add all command-line options to list. [#806](https://github.com/jcmoraisjr/haproxy-ingress/pull/806) (toothbrush)
* docs: update haproxy doc link to 2.2 [13bdd7c](https://github.com/jcmoraisjr/haproxy-ingress/commit/13bdd7cdb4e5ef9b0a14de8eee79e0b30b1a374e) (Joao Morais)
* docs: add section for AuditLog sidecar for ModSecurity daemonset [#825](https://github.com/jcmoraisjr/haproxy-ingress/pull/825) (sealneaward)
* docs: changing NodeSelector to ClusterIP service for ModSecurity [#826](https://github.com/jcmoraisjr/haproxy-ingress/pull/826) (sealneaward)
* docs: add a faq [#837](https://github.com/jcmoraisjr/haproxy-ingress/pull/837) (jcmoraisjr)
* docs: add modsec resource limits to controls V2 memory consumption [#841](https://github.com/jcmoraisjr/haproxy-ingress/pull/841) (sealneaward)
* Add golangci-lint and fix issues found by it [#868](https://github.com/jcmoraisjr/haproxy-ingress/pull/868) (mrueg)
* docs: include tuning of free backend slots in performance suggestions [#891](https://github.com/jcmoraisjr/haproxy-ingress/pull/891) (ssanders1449)
* docs: update haproxy doc link to 2.4 [#886](https://github.com/jcmoraisjr/haproxy-ingress/pull/886) (jcmoraisjr)
