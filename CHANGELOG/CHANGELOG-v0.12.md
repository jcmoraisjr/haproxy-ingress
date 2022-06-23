# CHANGELOG v0.12 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.11!](#upgrade-notes)
* [Contributors](#contributors)
* [v0.12.13](#v01213)
  * [Reference](#reference-r13)
  * [Release notes](#release-notes-r13)
  * [Fixes and improvements](#fixes-and-improvements-r13)
* [v0.12.12](#v01212)
  * [Reference](#reference-r12)
  * [Release notes](#release-notes-r12)
  * [Fixes and improvements](#fixes-and-improvements-r12)
* [v0.12.11](#v01211)
  * [Reference](#reference-r11)
  * [Release notes](#release-notes-r11)
  * [Fixes and improvements](#fixes-and-improvements-r11)
* [v0.12.10](#v01210)
  * [Reference](#reference-r10)
  * [Release notes](#release-notes-r10)
  * [Fixes and improvements](#fixes-and-improvements-r10)
* [v0.12.9](#v0129)
  * [Reference](#reference-r9)
  * [Release notes](#release-notes-r9)
  * [Fixes and improvements](#fixes-and-improvements-r9)
* [v0.12.8](#v0128)
  * [Reference](#reference-r8)
  * [Release notes](#release-notes-r8)
  * [Fixes and improvements](#fixes-and-improvements-r8)
* [v0.12.7](#v0127)
  * [Reference](#reference-r7)
  * [Release notes](#release-notes-r7)
  * [Fixes and improvements](#fixes-and-improvements-r7)
* [v0.12.6](#v0126)
  * [Reference](#reference-r6)
  * [Release notes](#release-notes-r6)
  * [Fixes and improvements](#fixes-and-improvements-r6)
* [v0.12.5](#v0125)
  * [Reference](#reference-r5)
  * [Fixes and improvements](#fixes-and-improvements-r5)
* [v0.12.4](#v0124)
  * [Reference](#reference-r4)
  * [Fixes and improvements](#fixes-and-improvements-r4)
* [v0.12.3](#v0123)
  * [Reference](#reference-r3)
  * [Fixes and improvements](#fixes-and-improvements-r3)
* [v0.12.2](#v0122)
  * [Reference](#reference-r2)
  * [Fixes and improvements](#fixes-and-improvements-r2)
* [v0.12.1](#v0121)
  * [Reference](#reference-r1)
  * [Fixes and improvements](#fixes-and-improvements-r1)
* [v0.12](#v012)
  * [Reference](#reference-r0)
  * [Fixes and improvements](#fixes-and-improvements-r0)
* [v0.12-beta.2](#v012-beta2)
  * [Reference](#reference-b2)
  * [Fixes and improvements](#fixes-and-improvements-b2)
* [v0.12-beta.1](#v012-beta1)
  * [Reference](#reference-b1)
  * [Improvements](#improvements-b1)
  * [Fixes](#fixes-b1)
* [v0.12-snapshot.3](#v012-snapshot3)
  * [Reference](#reference-s3)
  * [Improvements](#improvements-s3)
  * [Fixes](#fixes-s3)
* [v0.12-snapshot.2](#v012-snapshot2)
  * [Reference](#reference-s2)
  * [Improvements](#improvements-s2)
  * [Fixes](#fixes-s3)
* [v0.12-snapshot.1](#v012-snapshot1)
  * [Reference](#reference-s1)
  * [Improvements](#improvements-s1)
  * [Fixes](#fixes-s1)

## Major improvements

Highlights of this version

* HAProxy upgrade from 2.1 to 2.2.
* IngressClass resource support.
* Ability to configure and run an external haproxy, version 2.0 or above, on a sidecar container.

## Upgrade notes

Breaking backward compatibility from v0.11

* Kubernetes version 1.18 or newer.
* Ingress resources without `kubernetes.io/ingress.class` annotation was listened by default up to v0.11, now they are not. This will change the final configuration of clusters that 1) have Ingress resources without the class annotation and without the `ingressClassName` field, and 2) does not declare the `--ignore-ingress-without-class` command-line option. Add the command-line option `--watch-ingress-without-class` to bring back the default v0.11 behavior. See the [class matter](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#class-matter) documentation.
* HAProxy Ingress service account needs `get`, `list` and `watch` access to the `ingressclass` resource from the `networking.k8s.io` api group.
* The default backend configured with `--default-backend-service` does not have a fixed name `_default_backend` anymore, but instead a dynamic name based on the namespace, service name and listening port number of the target service, as any other backend. This will break configuration snippets that uses the old name.

## Contributors

* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Max Verigin ([griever989](https://github.com/griever989))
* paul ([toothbrush](https://github.com/toothbrush))
* pawelb ([pbabilas](https://github.com/pbabilas))
* Ricardo Katz ([rikatz](https://github.com/rikatz))

# v0.12.13

## Reference (r13)

* Release date: `2022-03-26`
* Helm chart: `--version 0.12.13`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.13`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.13`
* Embedded HAProxy version: `2.2.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.13`

## Release notes (r13)

This release fixes the match of the Prefix path type when the host is not declared (default host) and the pattern is a single slash. The configured service was not being selected if the incoming path doesn't finish with a slash.

Other notable changes include:

- Add compatibility with HAProxy 2.5 deployed as external/sidecar. Version 2.5 changed the lay out of the `show proc` command of the master API.
- Embedded HAProxy version was updated from 2.2.20 to 2.2.22.

## Fixes and improvements (r13)

* Add haproxy 2.5 support for external haproxy [#905](https://github.com/jcmoraisjr/haproxy-ingress/pull/905) (jcmoraisjr)
* Fix match of prefix pathtype if using default host [#908](https://github.com/jcmoraisjr/haproxy-ingress/pull/908) (jcmoraisjr)
* Remove initial whitespaces from haproxy template [#910](https://github.com/jcmoraisjr/haproxy-ingress/pull/910) (ironashram)
* update embedded haproxy from 2.2.20 to 2.2.22 [7270300](https://github.com/jcmoraisjr/haproxy-ingress/commit/7270300c92d93e8a233c8f572cc64263429fb279) (Joao Morais)

# v0.12.12

## Reference (r12)

* Release date: `2022-01-22`
* Helm chart: `--version 0.12.12`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.12`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.12`
* Embedded HAProxy version: `2.2.20`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.12`

## Release notes (r12)

This release fixes backend configuration snippets with blank lines. Such blank lines were being rejected due to a wrong parsing of a missing `--disable-config-keywords` command-line option.

Besides that, a few other improvements were made:

- All `var()` sample fetch now have the `-m str` match method. This fixes compatibility with HAProxy 2.5, which now enforces a match method when using `var()`. This however isn't enough to use HAProxy 2.5 as an external HAProxy due to incompatibility changes made in the master socket responses, hence the update in the [supported HAProxy versions](https://github.com/jcmoraisjr/haproxy-ingress/#use-haproxy-ingress). A future HAProxy Ingress release will make v0.12 and v0.13 branches compatible with HAProxy 2.5.
- Embedded HAProxy was updated from 2.2.19 to 2.2.20.

## Fixes and improvements (r12)

* Add disableKeywords only if defined [#876](https://github.com/jcmoraisjr/haproxy-ingress/pull/876) (jcmoraisjr)
* Add match method on all var() sample fetch method [#879](https://github.com/jcmoraisjr/haproxy-ingress/pull/879) (jcmoraisjr)
* update embedded haproxy from 2.2.19 to 2.2.20 [72dabd4](https://github.com/jcmoraisjr/haproxy-ingress/commit/72dabd4de200da9a71c3d66dd56865acafa03849) (Joao Morais)

# v0.12.11

## Reference (r11)

* Release date: `2021-12-25`
* Helm chart: `--version 0.12.11`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.11`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.11`
* Embedded HAProxy version: `2.2.19`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.11`

## Release notes (r11)

This release fixes an error message if the controller doesn't have permission to update a secret. The update is needed when the embedded acme signer is used. Before this update, a missing permission would fail the update of the secret without notifying the failure in the logs.

Also, the embedded HAProxy version was updated to 2.2.19, and client-go was updated to v0.19.16.

## Fixes and improvements (r11)

Fixes and improvements since `v0.12.10`:

* Fix error message on secret/cm update failure [#863](https://github.com/jcmoraisjr/haproxy-ingress/pull/863) (jcmoraisjr)
* update embedded haproxy from 2.2.17 to 2.2.19 [a4aa3f6](https://github.com/jcmoraisjr/haproxy-ingress/commit/a4aa3f6d68dc2278a759d0dd859471138775923a) (Joao Morais)
* update client-go from v0.19.14 to v0.19.16 [8d19d40](https://github.com/jcmoraisjr/haproxy-ingress/commit/8d19d406aeb61ec51ebbfe05a1c7365639234344) (Joao Morais)

# v0.12.10

## Reference (r10)

* Release date: `2021-09-16`
* Helm chart: `--version 0.12.10`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.10`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.10`
* Embedded HAProxy version: `2.2.17`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.10`

## Release notes (r10)

This release fixes a regression introduced in [#820](https://github.com/jcmoraisjr/haproxy-ingress/pull/820): a globally configured config-backend snippet wasn't being applied in the final configuration. Annotation based snippets weren't impacted.

## Fixes and improvements (r10)

Fixes and improvements since `v0.12.9`:

* Fix global config-backend snippet config [#856](https://github.com/jcmoraisjr/haproxy-ingress/pull/856) (jcmoraisjr)

# v0.12.9

## Reference (r9)

* Release date: `2021-09-08`
* Helm chart: `--version 0.12.9`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.9`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.9`
* Embedded HAProxy version: `2.2.17`

## Release notes (r9)

This release updates the embedded HAProxy version from `2.2.16` to `2.2.17`, which fixes a HAProxy's vulnerability with the Content-Length HTTP header. CVE-2021-40346 was assigned. The following announce from the HAProxy's mailing list has the details and possible workaround: https://www.mail-archive.com/haproxy@formilux.org/msg41114.html

Some controller issues were fixed as well:

* A misconfigured oauth (e.g. a missing service name) was allowing requests to reach the backend instead of deny the requests.
* An ingress resource configuration could not be applied if an ingress resource starts to reference a service that was already being referenced by another ingress;

## Fixes and improvements (r9)

Fixes and improvements since `v0.12.8`:

* always deny requests if oauth is misconfigured (#843) [c075258](https://github.com/jcmoraisjr/haproxy-ingress/commit/c075258b962cc94bba9d298279d696a314f54771) (Joao Morais)
* fix ingress update to an existing backend [8119212](https://github.com/jcmoraisjr/haproxy-ingress/commit/81192120e1c600096ddca5883d6e5d99baad93e4) (Joao Morais)
* update embedded haproxy from 2.2.16 to 2.2.17 [ac9ccf0](https://github.com/jcmoraisjr/haproxy-ingress/commit/ac9ccf0307736391f9fbfb28d3de15ef3540ca0b) (Joao Morais)
* update client-go from v0.19.13 to v0.19.14 [6dd9de1](https://github.com/jcmoraisjr/haproxy-ingress/commit/6dd9de11cdc22e891d759b2ddebe3427242f67b0) (Joao Morais)

# v0.12.8

## Reference (r8)

* Release date: `2021-08-17`
* Helm chart: `--version 0.12.8`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.8`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.8`
* Embedded HAProxy version: `2.2.16`

## Release notes (r8)

This release updates the embedded HAProxy version from `2.2.15` to `2.2.16`, which fixes some HAProxy's HTTP/2 vulnerabilities. A malicious request can abuse the H2 `:method` pseudo-header to forge malformed HTTP/1 requests, which can be accepted by some vulnerable backend servers. The following announce from the HAProxy's mailing list has the details: https://www.mail-archive.com/haproxy@formilux.org/msg41041.html

## Fixes and improvements (r8)

Fixes and improvements since `v0.12.7`:

* update embedded haproxy from 2.2.15 to 2.2.16 [dd07840](https://github.com/jcmoraisjr/haproxy-ingress/commit/dd07840794463dde8e190c5677ebacebdafd2e4e) (Joao Morais)

# v0.12.7

## Reference (r7)

* Release date: `2021-08-10`
* Helm chart: `--version 0.12.7`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.7`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.7`
* Embedded HAProxy version: `2.2.15`

## Release notes (r7)

This release fixes a failure in the synchronization between the in memory HAProxy model and the state of the running HAProxy instance. The internal model reflects how HAProxy should be configured based on ingress resources. The states can be out of sync when new empty slots are added to backends that wasn't in edit state, and only affects sharded backends (`--backend-shards` > 0).

The embedded HAProxy version was updated from `2.2.14` to `2.2.15`.

## Fixes and improvements (r7)

Fixes and improvements since `v0.12.6`:

* Fix change notification of backend shard [#835](https://github.com/jcmoraisjr/haproxy-ingress/pull/835) (jcmoraisjr)
* update embedded haproxy from 2.2.14 to 2.2.15 [ab0566b](https://github.com/jcmoraisjr/haproxy-ingress/commit/ab0566ba0b94b45d6aebd30dc4febb81cb8bcaaf) (Joao Morais)
* update client-go from v0.19.12 to v0.19.13 [c94936c](https://github.com/jcmoraisjr/haproxy-ingress/commit/c94936cda337562f59793dddcfa43ca3646c72af) (Joao Morais)

# v0.12.6

## Reference (r6)

* Release date: `2021-07-11`
* Helm chart: `--version 0.12.6`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.6`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.6`
* Embedded HAProxy version: `2.2.14`

## Release notes (r6)

This release improves the synchronization between HAProxy state and the in memory model that reflects that state. The controller used to trust that a state change sent to the admin socket is properly applied. Now every HAProxy response is parsed and the controller will enforce a reload if it doesn’t recognize the change as a valid one.

Some new security options were added as well: `--disable-external-name` can be used to not allow backend server discovery using an external domain, and `--disable-config-keywords` can be used to partially or completely disable configuration snippets via ingress or service annotations.

A warning will be emitted if the configured global ConfigMap does not exist. This used to be ignored, and v0.12 will only log this misconfiguration to preserve backward compatibility.

Paul improved the command-line documentation, adding some undocumented options that the controller supports.

## Fixes and improvements (r6)

Fixes and improvements since `v0.12.5`:

* Ensure that configured global ConfigMap exists [#804](https://github.com/jcmoraisjr/haproxy-ingress/pull/804) (jcmoraisjr)
* Reload haproxy if a backend server cannot be found [#810](https://github.com/jcmoraisjr/haproxy-ingress/pull/810) (jcmoraisjr)
* Add disable-external-name command-line option [#816](https://github.com/jcmoraisjr/haproxy-ingress/pull/816) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/command-line/#disable-external-name)
  * Command-line options:
    * `--disable-external-name`
* docs: Add all command-line options to list. [#806](https://github.com/jcmoraisjr/haproxy-ingress/pull/806) (toothbrush)
* Add disable-config-keywords command-line options [#820](https://github.com/jcmoraisjr/haproxy-ingress/pull/820) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/command-line/#disable-config-keywords)
  * Command-line options:
    * `--disable-config-keywords`
* docs: update haproxy doc link to 2.2 [986d754](https://github.com/jcmoraisjr/haproxy-ingress/commit/986d75427fe0966de92e7625887456cd44ef77f7) (Joao Morais)
* build: remove travis-ci configs [0d134de](https://github.com/jcmoraisjr/haproxy-ingress/commit/0d134de09a636673bd67d1b5750759edd5dbbe85) (Joao Morais)
* update client-go from 0.19.11 to 0.19.12 [aee8cd2](https://github.com/jcmoraisjr/haproxy-ingress/commit/aee8cd2b4a046488a7cd07c8a42061f8154f96c3) (Joao Morais)

# v0.12.5

## Reference (r5)

* Release date: `2021-06-20`
* Helm chart: `--version 0.12.5`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.5`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.5`
* Embedded HAProxy version: `2.2.14`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.5`

## Fixes and improvements (r5)

Fixes and improvements since `v0.12.4`:

* Fix backend match if no ingress use host match [#802](https://github.com/jcmoraisjr/haproxy-ingress/pull/802) (jcmoraisjr)

# v0.12.4

## Reference (r4)

* Release date: `2021-06-17`
* Helm chart: `--version 0.12.4`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.4`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.4`
* Embedded HAProxy version: `2.2.14`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.4`

## Fixes and improvements (r4)

Fixes and improvements since `v0.12.3`:

* Fix reading of needFullSync status [#772](https://github.com/jcmoraisjr/haproxy-ingress/pull/772) (jcmoraisjr)
* Fix per path filter of default host rules [#777](https://github.com/jcmoraisjr/haproxy-ingress/pull/777) (jcmoraisjr)
* Add option to disable API server warnings [#789](https://github.com/jcmoraisjr/haproxy-ingress/pull/789) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/command-line/#disable-api-warnings)
  * Command-line options:
    * `--disable-api-warnings`
* Fix domain validation on secure backend keys [#791](https://github.com/jcmoraisjr/haproxy-ingress/pull/791) (jcmoraisjr)
* Add ssl-always-add-https config key [#793](https://github.com/jcmoraisjr/haproxy-ingress/pull/793) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#ssl-always-add-https)
  * Configuration keys:
    * `ssl-always-add-https`
* Use the port name on DNS resolver template [#796](https://github.com/jcmoraisjr/haproxy-ingress/pull/796) (jcmoraisjr)
* Fix reading of tls secret without crt or key [#799](https://github.com/jcmoraisjr/haproxy-ingress/pull/799) (jcmoraisjr)
* update embedded haproxy from 2.2.13 to 2.2.14 [aa0a234](https://github.com/jcmoraisjr/haproxy-ingress/commit/aa0a234523cad45ca0432f8036f2bff704143d63) (Joao Morais)
* update client-go from 0.19.0 to 0.19.11 [b0b30c8](https://github.com/jcmoraisjr/haproxy-ingress/commit/b0b30c8aa80c621a55bf11fc6bdaf98dcdd84d80) (Joao Morais)

## Other

* build: move from travis to github actions [1e137dc](https://github.com/jcmoraisjr/haproxy-ingress/commit/1e137dc982f87e9d9f18cf1b25615768ee432ed0) (Joao Morais)

# v0.12.3

## Reference (r3)

* Release date: `2021-04-16`
* Helm chart: `--version 0.12.3`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.3`
* Embedded HAProxy version: `2.2.13`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.3`

## Fixes and improvements (r3)

Fixes and improvements since `v0.12.2`:

* Fix default host if configured as ssl-passthrough [#764](https://github.com/jcmoraisjr/haproxy-ingress/pull/764) (jcmoraisjr)
* Update embedded haproxy from 2.2.11 to 2.2.13 [7394764](https://github.com/jcmoraisjr/haproxy-ingress/commit/7394764e2c912af065b4d824a6057fe17d488555) (Joao Morais)

# v0.12.2

## Reference (r2)

* Release date: `2021-03-27`
* Helm chart: `--version 0.12.2`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.2`
* Embedded HAProxy version: `2.2.11`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.2`

## Fixes and improvements (r2)

Fixes and improvements since `v0.12.1`:

* Fix incorrect reload if endpoint list grows [#746](https://github.com/jcmoraisjr/haproxy-ingress/pull/746) (jcmoraisjr)
* Fix prefix path type if the path matches a domain [#756](https://github.com/jcmoraisjr/haproxy-ingress/pull/756) (jcmoraisjr)
* Update go from 1.14.(latest) to 1.14.15 [0ad978d](https://github.com/jcmoraisjr/haproxy-ingress/commit/0ad978d209ada9bc38e3b7fcd6d961be1c32d2f3) (Joao Morais)
* Update embedded haproxy from 2.2.9 to 2.2.11 and fixes CVE-2021-3450 (OpenSSL). [9d12c69](https://github.com/jcmoraisjr/haproxy-ingress/commit/9d12c694ad1629a78021c1a48825172ab64f5a34) (Joao Morais)

# v0.12.1

## Reference (r1)

* Release date: `2021-02-28`
* Helm chart: `--version 0.12.1`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12.1`
* Embedded HAProxy version: `2.2.9`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12.1`

## Fixes and improvements (r1)

Fixes and improvements since `v0.12`:

* Improve crt validation with ssl_c_verify [#743](https://github.com/jcmoraisjr/haproxy-ingress/pull/743) (jcmoraisjr)
* Remove unix socket before start acme server [#740](https://github.com/jcmoraisjr/haproxy-ingress/pull/740) (jcmoraisjr)
* Read the whole input when the response fills the buffer [#739](https://github.com/jcmoraisjr/haproxy-ingress/pull/739) (jcmoraisjr)
* Fix initial weight configuration [#742](https://github.com/jcmoraisjr/haproxy-ingress/pull/742) (jcmoraisjr)

# v0.12

## Reference (r0)

* Release date: `2021-02-19`
* Helm chart: `--version 0.12.0`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12`
* Embedded HAProxy version: `2.2.9`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12`

## Fixes and improvements (r0)

Fixes and improvements since `v0.12-beta.2`:

* Add support for native redirection of default backend [#731](https://github.com/jcmoraisjr/haproxy-ingress/pull/731) (rikatz) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#default-redirect)
  * Configuration keys:
    * `default-backend-redirect`
    * `default-backend-redirect-code`
* Fix shrinking of prioritized paths [#736](https://github.com/jcmoraisjr/haproxy-ingress/pull/736) (jcmoraisjr)
* Update haproxy from 2.2.8 to 2.2.9 [a84aaa8](https://github.com/jcmoraisjr/haproxy-ingress/commit/a84aaa8121eae5b9a129a437ca90392a10432761) (Joao Morais)

# v0.12-beta.2

## Reference (b2)

* Release date: `2021-02-02`
* Helm chart: `--version 0.12.0-beta.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12-beta.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12-beta.2`
* Embedded HAProxy version: `2.2.8`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12-beta.2`

## Fixes and improvements (b2)

Fixes and improvements since `v0.12-beta.1`

* Use field converter to remove port from hdr host [#729](https://github.com/jcmoraisjr/haproxy-ingress/pull/729) (jcmoraisjr)
* Add sni and verifyhost to secure connections [#730](https://github.com/jcmoraisjr/haproxy-ingress/pull/730) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#secure-backend)
  * Configuration keys:
    * `secure-sni`
    * `secure-verify-hostname`
* Fix path precedence of distinct match types [#728](https://github.com/jcmoraisjr/haproxy-ingress/pull/728) (jcmoraisjr)

# v0.12-beta.1

## Reference (b1)

* Release date: `2021-01-17`
* Helm chart: `--version 0.12.0-beta.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12-beta.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12-beta.1`
* Embedded HAProxy version: `2.2.8`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.12-beta.1`

## Improvements (b1)

New features and improvements since `v0.12-snapshot.3`:

* Readd haproxy user in the docker image [#718](https://github.com/jcmoraisjr/haproxy-ingress/pull/718) (jcmoraisjr)
* Create state file only if load-server-state is enabled [#721](https://github.com/jcmoraisjr/haproxy-ingress/pull/721) (jcmoraisjr)
* Add deny access list and exception ip/cidr [#722](https://github.com/jcmoraisjr/haproxy-ingress/pull/722) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#allowlist)
  * Configuration keys:
    * `allowlist-source-range`
    * `denylist-source-range`
* Update embedded haproxy from 2.2.6 to 2.2.8 [ba3f80b](https://github.com/jcmoraisjr/haproxy-ingress/commit/ba3f80bdde3fd6dfcfc5c8a26166255dad49cd39) (Joao Morais)

## Fixes (b1)

* Fix reload failure if admin socket refuses connection [#719](https://github.com/jcmoraisjr/haproxy-ingress/pull/719) (jcmoraisjr)
* Clear the crt expire gauge when full sync [#717](https://github.com/jcmoraisjr/haproxy-ingress/pull/717) (jcmoraisjr)
* Fix first conciliation if external haproxy is not running [#720](https://github.com/jcmoraisjr/haproxy-ingress/pull/720) (jcmoraisjr)

## Docs

* Fix prometheus config [#723](https://github.com/jcmoraisjr/haproxy-ingress/pull/723) (jcmoraisjr)

# v0.12-snapshot.3

## Reference (s3)

* Release date: `2020-12-13`
* Helm chart: `--version 0.12.0-snapshot.3 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12-snapshot.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12-snapshot.3`
* Embedded HAProxy version: `2.2.6`

## Improvements (s3)

New features and improvements since `v0.12-snapshot.2`:

* Add SameSite cookie attribute [#707](https://github.com/jcmoraisjr/haproxy-ingress/pull/707) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#affinity)
  * Configuration keys:
    * `session-cookie-same-site`
* Independently configure rules and TLS [#702](https://github.com/jcmoraisjr/haproxy-ingress/pull/702) (jcmoraisjr)
* Change oauth2 to path scope [#704](https://github.com/jcmoraisjr/haproxy-ingress/pull/704) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#oauth)
* Update haproxy from 2.2.5 to 2.2.6 [b34edd0](https://github.com/jcmoraisjr/haproxy-ingress/commit/b34edd0dfb3bcf08552885df4d8904973bb8a2dc) (Joao Morais)

## Fixes (s3)

* Use default certificate only if provided SNI isn't found [#700](https://github.com/jcmoraisjr/haproxy-ingress/pull/700) (jcmoraisjr)
* Only notifies ConfigMap updates if data changes [#703](https://github.com/jcmoraisjr/haproxy-ingress/pull/703) (jcmoraisjr)

## Docs

* Add path scope [#705](https://github.com/jcmoraisjr/haproxy-ingress/pull/705) (jcmoraisjr)

# v0.12-snapshot.2

## Reference (s2)

* Release date: `2020-11-18`
* Helm chart: `--version 0.12.0-snapshot.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12-snapshot.2`
* Embedded HAProxy version: `2.2.5`

## Improvements (s2)

New features and improvements since `v0.12-snapshot.1`:

* Update go from 1.14.8 to 1.14.(latest) [3c8b444](https://github.com/jcmoraisjr/haproxy-ingress/commit/3c8b4440a64b474ee715c79e4d5b25393cdc8d24) (Joao Morais)
* Add worker-max-reloads config option [#692](https://github.com/jcmoraisjr/haproxy-ingress/pull/692) (jcmoraisjr)
  * Configuration keys:
    * `worker-max-reloads` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#master-worker)
* Update haproxy from 2.2.4 to 2.2.5 [ac87843](https://github.com/jcmoraisjr/haproxy-ingress/commit/ac87843513b1a8ea304179082737eee9baa61eed) (Joao Morais)
* Add ingress class support [#694](https://github.com/jcmoraisjr/haproxy-ingress/pull/694) (jcmoraisjr)
  * Configuration keys:
    * Class matter, Strategies and Scope sections of the Configuration keys [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/)
  * Command-line options:
    * `--controller-class` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/command-line/#ingress-class)
    * `--watch-ingress-without-class` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/command-line/#ingress-class)

## Fixes (s2)

* Fix line too long on backend parsing [#683](https://github.com/jcmoraisjr/haproxy-ingress/pull/683) (jcmoraisjr)
* Fix basic auth backend tracking [#688](https://github.com/jcmoraisjr/haproxy-ingress/pull/688) (jcmoraisjr)
* Allow signer to work with wildcard dns certs [#695](https://github.com/jcmoraisjr/haproxy-ingress/pull/695) (pbabilas)
* Improve certificate validation of acme signer [#689](https://github.com/jcmoraisjr/haproxy-ingress/pull/689) (jcmoraisjr)

# v0.12-snapshot.1

## Reference (s1)

* Release date: `2020-10-20`
* Helm chart: `--version 0.12.0-snapshot.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.12-snapshot.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.12-snapshot.1`
* Embedded HAProxy version: `2.2.4`

## Improvements (s1)

New features and improvements since `v0.11-beta.1`:

* Update to go1.14.8 [#659](https://github.com/jcmoraisjr/haproxy-ingress/pull/659) (jcmoraisjr)
* Update to client-go v0.19.0 [#660](https://github.com/jcmoraisjr/haproxy-ingress/pull/660) (jcmoraisjr)
* Update to haproxy 2.2.3 [#661](https://github.com/jcmoraisjr/haproxy-ingress/pull/661) (jcmoraisjr)
* Add path-type-order global config [#662](https://github.com/jcmoraisjr/haproxy-ingress/pull/662) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#path-type)
  * Configuration keys:
    * `path-type-order`
* Add better handling for cookie affinity with preserve option [#667](https://github.com/jcmoraisjr/haproxy-ingress/pull/667) (griever989) - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#affinity)
  * Configuration keys:
    * `session-cookie-preserve`
    * `session-cookie-value-strategy`
* Add abstract per path config reader [#663](https://github.com/jcmoraisjr/haproxy-ingress/pull/663) (jcmoraisjr)
* Add option to run an external haproxy instance [#666](https://github.com/jcmoraisjr/haproxy-ingress/pull/666) (jcmoraisjr)
  * Configuration keys:
    * `external-has-lua` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#external)
    * `groupname` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#security)
    * `master-exit-on-failure` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#master-worker)
    * `username` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/keys/#security)
  * Command-line options:
    * `--master-socket` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/command-line/#master-socket)
* Convert ssl-redirect to the new per path config [#670](https://github.com/jcmoraisjr/haproxy-ingress/pull/670) (jcmoraisjr)
* Add --sort-endpoints-by command-line option [#678](https://github.com/jcmoraisjr/haproxy-ingress/pull/678) (jcmoraisjr)
  * Configuration keys:
    * `--sort-endpoints-by` - [doc](https://haproxy-ingress.github.io/v0.12/docs/configuration/command-line/#sort-endpoints-by)
* Update embedded haproxy to 2.2.4 [4ff2f55](https://github.com/jcmoraisjr/haproxy-ingress/commit/4ff2f550acb3e6e0975457cb89c381452edde228) (Joao Morais)
* Configure default backend to not change backend ID [#681](https://github.com/jcmoraisjr/haproxy-ingress/pull/681) (jcmoraisjr)

## Fixes (s1)

* Fix rewrite target match [#668](https://github.com/jcmoraisjr/haproxy-ingress/pull/668) (jcmoraisjr)
* Log socket response only if message is not empty [#675](https://github.com/jcmoraisjr/haproxy-ingress/pull/675) (jcmoraisjr)
* Improve old and new backend comparison [#676](https://github.com/jcmoraisjr/haproxy-ingress/pull/676) (jcmoraisjr)
* Implement sort-backends [#677](https://github.com/jcmoraisjr/haproxy-ingress/pull/677) (jcmoraisjr)
* Fix dynamic update of the default backend [#680](https://github.com/jcmoraisjr/haproxy-ingress/pull/680) (jcmoraisjr)

## Other

* Adds a GH Action to close stale issues [#615](https://github.com/jcmoraisjr/haproxy-ingress/pull/615) (rikatz)
