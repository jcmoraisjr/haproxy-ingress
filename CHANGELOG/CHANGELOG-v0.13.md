# CHANGELOG v0.13 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.12!](#upgrade-notes)
* [Contributors](#contributors)
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
* OAuth2: `auth-request.lua` was updated and also the haproxy variable name with user's email address. This update will not impact if neither the Lua script nor the `oauth2-headers` configuration key were changed.
* OAuth2 with external HAProxy sidecar: the new Lua script has dependency with `lua-json4` which should be installed in the external instance.
* Basic Authentication: `auth-type` configuration key was deprecated and doesn't need to be used. This will only impact deployments that configures the `auth-secret` without configuring `auth-type` - in this scenario v0.12 won't configure Basic Authentication, but v0.13 will.
* SSL passthrough: Hostnames configured as `ssl-passthrough` will now add non root paths `/` of these hostnames to the HAProxy's HTTP port. v0.12 and older controller versions log a warning and ignore such configuration. HTTPS requests have no impact.

## Contributors

* Andrew Rodland ([arodland](https://github.com/arodland))
* Bart Versluijs ([bartversluijs](https://github.com/bartversluijs))
* ironashram ([ironashram](https://github.com/ironashram))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Maël Valais ([maelvls](https://github.com/maelvls))
* Mateusz Kubaczyk ([mkubaczyk](https://github.com/mkubaczyk))
* Michał Zielonka ([michal800106](https://github.com/michal800106))
* Neil Seward ([sealneaward](https://github.com/sealneaward))
* paul ([toothbrush](https://github.com/toothbrush))
* Ricardo Katz ([rikatz](https://github.com/rikatz))
* Roman Gherta ([rgherta](https://github.com/rgherta))
* ssanders1449 ([ssanders1449](https://github.com/ssanders1449))
* Wojciech Chojnowski ([DCkQ6](https://github.com/DCkQ6))

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
