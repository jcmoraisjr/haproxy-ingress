# CHANGELOG v0.14 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.13!](#upgrade-notes)
* [Contributors](#contributors)
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
* Option to customize the response payload for any of the status codes managed by HAProxy or HAProxy Ingress, see the [HTTP Responses](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#http-response) configuration key documentation.
* Option to run the embedded HAProxy as Master Worker. Running HAProxy as Master Worker enables [worker-max-reloads](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#master-worker) option without the need to configure as an external deployment, enables HAProxy logging to stdout, and also has a better management of the running process. This option is not enabled by default, see the [master worker documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#master-worker) for further information.
* HAProxy Ingress can now be easily launched in the development environment with the help of the `--local-filesystem-prefix` command-line option. See also the command-line option [documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#local-filesystem-prefix) and the new `make` variables and targets in the [README](https://github.com/jcmoraisjr/haproxy-ingress/#develop-haproxy-ingress) file.

## Upgrade notes

Breaking backward compatibility from v0.13:

* Default `auth-tls-strict` configuration key value changed from `false` to `true`. This update will change the behavior of misconfigured client auth configurations: when `false` misconfigured mTLS send requests to the backend without any authentication, when `true` misconfigured mTLS will always fail the request. See also the [auth TLS documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#auth-tls).
* Default `--watch-gateway` command-line option changed from `false` to `true`. On v0.13 this option can only be enabled if the Gateway API CRDs are installed, otherwise the controller would refuse to start. Since v0.14 the controller will always check if the CRDs are installed. This will change the behavior on clusters that has Gateway API resources and doesn't declare the command-line option: v0.13 would ignore the resources and v0.14 would find and apply them. See also the [watch gateway documentation](https://haproxy-ingress.github.io/v0.14/docs/configuration/command-line/#watch-gateway).
* All the response payload managed by the controller using Lua script was rewritten in a backward compatible behavior, however deployments that overrides the `services.lua` script might break. See the [HTTP Responses](https://haproxy-ingress.github.io/v0.14/docs/configuration/keys/#http-response) documentation on how to customize HTTP responses using controller's configuration keys.

## Contributors

* Ameya Lokare ([juggernaut](https://github.com/juggernaut))
* Andrew Rodland ([arodland](https://github.com/arodland))
* ironashram ([ironashram](https://github.com/ironashram))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Maël Valais ([maelvls](https://github.com/maelvls))
* Manuel Rüger ([mrueg](https://github.com/mrueg))
* Marvin Rösch ([PaleoCrafter](https://github.com/PaleoCrafter))
* Mateusz Kubaczyk ([mkubaczyk](https://github.com/mkubaczyk))
* Michał Zielonka ([michal800106](https://github.com/michal800106))
* Neil Seward ([sealneaward](https://github.com/sealneaward))
* paul ([toothbrush](https://github.com/toothbrush))
* Roman Gherta ([rgherta](https://github.com/rgherta))
* ssanders1449 ([ssanders1449](https://github.com/ssanders1449))
* Wojciech Chojnowski ([DCkQ6](https://github.com/DCkQ6))

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
* Fix typo: s/distict/distinct [#867](https://github.com/jcmoraisjr/haproxy-ingress/pull/867) (juggernaut)
* Add disableKeywords only if defined [#876](https://github.com/jcmoraisjr/haproxy-ingress/pull/876) (jcmoraisjr)
* Add match method on all var() sample fetch method [#879](https://github.com/jcmoraisjr/haproxy-ingress/pull/879) (jcmoraisjr)
* Fix sni sample fetch on ssl decyphered tcp conns [#884](https://github.com/jcmoraisjr/haproxy-ingress/pull/884) (jcmoraisjr)
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
