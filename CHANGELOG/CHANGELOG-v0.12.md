# CHANGELOG v0.12 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.11!](#upgrade-notes)
* [Contributors](#contributors)
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
* pawelb ([pbabilas](https://github.com/pbabilas))
* Ricardo Katz ([rikatz](https://github.com/rikatz))

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
