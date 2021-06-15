# CHANGELOG v0.13 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.12!](#upgrade-notes)
* [Contributors](#contributors)
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
* Ingress API upgrade from `networking.k8s.io/v1beta1` to `networking.k8s.io/v1`.
* Partial implementation of Gateway API - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/gateway-api/)
* TCP services using ingress resources - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#tcp-services)
* External authetication - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#auth-external)
* Several new custom configurations - [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#configuration-snippet)

## Upgrade notes

Breaking backward compatibility from v0.12

* Kubernetes minimal version changed from 1.18 to 1.19.
* External HAProxy minimal version changed from 2.0 to 2.2.
* TLS configuration: v0.12 and older versions add hostnames to the HTTP and HTTPS maps despite the TLS attribute configuration. v0.13 will only add hostnames to the HTTPS map if the Ingress' TLS attribute lists the hostname, leading to 404 errors on misconfigured clusters. This behavior can be changed with `ssl-always-add-https` as a global or per hostname configuration, see the configuration [doc](https://haproxy-ingress.github.io/v0.13/docs/configuration/keys/#ssl-always-add-https).
* OAuth2: `auth-request.lua` was updated and also the haproxy variable name with user's email address. This update will not impact if neither the Lua script nor the `oauth2-headers` configuration key were changed.
* OAuth2 with external HAProxy sidecar: the new Lua script has dependency with `lua-json4` which should be installed in the external instance.
* Basic Authentication: `auth-type` configuration key was deprecated and doesn't need to be used. This will only impact deployments that configures the `auth-secret` without configuring `auth-type` - in this scenario v0.12 won't configure Basic Authentication, but v0.13 will.
* SSL passthrough: Hostnames configured as `ssl-passthrough` will now add non root paths `/` of these hostnames to the HAProxy's HTTP port. v0.12 and older controller versions log a warning and ignore such configuration. HTTPS requests have no impact.

## Contributors

* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Ricardo Katz ([rikatz](https://github.com/rikatz))

# v0.13.0-snapshot.3

## Reference (s3)

* Release date: `2021-06-09`
* Helm chart: `--version 0.13.0-snapshot.3 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.3`
* Image (Docker): `jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.3`
* Embedded HAProxy version: `2.3.10`

## Improvements (s3)

New features and improvements:

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
* Image (Docker): `jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.2`
* Embedded HAProxy version: `2.3.10`

## Improvements (s2)

New features and improvements:

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
* Image (Docker): `jcmoraisjr/haproxy-ingress:v0.13.0-snapshot.1`
* Embedded HAProxy version: `2.3.9`

## Improvements (s1)

New features and improvements:

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

* Duplicate Travis CI to Github Actions [#732](https://github.com/jcmoraisjr/haproxy-ingress/pull/732) (rikatz)
