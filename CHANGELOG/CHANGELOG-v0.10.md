# CHANGELOG v0.10 branch

* [Major improvements](#major-improvements)
* [Contributors](#contributors)
* [v0.10.14](#v01014)
  * [Reference](#reference-r14)
  * [Release notes](#release-notes-r14)
  * [Fixes and improvements](#fixes-and-improvements-r14)
* [v0.10.13](#v01013)
  * [Reference](#reference-r13)
  * [Release notes](#release-notes-r13)
  * [Fixes and improvements](#fixes-and-improvements-r13)
* [v0.10.12](#v01012)
  * [Reference](#reference-r12)
  * [Release notes](#release-notes-r12)
  * [Fixes and improvements](#fixes-and-improvements-r12)
* [v0.10.11](#v01011)
  * [Reference](#reference-r11)
  * [Release notes](#release-notes-r11)
  * [Fixes and improvements](#fixes-and-improvements-r11)
* [v0.10.10](#v01010)
  * [Reference](#reference-r10)
  * [Release notes](#release-notes-r10)
  * [Fixes and improvements](#fixes-and-improvements-r10)
* [v0.10.9](#v0109)
  * [Reference](#reference-r9)
  * [Release notes](#release-notes-r9)
  * [Fixes and improvements](#fixes-and-improvements-r9)
* [v0.10.8](#v0108)
  * [Reference](#reference-r8)
  * [Fixes and improvements](#fixes-and-improvements-r8)
* [v0.10.7](#v0107)
  * [Reference](#reference-r7)
  * [Fixes and improvements](#fixes-and-improvements-r7)
* [v0.10.6](#v0106)
  * [Reference](#reference-r6)
  * [Fixes and improvements](#fixes-and-improvements-r6)
* [v0.10.5](#v0105)
  * [Reference](#reference-r5)
  * [Fixes and improvements](#fixes-and-improvements-r5)
* [v0.10.4](#v0104)
  * [Reference](#reference-r4)
  * [Fixes and improvements](#fixes-and-improvements-r4)
* [v0.10.3](#v0103)
  * [Reference](#reference-r3)
  * [Fixes and improvements](#fixes-and-improvements-r3)
* [v0.10.2](#v0102)
  * [Reference](#reference-r2)
  * [Fixes and improvements](#fixes-and-improvements-r2)
* [v0.10.1](#v0101)
  * [Reference](#reference-r1)
  * [Fixes and improvements](#fixes-and-improvements-r1)
* [v0.10](#v010)
  * [Reference](#reference-r0)
  * [Fixes and improvements](#fixes-and-improvements-r0)
* [v0.10-beta.3](#v010-beta3)
  * [Reference](#reference-b3)
  * [Fixes and improvements](#fixes-and-improvements-b3)
* [v0.10-beta.2](#v010-beta2)
  * [Reference](#reference-b2)
  * [Fixes and improvements](#fixes-and-improvements-b2)
* [v0.10-beta.1](#v010-beta1)
  * [Reference](#reference-b1)
  * [Improvements](#improvements-b1)
  * [Fixes](#fixes-b1)
* [v0.10-snapshot.5](#v010-snapshot5)
  * [Reference](#reference-s5)
  * [Improvements](#improvements-s5)
* [v0.10-snapshot.4](#v010-snapshot4)
  * [Reference](#reference-s4)
  * [Improvements](#improvements-s4)
  * [Fixes](#fixes-s4)
* [v0.10-snapshot.3](#v010-snapshot3)
  * [Reference](#reference-s3)
  * [Improvements](#improvements-s3)
* [v0.10-snapshot.2](#v010-snapshot2)
  * [Reference](#reference-s2)
  * [Improvements](#improvements-s2)
* [v0.10-snapshot.1](#v010-snapshot1)
  * [Reference](#reference-s1)
  * [Improvements](#improvements-s1)

## Major improvements

Highlights of this version:

* HAProxy upgrade from 1.9 to 2.0
* Metrics:
  * HAProxy's internal Prometheus exporter, see the [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#bind-port)
  * HAProxy Ingress exporter for Prometheus
  * HAProxy Ingress dashboard for Grafana, see the [metrics example](https://haproxy-ingress.github.io/v0.10/docs/examples/metrics/)

## Contributors

* Alexis Dufour ([AlexisDuf](https://github.com/AlexisDuf))
* Anton Carlos ([antcs](https://github.com/antcs))
* Colin Deasy ([coldeasy](https://github.com/coldeasy))
* Eliot Hautefeuille ([hileef](https://github.com/hileef))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* KKlapper ([KKlapper](https://github.com/KKlapper))
* pawelb ([pbabilas](https://github.com/pbabilas))
* Robert Agbozo ([RobertTheProfessional](https://github.com/RobertTheProfessional))
* Sankul ([dark-shade](https://github.com/dark-shade))
* Tadeu Andrade ([mtatheonly](https://github.com/mtatheonly))

# v0.10.14

## Reference (r14)

* Release date: `2022-03-26`
* Helm chart: `--version 0.10.14`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.14`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.14`
* Embedded HAProxy version: `2.0.28`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.14`

## Release notes (r14)

This release fixes backend configuration snippets with blank lines. Such blank lines were being rejected due to a wrong parsing of a missing `--disable-config-keywords` command-line option.

Also, the embedded HAProxy version was updated from 2.0.26 to 2.0.28.

## Fixes and improvements (r14)

Fixes and improvements since `v0.10.13`:

* Add disableKeywords only if defined [#876](https://github.com/jcmoraisjr/haproxy-ingress/pull/876) (jcmoraisjr)
* Remove initial whitespaces from haproxy template [#910](https://github.com/jcmoraisjr/haproxy-ingress/pull/910) (ironashram)
* update embedded haproxy from 2.0.26 to 2.0.28 [97f105c](https://github.com/jcmoraisjr/haproxy-ingress/commit/97f105c908149d642af80432e916697b3234a234) (Joao Morais)

# v0.10.13

## Reference (r13)

* Release date: `2021-12-25`
* Helm chart: `--version 0.10.13`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.13`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.13`
* Embedded HAProxy version: `2.0.26`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.13`

## Release notes (r13)

This release updates embedded HAProxy from 2.0.25 to 2.0.26.

## Fixes and improvements (r13)

Fixes and improvements since `v0.10.12`:

* update embedded haproxy from 2.0.25 to 2.0.26 [e107144](https://github.com/jcmoraisjr/haproxy-ingress/commit/e107144853191e5290f3f28a99ed9aedf383ea2c) (Joao Morais)

# v0.10.12

## Reference (r12)

* Release date: `2021-09-16`
* Helm chart: `--version 0.10.12`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.12`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.12`
* Embedded HAProxy version: `2.0.25`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.12`

## Release notes (r12)

This release fixes a regression introduced in [#820](https://github.com/jcmoraisjr/haproxy-ingress/pull/820): a globally configured config-backend snippet wasn't being applied in the final configuration. Annotation based snippets weren't impacted.

## Fixes and improvements (r12)

Fixes and improvements since `v0.10.11`:

* Fix global config-backend snippet config [#856](https://github.com/jcmoraisjr/haproxy-ingress/pull/856) (jcmoraisjr)

# v0.10.11

## Reference (r11)

* Release date: `2021-09-08`
* Helm chart: `--version 0.10.11`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.11`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.11`
* Embedded HAProxy version: `2.0.25`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.11`

## Release notes (r11)

This release updates the embedded HAProxy version from `2.0.24` to `2.0.25`, which fixes a HAProxy's vulnerability with the Content-Length HTTP header. CVE-2021-40346 was assigned. The following announce from the HAProxy's mailing list has the details and possible workaround: https://www.mail-archive.com/haproxy@formilux.org/msg41114.html

Also, a misconfigured oauth (e.g. a missing service name) was allowing requests to reach the backend instead of deny the requests.

## Fixes and improvements (r11)

Fixes and improvements since `v0.10.10`:

* always deny requests if oauth is misconfigured [1ff88ec](https://github.com/jcmoraisjr/haproxy-ingress/commit/1ff88ecf02cfb5a7c20e1a913d65bfa5931280cf) (Joao Morais)
* update embedded haproxy from 2.0.24 to 2.0.25 [01631b4](https://github.com/jcmoraisjr/haproxy-ingress/commit/01631b44bf1e98e83311dabcde5482932e81817f) (Joao Morais)

# v0.10.10

## Reference (r10)

* Release date: `2021-08-17`
* Helm chart: `--version 0.10.10`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.10`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.10`
* Embedded HAProxy version: `2.0.24`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.10`

## Release notes (r10)

This release updates the embedded HAProxy version from `2.0.22` to `2.0.24`, which fixes some HAProxy's HTTP/2 vulnerabilities. A malicious request can abuse the H2 `:method` pseudo-header to forge malformed HTTP/1 requests, which can be accepted by some vulnerable backend servers. The following announce from the HAProxy's mailing list has the details: https://www.mail-archive.com/haproxy@formilux.org/msg41041.html

## Fixes and improvements (r10)

Fixes and improvements since `v0.10.9`:

* update embedded haproxy from 2.0.22 to 2.0.24 [1a44f00](https://github.com/jcmoraisjr/haproxy-ingress/commit/1a44f00195be951fa55d988517684417fe6622ea) (Joao Morais)

# v0.10.9

## Reference (r9)

* Release date: `2021-07-11`
* Helm chart: `--version 0.10.9`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.9`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.9`
* Embedded HAProxy version: `2.0.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.9`

## Release notes (r9)

This release adds some security options: `--disable-external-name` can be used to not allow backend server discovery using an external domain; `--disable-config-keywords` can be used to partially or completely disable configuration snippets via ingress or service annotations.

Also, a warning will be emitted if the configured global ConfigMap does not exist.

There is no urge to update, except if some of the new options seem useful.

## Fixes and improvements (r9)

Fixes and improvements since `v0.10.8`:

* Ensure that configured global ConfigMap exists [#804](https://github.com/jcmoraisjr/haproxy-ingress/pull/804) (jcmoraisjr)
* Add disable-external-name command-line option [#816](https://github.com/jcmoraisjr/haproxy-ingress/pull/816) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#disable-external-name)
  * Command-line options:
    * `--disable-external-name`
* Add disable-config-keywords command-line options [#820](https://github.com/jcmoraisjr/haproxy-ingress/pull/820) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#disable-config-keywords)
  * Command-line options:
    * `--disable-config-keywords`
* build: remove travis-ci configs [8c7fc79](https://github.com/jcmoraisjr/haproxy-ingress/commit/8c7fc794ef20a87da86bbfe80f61b7d864580c04) (Joao Morais)

# v0.10.8

## Reference (r8)

* Release date: `2021-06-20`
* Helm chart: `--version 0.10.8`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.8`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.8`
* Embedded HAProxy version: `2.0.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.8`

## Fixes and improvements (r8)

Fixes and improvements since `v0.10.7`:

* Use the port name on DNS resolver template [#796](https://github.com/jcmoraisjr/haproxy-ingress/pull/796) (jcmoraisjr)
* Fix reading of tls secret without crt or key [#799](https://github.com/jcmoraisjr/haproxy-ingress/pull/799) (jcmoraisjr)
* build: move from travis to github actions [7a81577](https://github.com/jcmoraisjr/haproxy-ingress/commit/7a8157753ff7842b4757f81c9c91ba261f5c77e7) (Joao Morais)

# v0.10.7

## Reference (r7)

* Release date: `2021-04-16`
* Helm chart: `--version 0.10.7`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.7`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.7`
* Embedded HAProxy version: `2.0.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.7`

## Fixes and improvements (r7)

Fixes and improvements since `v0.10.6`:

* Fix default host if configured as ssl-passthrough [#764](https://github.com/jcmoraisjr/haproxy-ingress/pull/764) (jcmoraisjr)
* Update embedded haproxy from 2.0.21 to 2.0.22 [9a57a6c](https://github.com/jcmoraisjr/haproxy-ingress/commit/9a57a6ce0cb9763284c837b4f17c4891dff74509) (Joao Morais)

# v0.10.6

## Reference (r6)

* Release date: `2021-03-27`
* Helm chart: `--version 0.10.6`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.6`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.6`
* Embedded HAProxy version: `2.0.21`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.6`

## Fixes and improvements (r6)

Fixes and improvements since `v0.10.5`:

* Fix incorrect reload if endpoint list grows [#746](https://github.com/jcmoraisjr/haproxy-ingress/pull/746) (jcmoraisjr)
* Fix backend matches if hostname uses wildcard [#752](https://github.com/jcmoraisjr/haproxy-ingress/pull/752) (jcmoraisjr)
* Update haproxy from 2.0.20 to 2.0.21 and fixes CVE-2021-3450 (OpenSSL). [01708b9](https://github.com/jcmoraisjr/haproxy-ingress/commit/01708b909869861b385a922403844d2e6e857a6d) (Joao Morais)
* Update go from 1.13.4 to 1.13.15 [5bd13b6](https://github.com/jcmoraisjr/haproxy-ingress/commit/5bd13b66e25cc65c6ef602676da6e3dea62826c9) (Joao Morais)

# v0.10.5

## Reference (r5)

* Release date: `2021-02-28`
* Helm chart: `--version 0.10.5`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.5`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.5`
* Embedded HAProxy version: `2.0.20`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.5`

## Fixes and improvements (r5)

Fixes and improvements since `v0.10.4`:

* Improve crt validation with ssl_c_verify [#743](https://github.com/jcmoraisjr/haproxy-ingress/pull/743) (jcmoraisjr)
* Fix initial weight configuration [#742](https://github.com/jcmoraisjr/haproxy-ingress/pull/742) (jcmoraisjr)

# v0.10.4

## Reference (r4)

* Release date: `2021-02-03`
* Helm chart: `--version 0.10.4`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.4`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.4`
* Embedded HAProxy version: `2.0.20`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.4`

## Fixes and improvements (r4)

Fixes and improvements since `v0.10.3`:

* Fix reload failure if admin socket refuses connection [#719](https://github.com/jcmoraisjr/haproxy-ingress/pull/719) (jcmoraisjr)
* Readd haproxy user in the docker image [#718](https://github.com/jcmoraisjr/haproxy-ingress/pull/718) (jcmoraisjr)
* Update embedded haproxy to 2.0.20 [ae3cc40](https://github.com/jcmoraisjr/haproxy-ingress/commit/ae3cc4088edd321bb073e171361f7b769ca09fbd) (Joao Morais)

## Other

* Fix prometheus config [#723](https://github.com/jcmoraisjr/haproxy-ingress/pull/723) (jcmoraisjr)

# v0.10.3

## Reference (r3)

* Release date: `2020-12-13`
* Helm chart: `--version 0.10.3`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.3`
* Embedded HAProxy version: `2.0.19`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.3`

## Fixes and improvements (r3)

Fixes and improvements since `v0.10.2`:

* Use default certificate only if provided SNI isn't found [#700](https://github.com/jcmoraisjr/haproxy-ingress/pull/700) (jcmoraisjr)
* Add path scope [#705](https://github.com/jcmoraisjr/haproxy-ingress/pull/705) (jcmoraisjr)
* Fix duplication of userlist [#701](https://github.com/jcmoraisjr/haproxy-ingress/pull/701) (jcmoraisjr)

# v0.10.2

## Reference (r2)

* Release date: `2020-11-16`
* Helm chart: `--version 0.10.2`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.2`
* Embedded HAProxy version: `2.0.19`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.2`

## Fixes and improvements (r2)

Fixes and improvements since `v0.10.1`:

* Fix line too long on backend parsing [#683](https://github.com/jcmoraisjr/haproxy-ingress/pull/683) (jcmoraisjr)
* Allow signer to work with wildcard dns certs [#695](https://github.com/jcmoraisjr/haproxy-ingress/pull/695) (pbabilas)
* Update embedded haproxy from 2.0.18 to 2.0.19 [b7b0ca9](https://github.com/jcmoraisjr/haproxy-ingress/commit/b7b0ca9961da9f0896ee14e2e68348e5005f2a9c) (Joao Morais)

# v0.10.1

## Reference (r1)

* Release date: `2020-10-20`
* Helm chart: `--version 0.10.1`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10.1`
* Embedded HAProxy version: `2.0.18`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10.1`

## Fixes and improvements (r1)

Fixes and improvements since `v0.10`:

* Fix rewrite target match [#668](https://github.com/jcmoraisjr/haproxy-ingress/pull/668) (jcmoraisjr)
* Implement sort-backends [#677](https://github.com/jcmoraisjr/haproxy-ingress/pull/677) (jcmoraisjr)
* Update embedded haproxy to 2.0.18 [d9ac2c8](https://github.com/jcmoraisjr/haproxy-ingress/commit/d9ac2c8baffd4d1eab7a2d86180ff470c3f494a3) (Joao Morais)

# v0.10

## Reference (r0)

* Release date: `2020-09-07`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10`
* Embedded HAProxy version: `2.0.17`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10`

## Fixes and improvements (r0)

Fixes and improvements since `v0.10-beta.3`:

* `v0.10` is binary compatible with `v0.10-beta.3`.

# v0.10-beta.3

## Reference (b3)

* Release date: `2020-08-02`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-beta.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-beta.3`
* Embedded HAProxy version: `2.0.17`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10-beta.3`

## Fixes and improvements (b3)

Fixes and improvements since `v0.10-beta.2`:

* Update haproxy from 2.0.15 to 2.0.17
* Add service event handler [#633](https://github.com/jcmoraisjr/haproxy-ingress/pull/633)
* Configure default crt on ingress parsing phase [#634](https://github.com/jcmoraisjr/haproxy-ingress/pull/634)

# v0.10-beta.2

## Reference (b2)

* Release date: `2020-06-13`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-beta.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-beta.2`
* Embedded HAProxy version: `2.0.15`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10-beta.2`

## Fixes and improvements (b2)

Fixes and improvements since `v0.10-beta.1`:

* Allow overriding CPU Map [#588](https://github.com/jcmoraisjr/haproxy-ingress/pull/588) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#cpu-map)
  * Configuration keys:
    * `cpu-map`
    * `use-cpu-map`
* TCP Services : SSL : Optionally Verify Client [#589](https://github.com/jcmoraisjr/haproxy-ingress/pull/589) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#tcp-services-configmap)
* Update haproxy from 2.0.14 to 2.0.15

# v0.10-beta.1

## Reference (b1)

* Release date: `2020-05-18`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-beta.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-beta.1`
* Embedded HAProxy version: `2.0.14`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.10-beta.1`

## Improvements (b1)

New features and improvements since `v0.10-snapshot.5`:

* Add check interval on tcp service [#576](https://github.com/jcmoraisjr/haproxy-ingress/pull/576)
  * Command-line option:
    * `--tcp-services-configmap` (update) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#tcp-services-configmap)
* Add use-forwarded-proto config key [#577](https://github.com/jcmoraisjr/haproxy-ingress/pull/577)
  * Configuration keys:
    *  `use-forwarded-proto` - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#fronting-proxy-port)

## Fixes (b1)

* Fix logging messages [#559](https://github.com/jcmoraisjr/haproxy-ingress/pull/559)
* Fix server-alias on http/80 [#570](https://github.com/jcmoraisjr/haproxy-ingress/pull/570)
* Fix permission using watch-namespace [#578](https://github.com/jcmoraisjr/haproxy-ingress/pull/578)

# v0.10-snapshot.5

## Reference (s5)

* Release date: `2020-04-02`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-snapshot.5`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-snapshot.5`
* Embedded HAProxy version: `2.0.14`

## Improvements (s5)

New features and improvements since `v0.10-snapshot.4`:

* Update HAProxy from 2.0.13 to 2.0.14, which fixes CVE-2020-11100

# v0.10-snapshot.4

## Reference (s4)

* Release date: `2020-03-24`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-snapshot.4`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-snapshot.4`
* Embedded HAProxy version: `2.0.13`

## Improvements (s4)

New features and improvements since `v0.10-snapshot.3`:

* Update to haproxy 2.0.13 [#521](https://github.com/jcmoraisjr/haproxy-ingress/pull/521)
* Ignore ingresses without specified class [#527](https://github.com/jcmoraisjr/haproxy-ingress/pull/527) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#ignore-ingress-without-class)
  * Command-line options:
    * `--ignore-ingress-without-class`
* Improve certificate sign logs [#533](https://github.com/jcmoraisjr/haproxy-ingress/pull/533)
* Add cert signing metrics [#535](https://github.com/jcmoraisjr/haproxy-ingress/pull/535)
* Add buckets-response-time command-line option [#537](https://github.com/jcmoraisjr/haproxy-ingress/pull/537) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#buckets-response-time)
  * Command-line options:
    * `--buckets-response-time`
* Add external call to certificate check [#539](https://github.com/jcmoraisjr/haproxy-ingress/pull/#539) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#stats)
* docs: add crt signing metrics in the dashboard [#540](https://github.com/jcmoraisjr/haproxy-ingress/pull/#540) - [doc](https://haproxy-ingress.github.io/v0.10/docs/examples/metrics/)

## Fixes (s4)

* Fix TLS handshake on backend [#520](https://github.com/jcmoraisjr/haproxy-ingress/pull/520)
* Update crt metric if date changes [#524](https://github.com/jcmoraisjr/haproxy-ingress/pull/524)
* Clear acme work queue on stopped leading [#526](https://github.com/jcmoraisjr/haproxy-ingress/pull/526)
* Restart the leader elector when stop leading [#532](https://github.com/jcmoraisjr/haproxy-ingress/pull/532)
* Fix race on failure rate limit queue [#534](https://github.com/jcmoraisjr/haproxy-ingress/pull/534)
* Fix processing count metric name [#536](https://github.com/jcmoraisjr/haproxy-ingress/pull/536)
* Fix label naming of cert signing metric [#538](https://github.com/jcmoraisjr/haproxy-ingress/pull/#538)

# v0.10-snapshot.3

## Reference (s3)

* Release date: `2020-02-06`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-snapshot.3`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-snapshot.3`
* Embedded HAProxy version: `2.0.12`

## Improvements (s3)

New features and improvements since `v0.10-snapshot.2`:

* Sort tcp services by name and port [#506](https://github.com/jcmoraisjr/haproxy-ingress/pull/506)
* Add backend-server-naming key [#507](https://github.com/jcmoraisjr/haproxy-ingress/pull/507) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#backend-server-naming)
  * Configuration keys:
    * `backend-server-naming`
* Add ssl-redirect-code global config key [#511](https://github.com/jcmoraisjr/haproxy-ingress/pull/511) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#ssl-redirect)
  * Configuration keys:
    * `ssl-redirect-code`
* Add modsecurity timeout connect/server [#512](https://github.com/jcmoraisjr/haproxy-ingress/pull/512) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#modsecurity)
  * Configuration keys:
    * `modsecurity-timeout-connect`
    * `modsecurity-timeout-server`
* Add ssl-fingerprint-lower config key [#515](https://github.com/jcmoraisjr/haproxy-ingress/pull/515) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#auth-tls)
  * Configuration keys:
    * `ssl-fingerprint-lower`
* Remove haproxy warning filter [#514](https://github.com/jcmoraisjr/haproxy-ingress/pull/514)
* Create frontends even without ingress [#516](https://github.com/jcmoraisjr/haproxy-ingress/pull/516)
* Add auth-tls-strict configuration key [#513](https://github.com/jcmoraisjr/haproxy-ingress/pull/513) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#auth-tls)
  * Configuration keys:
    * `auth-tls-strict`
* Update to haproxy 2.0.12 [#518](https://github.com/jcmoraisjr/haproxy-ingress/pull/518)

# v0.10-snapshot.2

## Reference (s2)

* Release date: `2020-01-19`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-snapshot.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-snapshot.2`
* Embedded HAProxy version: `2.0.11`

## Improvements (s2)

New features and improvements since `v0.10-snapshot.1`:

* Change unix sockets user to haproxy [#504](https://github.com/jcmoraisjr/haproxy-ingress/pull/504)
* Add CN label in the cert_expire metric [#501](https://github.com/jcmoraisjr/haproxy-ingress/pull/501)

# v0.10-snapshot.1

## Reference (s1)

* Release date: `2019-12-30`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.10-snapshot.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.10-snapshot.1`
* Embedded HAProxy version: `2.0.11`

## Improvements (s1)

New features and improvements since `v0.9-beta.1`:

* Update to haproxy 2.0.11 [#414](https://github.com/jcmoraisjr/haproxy-ingress/pull/414)
* Remove v0.7 controller [#483](https://github.com/jcmoraisjr/haproxy-ingress/pull/483)
* Add frontend to the internal prometheus exporter [#486](https://github.com/jcmoraisjr/haproxy-ingress/pull/486)
  * Configuration keys:
    * `bind-ip-addr-prometheus` - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#bind-ip-addr)
    * `prometheus-port` - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/keys/#bind-port)
* Defaults to not create prometheus listener [#491](https://github.com/jcmoraisjr/haproxy-ingress/pull/491)
* Metric collector and exporter [#487](https://github.com/jcmoraisjr/haproxy-ingress/pull/487) - [doc](https://haproxy-ingress.github.io/v0.10/docs/configuration/command-line/#stats)
  * Command-line options:
    * `--healthz-port`
    * `--profiling`
    * `--stats-collect-processing-period`
