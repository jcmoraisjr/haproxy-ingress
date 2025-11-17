# CHANGELOG v0.16 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.15!](#upgrade-notes)
  * [Deprecated command-line options](#deprecated-command-line-options)
* [Contributors](#contributors)
* [v0.16.0-beta.1](#v0160-beta1)
  * [Reference](#reference-b1)
  * [Release notes](#release-notes-b1)
  * [Improvements](#improvements-b1)
  * [Fixes](#fixes-b1)
* [v0.16.0-alpha.2](#v0160-alpha2)
  * [Reference](#reference-a2)
  * [Release notes](#release-notes-a2)
  * [Improvements](#improvements-a2)
  * [Fixes](#fixes-a2)
* [v0.16.0-alpha.1](#v0160-alpha1)
  * [Reference](#reference-a1)
  * [Release notes](#release-notes-a1)
  * [Improvements](#improvements-a1)
  * [Fixes](#fixes-a1)

## Major improvements

Highlights of this version:

* Embedded HAProxy version update from 2.6 to 2.8.
* FastCGI protocol support.
* Clustered metrics via peers configuration, see how it works in the [documentation](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#peers).

## Upgrade notes

Breaking backward compatibility from v0.15:

* HAProxy versions older than 2.4 are no longer supported in the External HAProxy deployment.
* Default load balance algorithm changed from Roundrobin to Random(2), see [this thread](https://www.mail-archive.com/haproxy@formilux.org/msg46011.html) regarding the rationale behind this change.

### Deprecated command-line options

The `--enable-endpointslices-api` command-line option was deprecated on v0.16 and should be removed on a future version. See its documentation at the [v0.16 documentation page](https://haproxy-ingress.github.io/v0.16/docs/configuration/command-line/#enable-endpointslices-api).

## Contributors

* Gerald Barker ([gezb](https://github.com/gezb))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Till! ([till](https://github.com/till))

# v0.16.0-beta.1

## Reference (b1)

* Release date: `2025-10-15`
* Helm chart: `--version 0.16.0-beta.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.16.0-beta.1`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.16.0-beta.1`
* Embedded HAProxy version: `2.8.16`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.16.0-beta.1`

## Release notes (b1)

This is the first beta version of the v0.16 branch. It updates the embedded haproxy version, which fixes CVE-2025-11230, see HAProxy release notes https://www.mail-archive.com/haproxy@formilux.org/msg46190.html . Other issues were also found and fixed:

- Artyom found the fronting-proxy configuration overwriting the `X-Forwarded-Proto` header when both the fronting proxy and the regular HTTP shares the same TCP port number.
- Lua response was broken if more than one custom response need to be handled to the same HTTP response code.

Changes in dependencies:

- embedded haproxy from 2.8.15 to 2.8.16
- controller-runtime from v0.22.1 to v0.22.3
- go from 1.25.1 to 1.25.3

## Improvements (b1)

New features and improvements since `v0.16.0-alpha.2`:

* Bump sigs.k8s.io/controller-runtime from 0.22.1 to 0.22.2 [#1309](https://github.com/jcmoraisjr/haproxy-ingress/pull/1309) (dependabot[bot])
* update dependencies [0613cc5](https://github.com/jcmoraisjr/haproxy-ingress/commit/0613cc5a2317bf44e84f2df783db682a5ece7890) (Joao Morais)
* Bump sigs.k8s.io/controller-runtime from 0.22.2 to 0.22.3 [#1312](https://github.com/jcmoraisjr/haproxy-ingress/pull/1312) (dependabot[bot])
* update go from 1.25.1 to 1.25.3 [1826091](https://github.com/jcmoraisjr/haproxy-ingress/commit/18260913e2fdc77ce15a19309ab4ef08458208f1) (Joao Morais)
* update embedded haproxy from 2.8.15 to 2.8.16 [d6c28b4](https://github.com/jcmoraisjr/haproxy-ingress/commit/d6c28b4966a738aa1b42000e8ba93092d36a5ef7) (Joao Morais)

## Fixes (b1)

* fix xfp header on fronting proxy shared port [#1310](https://github.com/jcmoraisjr/haproxy-ingress/pull/1310) (jcmoraisjr)
* fix lua http response having two or more options [#1311](https://github.com/jcmoraisjr/haproxy-ingress/pull/1311) (jcmoraisjr)

# v0.16.0-alpha.2

## Reference (a2)

* Release date: `2025-09-15`
* Helm chart: `--version 0.16.0-alpha.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.16.0-alpha.2`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.16.0-alpha.2`
* Embedded HAProxy version: `2.8.15`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.16.0-alpha.2`

## Release notes (a2)

This is the second and last alpha version of the v0.16 branch. All the new functionalities are already implemented, we should start the beta releases as soon as we identify this release good enough for the new phase.

See below the highlights since the first alpha version:

- Peers configuration is now backend scoped, so distinct backends can have their own stick-tables synchronized on all HAProxy instances. There is a backward incompatibility change from the alpha.1 syntax: `peers-table` now is backend scoped, so use instead `peers-table-global` if a single global one is desired. See its new documentation here: https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#peers
- Chitoku found a regression on CA secrets configured via `file://`, this syntax was not working since a change that made it possible to configure CA secrets globally.

Changes in dependencies:

- client-go from v0.33.4 to v0.34.1
- controller-runtime from v0.21.0 to v0.22.1
- go from 1.24.6 to 1.25.1

## Improvements (a2)

New features and improvements since `v0.16.0-alpha.1`:

* Bump github.com/stretchr/testify from 1.10.0 to 1.11.0 [#1296](https://github.com/jcmoraisjr/haproxy-ingress/pull/1296) (dependabot[bot])
* Bump actions/stale from 8 to 10 [#1299](https://github.com/jcmoraisjr/haproxy-ingress/pull/1299) (dependabot[bot])
* Bump actions/setup-go from 5 to 6 [#1300](https://github.com/jcmoraisjr/haproxy-ingress/pull/1300) (dependabot[bot])
* Bump golang.org/x/sync from 0.16.0 to 0.17.0 [#1302](https://github.com/jcmoraisjr/haproxy-ingress/pull/1302) (dependabot[bot])
* Bump k8s.io/client-go from 0.33.4 to 0.34.0 [#1305](https://github.com/jcmoraisjr/haproxy-ingress/pull/1305) (dependabot[bot])
* Bump sigs.k8s.io/controller-runtime from 0.21.0 to 0.22.1 [#1301](https://github.com/jcmoraisjr/haproxy-ingress/pull/1301) (dependabot[bot])
* add backend scoped stick tables [#1293](https://github.com/jcmoraisjr/haproxy-ingress/pull/1293) (jcmoraisjr)
* update dependencies [c713328](https://github.com/jcmoraisjr/haproxy-ingress/commit/c7133283daa25e1f6f7004f1016add7398d0ef09) (Joao Morais)
* update go from 1.24.6 to 1.25.1 [#1306](https://github.com/jcmoraisjr/haproxy-ingress/pull/1306) (jcmoraisjr)

## Fixes (a2)

* fix reading backend ca certificate from file [#1297](https://github.com/jcmoraisjr/haproxy-ingress/pull/1297) (jcmoraisjr)

# v0.16.0-alpha.1

## Reference (a1)

* Release date: `2025-08-20`
* Helm chart: `--version 0.16.0-alpha.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.16.0-alpha.1`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.16.0-alpha.1`
* Embedded HAProxy version: `2.8.15`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.16.0-alpha.1`

## Release notes (a1)

This is the first tag of the v0.16 branch, which brings most, if not all the breaking changes expected to the v0.16 release:

- Minimum HAProxy version on the External HAProxy topology changed from 2.2 to 2.4, due to a change on how Lua scripts are loaded.
- Default load balance algorithm was changed from Roundrobin to Random(2) if not declared in global ConfigMap or as a backend annotation.
- Code cleanup might have an impact in the case your workload depends on it somehow. Removed codes that might impact are:
  - Old controller engine was removed altogether, so the `"HAPROXY_INGRESS_RUNTIME" == "LEGACY"` envvar has no effect.
  - Endpoints API was deprecated on Kubernetes 1.33 and removed from our v0.16 codebase, HAProxy Ingress now uses only EndpointSlice API.

We should have at least one other alpha/snapshot release, and we will report any new breaking changes on its release notes in the case it happens.

Besides that, the following areas had some improvement since v0.15:

- Embedded HAProxy version changed from 2.6 to 2.8.
- FastCGI protocol is now supported, both plain and on top of TLS. See its [documentation](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#fastcgi).
- Clustered metrics, non centralized, via peers configuration. HAProxy Ingress configures every HAProxy instance to talk to each other to share their local metrics. Note that alpha.1 supports only global configuration with a single shared stick table, a backend scoped configuration should be done for alpha.2. See its [documentation](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#peers).
- Customized proxy HTTP responses are now Host/Backend scoped, so they can be configured per hostname or backend via ingress or service annotation. See its [documentation](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#http-response).
- Better support for a namespaced controller by adding the `--disable-ingress-class-api` command-line option. See its [documentation](https://haproxy-ingress.github.io/v0.16/docs/configuration/command-line/#ingress-class).
- Code cleanup: legacy controller code (on behalf of controller-runtime), deprecated Endpoints API (on behalf of EndpointSlice), and deprecated structs used to track changes on a former HAProxy Ingress version.

Dependencies:

- embedded haproxy from 2.6.22 to 2.8.15
- client-go from v0.32.8 to v0.33.4
- controller-runtime from v0.20.4 to v0.21.0
- go from 1.23.12 to 1.24.6

## Improvements (a1)

New features and improvements since `v0.15`:

* Bump golangci/golangci-lint-action from 6 to 7 [#1231](https://github.com/jcmoraisjr/haproxy-ingress/pull/1231) (dependabot)
* remove legacy controller and work queue [#1233](https://github.com/jcmoraisjr/haproxy-ingress/pull/1233) (jcmoraisjr)
* Update(docs): for custom tcp ports [#1247](https://github.com/jcmoraisjr/haproxy-ingress/pull/1247) (till)
* Bump golang.org/x/crypto from 0.36.0 to 0.40.0 [#1258](https://github.com/jcmoraisjr/haproxy-ingress/pull/1258) (dependabot)
* Bump k8s.io/api from 0.32.3 to 0.33.2 [#1259](https://github.com/jcmoraisjr/haproxy-ingress/pull/1259) (jcmoraisjr)
* Bump k8s.io/client-go from 0.33.2 to 0.33.3 [#1261](https://github.com/jcmoraisjr/haproxy-ingress/pull/1261) (jcmoraisjr)
* Bump sigs.k8s.io/controller-runtime from 0.20.4 to 0.21.0 [#1263](https://github.com/jcmoraisjr/haproxy-ingress/pull/1263) (dependabot)
* auth external integration tests [#1264](https://github.com/jcmoraisjr/haproxy-ingress/pull/1264) (jcmoraisjr)
* change tests to haproxy 3.2 [#1268](https://github.com/jcmoraisjr/haproxy-ingress/pull/1268) (jcmoraisjr)
* remove fields used by the former tracking [#1270](https://github.com/jcmoraisjr/haproxy-ingress/pull/1270) (jcmoraisjr)
* deprecate v1.endpoints api [#1271](https://github.com/jcmoraisjr/haproxy-ingress/pull/1271) (jcmoraisjr)
* add grace period for embedded haproxy [#1272](https://github.com/jcmoraisjr/haproxy-ingress/pull/1272) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.16/docs/configuration/command-line/#haproxy-grace-period)
  * Command-line options:
    * `--haproxy-grace-period`
* Bump github.com/prometheus/client_golang from 1.22.0 to 1.23.0 [#1278](https://github.com/jcmoraisjr/haproxy-ingress/pull/1278) (dependabot[bot])
* Bump golang.org/x/crypto from 0.40.0 to 0.41.0 [#1285](https://github.com/jcmoraisjr/haproxy-ingress/pull/1285) (dependabot[bot])
* Bump actions/checkout from 4 to 5 [#1286](https://github.com/jcmoraisjr/haproxy-ingress/pull/1286) (dependabot[bot])
* add option to disable ingress class watch [#1274](https://github.com/jcmoraisjr/haproxy-ingress/pull/1274) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.16/docs/configuration/command-line/#ingress-class)
  * Command-line options:
    * `--disable-ingress-class-api`
* add fastcgi support [#1275](https://github.com/jcmoraisjr/haproxy-ingress/pull/1275) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#fastcgi)
  * Configuration keys:
    * `fcgi-app`
    * `fcgi-enabled-apps`
* add config snippet config-backend-early [#1276](https://github.com/jcmoraisjr/haproxy-ingress/pull/1276) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#configuration-snippet)
  * Configuration keys:
    * `config-backend-early`
    * `config-backend-late`
* load lua script per thread instead [#1281](https://github.com/jcmoraisjr/haproxy-ingress/pull/1281) (jcmoraisjr)
* change default load balance algorithm to random(2) [#1282](https://github.com/jcmoraisjr/haproxy-ingress/pull/1282) (jcmoraisjr)
* makes controller pod namespace and name mandatory [#1287](https://github.com/jcmoraisjr/haproxy-ingress/pull/1287) (jcmoraisjr)
* allows to configure http responses via ingress [#1280](https://github.com/jcmoraisjr/haproxy-ingress/pull/1280) (jcmoraisjr)
* turn envvars optional [#1290](https://github.com/jcmoraisjr/haproxy-ingress/pull/1290) (jcmoraisjr)
* add peers config [#1277](https://github.com/jcmoraisjr/haproxy-ingress/pull/1277) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#peers)
  * Configuration keys:
    * `peers-name`
    * `peers-port`
    * `peers-table`
* update client-go from v0.33.3 to v0.33.4 [2aa3cf6](https://github.com/jcmoraisjr/haproxy-ingress/commit/2aa3cf6da0939453bbcb202fde2484286e6ed5a2) (Joao Morais)
* update dependencies [1b4bc87](https://github.com/jcmoraisjr/haproxy-ingress/commit/1b4bc876d7e46a1d7ac99f949b424d3edd8fac47) (Joao Morais)
* update go from 1.23.7 to 1.24.6 [59062bf](https://github.com/jcmoraisjr/haproxy-ingress/commit/59062bfffa17ff69afbe009bc95f18a56c42792e) (Joao Morais)
* update embedded haproxy from 2.6.21 to 2.8.15 [#1292](https://github.com/jcmoraisjr/haproxy-ingress/pull/1292) (jcmoraisjr)
* update docsy from v0.11.0 to v0.12.0 [0f869c4](https://github.com/jcmoraisjr/haproxy-ingress/commit/0f869c4bfc10c5a10e55cb22b6b30e3a90185c98) (Joao Morais)

Chart improvements since `v0.15`:

* Allow custom labels to be added to the controllers DaemonSet/Deployment [#93](https://github.com/haproxy-ingress/charts/pull/93) (gezb)
* add permission to replicasets and daemonsets [#94](https://github.com/haproxy-ingress/charts/pull/94) (jcmoraisjr)

## Fixes (a1)

* block attempt to read cluster credentials [#1273](https://github.com/jcmoraisjr/haproxy-ingress/pull/1273) (jcmoraisjr)
* create new event queues when leader is acquired [#1283](https://github.com/jcmoraisjr/haproxy-ingress/pull/1283) (jcmoraisjr)
* read controller pod selector from owner [#1288](https://github.com/jcmoraisjr/haproxy-ingress/pull/1288) (jcmoraisjr)
