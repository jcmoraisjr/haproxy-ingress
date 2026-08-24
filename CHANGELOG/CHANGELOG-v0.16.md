# CHANGELOG v0.16 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.15!](#upgrade-notes)
  * [Deprecated command-line options](#deprecated-command-line-options)
* [Contributors](#contributors)
* [v0.16.1](#v0161)
  * [Reference](#reference-r1)
  * [Release notes](#release-notes-r1)
  * [Fixes and Improvements](#fixes-and-improvements-r1)
* [v0.16.0](#v0160)
  * [Reference](#reference-r0)
  * [Release notes](#release-notes-r0)
  * [Fixes and Improvements](#fixes-and-improvements-r0)
* [v0.16.0-beta.2](#v0160-beta2)
  * [Reference](#reference-b2)
  * [Release notes](#release-notes-b2)
  * [Improvements](#improvements-b2)
  * [Fixes](#fixes-b2)
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
* Ian Roberts ([ianroberts](https://github.com/ianroberts))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Lola Delannoy ([spnngl](https://github.com/spnngl))
* Mia Mouret ([mia-mouret](https://github.com/mia-mouret))
* Nadia Santalla ([nadiamoe](https://github.com/nadiamoe))
* Pedro Gonçalves ([PerGon](https://github.com/PerGon))
* Till! ([till](https://github.com/till))
* Vladimir Kozhukalov ([kozhukalov](https://github.com/kozhukalov))

# v0.16.1

## Reference (r1)

* Release date: `2026-05-04`
* Helm chart: `--version 0.16.1`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.16.1`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.16.1`
* Embedded HAProxy version: `2.8.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.16.1`

## Release notes (r1)

This release fixes some issues found on v0.16 branch:

- Updating base image and Go, which fixes a number of reported CVEs on OS libraries and Go's stdlib.
- Nadia reported that external authentication, if placed in the frontend via `auth-external-placement` configuration key, uses exact path match despite of the path configuration. Backend placed configuration (the default placement) does not have this problem. It is recommended to update HAProxy Ingress asap if you use external authentication placed in the frontend.
- Florian reported that idle metric collector can crash the controller if haproxy eventually reports more than 100 on its metric. This happens because the controller did not check the boundaries and a counter metric would become negative, making Prometheus client to crash. See also https://github.com/haproxy/haproxy/issues/3339.
- A race can happen in the controller start using master-worker mode, when checking if the master socket is already available. In case of an error reading the socket, the controller checks its presence, returning the original error if it was created in this time frame and was found. This behavior makes the controller delay 30 extra seconds to become ready.
- Nadia reported and fixed a case-sensitive match in external authentication header match, which is expected to be case-insensitive.
- Ian reported and fixed the starting user configured in the controller image, changing from the `haproxy` name to its UID `99`. The UID continues the same, but not using the name allows to configure the container runtime to run as non root without the need to specify an UID.
- Logan reported that a PDB resource was always being created despite of being configured, this happened because chart was comparing the `maxUnavailable` to a declared zero, which is also the value when it is not configured.
- Ian configured all the writable folders as emptyDir, which makes the controller to work on containers having read only file system.
- The service account is now configured only in the controller container for security reasons, sidecar containers does not have the service account anymore.

Also, Lola added VPA (VerticalPodAutoscaler) configuration option.

Changes in dependencies:

- embedded haproxy from 2.8.20 to 2.8.22
- go from 1.25.8 to 1.25.9
- client-go from v0.34.6 to v0.34.7

## Fixes and improvements (r1)

New fixes and improvements since `v0.16.0`:

* update metrics page and dashboard [#1435](https://github.com/jcmoraisjr/haproxy-ingress/pull/1435) (jcmoraisjr)
* Use numeric USER in Dockerfile [#1431](https://github.com/jcmoraisjr/haproxy-ingress/pull/1431) (ianroberts)
* doc: fix default value for watch gateway [#1457](https://github.com/jcmoraisjr/haproxy-ingress/pull/1457) (jcmoraisjr)
* pin dependencies from makefile [#1467](https://github.com/jcmoraisjr/haproxy-ingress/pull/1467) (jcmoraisjr)
* convert user-provided auth external header names to lowercase [#1429](https://github.com/jcmoraisjr/haproxy-ingress/pull/1429) (nadiamoe)
* parameterize the eventually timeout and interval [#1468](https://github.com/jcmoraisjr/haproxy-ingress/pull/1468) (jcmoraisjr)
* adding boundary in the idle_pct metric [#1456](https://github.com/jcmoraisjr/haproxy-ingress/pull/1456) (jcmoraisjr)
* fix request match on frontend based external auth [#1470](https://github.com/jcmoraisjr/haproxy-ingress/pull/1470) (jcmoraisjr)
* fix race checking if haproxy socket is missing [#1471](https://github.com/jcmoraisjr/haproxy-ingress/pull/1471) (jcmoraisjr)
* update embedded haproxy from 2.8.20 to 2.8.22 [0cacf6c](https://github.com/jcmoraisjr/haproxy-ingress/commit/0cacf6ce7c1dd4ac3c9f1a5698dfaaeb5903a68f) (Joao Morais)
* update go from 1.25.8 to 1.25.9 [83a5691](https://github.com/jcmoraisjr/haproxy-ingress/commit/83a56919963d4782abdf870c837052dbdfe58555) (Joao Morais)
* update client-go from v0.34.6 to v0.34.7 [645e897](https://github.com/jcmoraisjr/haproxy-ingress/commit/645e897484d0b82af3ec5b3ddc9ef0b45d498131) (Joao Morais)

Chart improvements since `v0.16.0`:

* feat: always mount writeable folders from emptyDir [#106](https://github.com/haproxy-ingress/charts/pull/106) (ianroberts)
* feat: add VerticalPodAutoscaler resource for controller [#107](https://github.com/haproxy-ingress/charts/pull/107) (spnngl)
* create pdb only if max unavailable is defined [#108](https://github.com/haproxy-ingress/charts/pull/108) (jcmoraisjr)
* manually mount sa only in controller pod [#109](https://github.com/haproxy-ingress/charts/pull/109) (jcmoraisjr)

# v0.16.0

## Reference (r0)

* Release date: `2026-03-23`
* Helm chart: `--version 0.16.0`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.16.0`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.16.0`
* Embedded HAProxy version: `2.8.20`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.16.0`

## Release notes (r0)

This is the first GA release of the v0.16 branch, which fixes some issues found in the last beta version:

- Ian found and fixed two compliance issues on CORS: `access-control-allow-origin` response header returns a `*` by default, instead of the supplied Origin, which is not allowed by the specification when Allow Credentials is configured as true. This also happens despite of the Origin configuration in case of a 413 Too Large response is generated by HAProxy.
- Mia found and fixed the missing of the second IP address on Ingress and Gateway status, on dual stack clusters, when using node IP address. This leads the Ingress and Gateway status to report only one of the A or AAAA entries, depending on the order they are listed in the node status.
- Alex found that a strict validation in CORS Allow Origin configuration, refusing to configure protocols other than http and https, leads the configuration to the permissive `*`. Example of other protocols include `capacitor://` and `chrome-extension://`. The validation was changed to allow any protocol.
- Wojciech reported that a PEM validation is failing to use a valid PEM formatted certificate in case the input has more than one trailing spaces or line break after the last PEM block.
- Ian observed that CORS generated response headers were not being added when a custom response is configured and HAProxy uses it, like a custom 5xx response. HAProxy has `http-after-response` for this purpose, and now CORS response headers are configured using it.
- Thorsten reported that rewrite-target does not work with path match as regex. Now the rewrite configuration takes into account the match type.
- Stephan observed that Ingress status does not update the IP address when its class is changed from another controller to HAProxy Ingress. This was happening because we were tracking only Ingress creation and IP changes, but scenario happens on Ingress updates.

Also, base image and stdlib were updated in order to fix some known CVEs.

Thanks to everyone who reported issues and contributed fixes, your help makes each release better.

Changes in dependencies:

- embedded haproxy from 2.8.18 to 2.8.20
- go from 1.25.5 to 1.25.8
- client-go from v0.34.3 to v0.34.6

## Fixes and improvements (r0)

New fixes and improvements since `v0.16.0-beta.2`:

* fix: move logic to capture request origin header earlier (backport 0.16) [#1386](https://github.com/jcmoraisjr/haproxy-ingress/pull/1386) (ianroberts)
* fix: report all node IPs in status for dual-stack support [#1381](https://github.com/jcmoraisjr/haproxy-ingress/pull/1381) (mia-mouret)
* Reflect back request origin when credentials enabled (0.16 backport) [#1390](https://github.com/jcmoraisjr/haproxy-ingress/pull/1390) (ianroberts)
* fix server state file generation [#1404](https://github.com/jcmoraisjr/haproxy-ingress/pull/1404) (jcmoraisjr)
* configure CA for requests missing SNI [#1408](https://github.com/jcmoraisjr/haproxy-ingress/pull/1408) (jcmoraisjr)
  * Configuration keys:
    * [`auth-tls-default-secret`](https://haproxy-ingress.github.io/v0.16/docs/configuration/keys/#auth-tls)
* make cors allow header rule more flexible [#1401](https://github.com/jcmoraisjr/haproxy-ingress/pull/1401) (jcmoraisjr)
* improve validation of PEM data [#1405](https://github.com/jcmoraisjr/haproxy-ingress/pull/1405) (jcmoraisjr)
* add cors headers on proxy generated responses [#1402](https://github.com/jcmoraisjr/haproxy-ingress/pull/1402) (jcmoraisjr)
* fix rewrite path handling for regex paths [#1411](https://github.com/jcmoraisjr/haproxy-ingress/pull/1411) (jcmoraisjr)
* check ingress status on add and update events [#1421](https://github.com/jcmoraisjr/haproxy-ingress/pull/1421) (jcmoraisjr)
* bump go from 1.25.5 to 1.25.8 [0fc41d3](https://github.com/jcmoraisjr/haproxy-ingress/commit/0fc41d3c7cf16ae517b9018d764d79f38b193238) (Joao Morais)
* bump embedded haproxy from 2.8.18 to 2.8.20 [b771ced](https://github.com/jcmoraisjr/haproxy-ingress/commit/b771cedf1432563536195a874f3aa4470b4d61ae) (Joao Morais)
* bump client-go from v0.34.3 to v0.34.6 [e4b6c22](https://github.com/jcmoraisjr/haproxy-ingress/commit/e4b6c22ce035dc1d8fafcaaab10f9ca29d5f96f8) (Joao Morais)

Chart improvements since `v0.16.0-beta.2`:

* add daemonset extraHostPorts [#98](https://github.com/haproxy-ingress/charts/pull/98) (bapung)

# v0.16.0-beta.2

## Reference (b2)

* Release date: `2026-01-04`
* Helm chart: `--version 0.16.0-beta.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.16.0-beta.2`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.16.0-beta.2`
* Embedded HAProxy version: `2.8.18`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.16.0-beta.2`

## Release notes (b2)

This is the second beta version of the v0.16 branch, which fixes some issues found since the first beta version:

- Nirajan found an endless reconciliation loop, which happens due to a hardcoded timeout of `5s` when using haproxy v2.7+ in master-worker or external mode. The `reload` api command is synchronous since this version, and reloads taking more than 5 seconds were being recognized as a failure for HAProxy Ingress, although it succeeds in the haproxy side.
- Hasnain identified that if the embedded haproxy process in master-worker mode is killed during a reload command, HAProxy Ingress fails to recognize the reload count of the new instance, leading to an endless failing loop.
- Status update changed to a synchronous approach, which avoids overriding changes made on concurrent updates.

Last but not least stdlib and a few controller dependencies were updated in order to fix some known CVEs.

Changes in dependencies:

- embedded haproxy from 2.8.16 to 2.8.18
- controller-runtime from v0.22.3 to v0.22.4
- go from 1.25.3 to 1.25.5

## Improvements (b2)

New features and improvements since `v0.16.0-beta.1`:

* make status update synchronous [#1330](https://github.com/jcmoraisjr/haproxy-ingress/pull/1330) (jcmoraisjr)
* Add connection timeout command-line option [#1348](https://github.com/jcmoraisjr/haproxy-ingress/pull/1348) [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/#timeout) (jcmoraisjr)
  * Command-line option:
    * `--connection-timeout`
* update dependencies [be866c5](https://github.com/jcmoraisjr/haproxy-ingress/commit/be866c505d047e577813a557726356a2aa022773) (Joao Morais)
* update go from 1.25.3 to 1.25.5 [b9f30df](https://github.com/jcmoraisjr/haproxy-ingress/commit/b9f30dfc7e30b69ed6bf5b848a46007254cb7c47) (Joao Morais)
* update embedded haproxy from 2.8.16 to 2.8.18 [1409b7f](https://github.com/jcmoraisjr/haproxy-ingress/commit/1409b7f9658a124423cbbbdefaabba166a0ce3aa) (Joao Morais)

Chart improvements since `v0.16.0-beta.1`:

* Add feature to control PDB via maxUnavailable as well [#95](https://github.com/haproxy-ingress/charts/pull/95) (PerGon)
* Toggle controller service [#99](https://github.com/haproxy-ingress/charts/pull/99) (kozhukalov)
* add list and watch permission to namespace and node apis [#101](https://github.com/haproxy-ingress/charts/pull/101) (jcmoraisjr)

## Fixes (b2)

* fix full-sync trigger [#1331](https://github.com/jcmoraisjr/haproxy-ingress/pull/1331) (jcmoraisjr)
* fix status update during shutdown [#1335](https://github.com/jcmoraisjr/haproxy-ingress/pull/1335) (jcmoraisjr)
* check if process is the same waiting for reload [#1355](https://github.com/jcmoraisjr/haproxy-ingress/pull/1355) (jcmoraisjr)

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
