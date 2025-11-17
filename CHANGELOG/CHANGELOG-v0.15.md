# CHANGELOG v0.15 branch

* [Major improvements](#major-improvements)
* [Upgrade notes - read before upgrade from v0.14!](#upgrade-notes)
  * [Deprecated command-line options](#deprecated-command-line-options)
  * [Upgrading with embedded Acme](#upgrading-with-embedded-acme)
  * [Upgrading with custom repositories](#upgrading-with-custom-repositories)
* [Contributors](#contributors)
* [v0.15.0](#v0150)
  * [Reference](#reference-r0)
  * [Release notes](#release-notes-r0)
  * [Fixes and improvements](#fixes-and-improvements-r0)
* [v0.15.0-beta.2](#v0150-beta2)
  * [Reference](#reference-b2)
  * [Release notes](#release-notes-b2)
  * [Improvements](#improvements-b2)
  * [Fixes](#fixes-b2)
* [v0.15.0-beta.1](#v0150-beta1)
  * [Reference](#reference-b1)
  * [Release notes](#release-notes-b1)
  * [Improvements](#improvements-b1)
  * [Fixes](#fixes-b1)
* [v0.15.0-alpha.3](#v0150-alpha3)
  * [Reference](#reference-a3)
  * [Release notes](#release-notes-a3)
  * [Improvements](#improvements-a3)
  * [Fixes](#fixes-a3)
* [v0.15.0-alpha.2](#v0150-alpha2)
  * [Reference](#reference-a2)
  * [Release notes](#release-notes-a2)
  * [Improvements](#improvements-a2)
  * [Fixes](#fixes-a2)
* [v0.15.0-alpha.1](#v0150-alpha1)
  * [Reference](#reference-a1)
  * [Release notes](#release-notes-a1)
  * [Improvements](#improvements-a1)
  * [Fixes](#fixes-a1)

## Major improvements

Highlights of this version:

* Embedded HAProxy upgrade from 2.4 to 2.6.
* Change from a legacy controller engine component to [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime).
* Improvements on Gateway API: v1 API and TCPRoute support
* Integration tests
* Dark theme in the documentation

## Upgrade notes

Breaking backward compatibility from v0.14:

* HAProxy Ingress used to start as root by default up to v0.14. Starting on v0.15 the controller container starts as the non root user `haproxy`, UID `99`. This change should impact deployments that need to start as root, e.g. chroot enabled, binding on privileged TCP ports (1024 or below) on old container runtimes, etc. Workloads that need to run as root can, despite the security risk, configure the security context in the deployment resource or Helm chart to enforce starting user as root. See the [security doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#security) for configuration examples.
* Besides starting as non root, the `haproxy` user ID changed from `1001` to `99`. The former `1001` UID was chosen and created in a day `docker.io/haproxy` container image started as root (2.3 and older). Starting from 2.4 the `haproxy` user was added as UID `99`. In v0.15 we started to use the same UID, so file systems shared between controller and haproxy doesn't have permission issues.
* Election ID was changed, see the [documentation](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/#election-id) for customization options. Election ID is used by embedded Acme signer and status updater to, respectively, request certificates and update ingress status. A cluster of HAProxy Ingress controllers will elect two controllers at the same time during the rolling update from any other version to v0.15. Ingress status does not have an impact. See [Upgrading with embedded Acme](#upgrading-with-embedded-acme) below for details about upgrading with embedded Acme signer enabled.
* Master worker mode is now enabled by default, see the [documentation](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/#master-worker). This mode starts a master HAProxy process in foreground, which controls the worker processes.
* Helm chart has now a distinct field for the registry of an image, which should impact charts that configure custom repositories. See [Upgrading with custom repositories](#upgrading-with-custom-repositories) below for the details.
* Log debug level is enabled by default. HAProxy Ingress has a good balance between low verbosity and useful information on its debug level.
* EndpointSlices API is enabled by default, anticipating the deprecation of Endpoints API since Kubernetes 1.33.
* Due to EndpointSlices API enabled by default, the minimal supported Kubernetes version is 1.21 in the default configuration.
* Default image for the log sidecar changed from `whereisaaron/kube-syslog-sidecar` to `ghcr.io/crisu1710/kube-syslog-sidecar:0.2.0`. It is the same codebase, just adding support for multiple architectures.

### New controller engine

HAProxy Ingress starting from v0.15 uses [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) as its watch and notification engine for Ingress and Gateway API resources. This is an internal implementation that shouldn't change controller behavior. v0.15 still preserves the legacy controller, it can be enabled by configuring envvar `HAPROXY_INGRESS_RUNTIME` as `LEGACY`, and can be used on debugging, when checking a misbehavior in the new controller. Please file an [issue at GitHub](https://github.com/jcmoraisjr/haproxy-ingress/issues/new?template=bug.md) in the case you find a problem in the new controller, even if the issue is solved moving to the old one. v0.16 will remove the old controller engine implementation.

### Deprecated command-line options

The following command-line options were deprecated on v0.15 and should be removed on a future version:

* `--acme-election-id`
* `--disable-pod-list`
* `--force-namespace-isolation`
* `--healthz-port`

See their documentation at the [command-line options documentation page](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/).

### Upgrading with embedded Acme

Embedded Acme signer uses leader election to request certificates just once, despite the size of the HAProxy Ingress cluster. When rolling update to v0.15, one controller from the older version and another controller from the new version will understand themselves as the leader at the same time, due to the change in the election ID.

The only drawback is that, if the expiring certificate check runs during the rolling update, the embedded Acme signer will call the Acme backend twice per certificate that needs to be issued. This behavior can be avoided by changing the global [`acme-terms-agreed`](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#acme) configuration key as false during the rolling update, updating to true as soon as the rolling update has finished.

### Upgrading with custom repositories

HAProxy Ingress Helm chart now uses distinct fields for the registry and the repository of a container image. If a Helm chart customizes `image.repository` of any container image, now it should consider the `image.registry` field as well.

v0.14 example:

```yaml
controller:
  haproxy:
    enabled: true
    image:
      repository: myhub.local/haproxy
```

Starting on v0.15, registry and repository should be placed on distinct attributes:

```yaml
controller:
  haproxy:
    enabled: true
    image:
      registry: myhub.local
      repository: haproxy
```

See the full syntax and default values in the [README.md](https://github.com/haproxy-ingress/charts/blob/release-0.15/haproxy-ingress/README.md#configuration) and in the [values.yaml](https://github.com/haproxy-ingress/charts/blob/release-0.15/haproxy-ingress/values.yaml) files of the HAProxy Ingress Helm chart.

## Contributors

* Ali Afsharzadeh ([guoard](https://github.com/guoard))
* Andrej Baran ([andrejbaran](https://github.com/andrejbaran))
* Arrigo Zanette ([zanettea](https://github.com/zanettea))
* Błażej Frydlewicz ([blafry](https://github.com/blafry))
* Chris Boot ([bootc](https://github.com/bootc))
* Dmitry Misharov ([quarckster](https://github.com/quarckster))
* Dmitry Spikhalsky ([Spikhalskiy](https://github.com/Spikhalskiy))
* Fredrik Wendel ([fredrik-w](https://github.com/fredrik-w))
* genofire ([genofire](https://github.com/genofire))
* Gerald Barker ([gezb](https://github.com/gezb))
* Grzegorz Dziwoki ([gdziwoki](https://github.com/gdziwoki))
* Jan Bebendorf ([JanHolger](https://github.com/JanHolger))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* Jop Zinkweg ([jzinkweg](https://github.com/jzinkweg))
* Julien Torrielli ([Jul13nT](https://github.com/Jul13nT))
* Jurriaan Wijnberg ([jr01](https://github.com/jr01))
* Karan Chaudhary ([lafolle](https://github.com/lafolle))
* Mac Chaffee ([mac-chaffee](https://github.com/mac-chaffee))
* Matt Low ([mlow](https://github.com/mlow))
* Manuel Rüger ([mrueg](https://github.com/mrueg))
* Michele Palazzi ([ironashram](https://github.com/ironashram))
* Philipp Hossner ([phihos](https://github.com/phihos))
* Robin Schneider ([Crisu1710](https://github.com/Crisu1710))
* RT ([hedgieinsocks](https://github.com/hedgieinsocks))
* tomklapka ([tomklapka](https://github.com/tomklapka))
* Tomasz Zurkowski ([doriath](https://github.com/doriath))

# v0.15.0

## Reference (r0)

* Release date: `2025-10-15`
* Helm chart: `--version 0.15.0`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.15.0`
* Embedded HAProxy version: `2.6.23`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.15.0`

## Release notes (r0)

This is the first stable release of the v0.15 branch. See above the [major improvements](#major-improvements) and [breaking changes](#upgrade-notes) regarding changes from the `v0.14` version.

From `v0.15.0-beta.2`, this release updates the embedded haproxy version, which fixes CVE-2025-11230, see HAProxy release notes https://www.mail-archive.com/haproxy@formilux.org/msg46189.html . Other issues were also found and fixed:

- Chitoku found a regression on some certificate related annotations not working with the `file://` protocol, after implementing global support on those annotations.
- Artyom found the fronting-proxy configuration overwriting the `X-Forwarded-Proto` header when both the fronting proxy and the regular HTTP shares the same TCP port number.

Dependencies:

- embedded haproxy from 2.6.22 to 2.6.23
- go from 1.23.12 to 1.24.7

## Fixes and improvements (r0)

New fixes and improvements since `v0.15.0-beta.2`:

* fix reading backend ca certificate from file [#1297](https://github.com/jcmoraisjr/haproxy-ingress/pull/1297) (jcmoraisjr)
* fix xfp header on fronting proxy shared port [#1310](https://github.com/jcmoraisjr/haproxy-ingress/pull/1310) (jcmoraisjr)
* update dependencies [a97f3c3](https://github.com/jcmoraisjr/haproxy-ingress/commit/a97f3c34c5b25aace579d9162957bc5e5d61a2c0) (Joao Morais)
* update haproxy from 2.6.22 to 2.6.23 [27cda7c](https://github.com/jcmoraisjr/haproxy-ingress/commit/27cda7c8f23f6734cf2ee7f7a4aa65cfebab2bdc) (Joao Morais)
* update go from 1.23.12 to 1.24.7 [266cbba](https://github.com/jcmoraisjr/haproxy-ingress/commit/266cbba2000ae7d99d6e5221dd63490757e32a81) (Joao Morais)

# v0.15.0-beta.2

## Reference (b2)

* Release date: `2025-08-15`
* Helm chart: `--version 0.15.0-beta.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0-beta.2`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.15.0-beta.2`
* Embedded HAProxy version: `2.6.22`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.15.0-beta.2`

## Release notes (b2)

This is the second and last beta version of the v0.15 branch. Find below a list of improvements made since `beta.1`.

Exclusive v0.15 changes include:

- Robert Paschedag found an event queue misbehavior when controller looses the leader and acquire it again later. This was preventing Status update and ACME check events to happen.
- Kara reported that controller pod listing is misbehaving on some deployments that uses DaemonSet. This prevents ingress status to be updated with all node IPs where the controller is running.
- EndpointSlice API were missing in the new controller engine. This is now the default API used to watch service endpoints, since the Endpoints API is deprecated in Kubernetes 1.33.
- A race was preventing HAProxy Ingress to stop fast on a rolling update or scale down event, due to a failure to identify if haproxy is restarting or has already stopped.

Fixes merged to stable branches:

- An user with update ingress privilege can escalate their own privilege to the controller one, by exploring the config snippet annotation if it was not disabled via `--disable-config-keywords=*` command-line option. Mitigate this vulnerability by updating controller version, or disabling config snippet.
- Fixes a panic on controller shutdown due to closing the same connection twice, if its startup failed the very first reconciliation.
- Fixes a race during haproxy reload, when the controller connects fast enough via the master socket, finds the old instance still running and thinks it's the new one already. If this happens, it might lead to problems in the synchronization of the in-memory model to the running instance, sometimes making haproxy to reflect an older state.

Dependencies:

- embedded haproxy from 2.6.21 to 2.6.22
- client-go from v0.32.3 to v0.32.8
- controller-runtime from v0.20.3 to v0.20.4
- go from 1.23.7 to 1.23.12

## Improvements (b2)

New features and improvements since `v0.15.0-beta.1`:

* add endpointslice api on new controller [#1260](https://github.com/jcmoraisjr/haproxy-ingress/pull/1260) (jcmoraisjr)
* Bump sigs.k8s.io/controller-runtime from 0.20.3 to 0.20.4 [#1232](https://github.com/jcmoraisjr/haproxy-ingress/pull/1232) (dependabot)
* Bump github.com/go-logr/logr from 1.4.2 to 1.4.3 [#1262](https://github.com/jcmoraisjr/haproxy-ingress/pull/1262) (dependabot)
* move to endpointslice by default [#1269](https://github.com/jcmoraisjr/haproxy-ingress/pull/1269) (jcmoraisjr)
* update client-go from v0.32.3 to v0.32.8 [c7b2b5d](https://github.com/jcmoraisjr/haproxy-ingress/commit/c7b2b5d8de1608c79cf2e22fc9311f8f384a9aa9) (Joao Morais)
* update dependencies [8df7b5b](https://github.com/jcmoraisjr/haproxy-ingress/commit/8df7b5b4c648f3d8afb9f1e0a45f0e15ded297e3) (Joao Morais)
* update go from 1.23.7 to 1.23.12 [deace06](https://github.com/jcmoraisjr/haproxy-ingress/commit/deace06d8cdcdcbd784f42141ff6aed37628265c) (Joao Morais)
* update embedded haproxy from 2.6.21 to 2.6.22 [47b145d](https://github.com/jcmoraisjr/haproxy-ingress/commit/47b145d1b49686239dc3a4b8cae4a13da8402a20) (Joao Morais)
* update docsy from v0.11.0 to v0.12.0 [f9e0f8e](https://github.com/jcmoraisjr/haproxy-ingress/commit/f9e0f8e0cdf19e770b9b38de7345101dd6083537) (Joao Morais)

Chart improvements since `v0.15.0-beta.1`:

* Allow custom labels to be added to the controllers DaemonSet/Deployment [#93](https://github.com/haproxy-ingress/charts/pull/93) (gezb)
* add permission to replicasets and daemonsets [#94](https://github.com/haproxy-ingress/charts/pull/94) (jcmoraisjr)

## Fixes (b2)

* check if haproxy reloaded already [#1265](https://github.com/jcmoraisjr/haproxy-ingress/pull/1265) (jcmoraisjr)
* ensure that embedded haproxy starts just once [#1266](https://github.com/jcmoraisjr/haproxy-ingress/pull/1266) (jcmoraisjr)
* add context on socket calls [#1267](https://github.com/jcmoraisjr/haproxy-ingress/pull/1267) (jcmoraisjr)
* block attempt to read cluster credentials [#1273](https://github.com/jcmoraisjr/haproxy-ingress/pull/1273) (jcmoraisjr)
* create new event queues when leader is acquired [#1283](https://github.com/jcmoraisjr/haproxy-ingress/pull/1283) (jcmoraisjr)
* read controller pod selector from owner [#1288](https://github.com/jcmoraisjr/haproxy-ingress/pull/1288) (jcmoraisjr)

# v0.15.0-beta.1

## Reference (b1)

* Release date: `2025-03-22`
* Helm chart: `--version 0.15.0-beta.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0-beta.1`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.15.0-beta.1`
* Embedded HAProxy version: `2.6.21`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.15.0-beta.1`

## Release notes (b1)

This is the first beta version of the v0.15 branch, having important stability changes and vulnerability fixes since alpha.3. The main branch now is open for v0.16 development, including but not limited to code cleanup, better Gateway API support, and quic/h3.

Find below a list of improvements made since `alpha.3`.

Exclusive v0.15 changes include:

- Robert found a misbehavior on status update, due to a misconfigured leader election. A controller instance that lost leader didn't start an election, so didn't have a chance to be the leader anymore.
- Gateway API now supports multiple certificates on a single Gateway Listener.

Other changes already merged to the stable branches:

- Controller now retries to apply a haproxy reload in the case of a failure. Older controller versions didn't retry because all the failures are related with misconfiguration, but since master-worker and external modes are options, other network or socket related issues might happen.
- TCP services now supports a list of TLS certificates.

Fixes merged to stable branches:

- Robson, Moacir and Fabio found a memory leak on Gateway API reconciliation. Depending on the changes being applied, an older in memory representation of the load balancer state is referenced by the new one, creating a chain of old representations not having a chance to be collected by GC.
- rdavyd found an endpoint configuration overwrite in the case the same service, or a distinct service with the same endpoints are added in a single rule of a single HTTPRoute on Gateway API.
- All known vulnerable components were updated, like go's stdlib and `golang.org/x/crypto`

Dependencies:

- embedded haproxy from 2.6.17 to 2.6.21
- client-go from v0.30.2 to v0.32.3
- controller-runtime from v0.18.4 to v0.20.3
- go from 1.22.4 to 1.23.7, having `//go:debug default=go1.19` for backward compatibility (legacy controller)

## Improvements (b1)

New features and improvements since `v0.15.0-alpha.3`:

* Bump golang.org/x/crypto from 0.24.0 to 0.27.0 [d768c6e](https://github.com/jcmoraisjr/haproxy-ingress/commit/d768c6e6981fdf6f11d543cdc9bb4c21f89055d0)
* Update client-go and controller-runtime dependencies [#1168](https://github.com/jcmoraisjr/haproxy-ingress/pull/1168) (jcmoraisjr)
* Bump github.com/Masterminds/sprig/v3 from 3.2.3 to 3.3.0 [d949e8e](https://github.com/jcmoraisjr/haproxy-ingress/commit/d949e8e64f1e5b9c40c04d1a51b37369e8b86f9e)
* Bump github.com/prometheus/client_golang from 1.19.1 to 1.20.3 [47b7542](https://github.com/jcmoraisjr/haproxy-ingress/commit/47b75426b3f9c7bc01c183030022eed6de6789ca)
* Bump github.com/prometheus/client_golang from 1.20.3 to 1.20.4 [19d1d95](https://github.com/jcmoraisjr/haproxy-ingress/commit/19d1d957817e21e5f12d6f20f2885490edf46919)
* bump dependencies [#1206](https://github.com/jcmoraisjr/haproxy-ingress/pull/1206) (jcmoraisjr)
* Bump golang.org/x/net from 0.30.0 to 0.33.0 [#1207](https://github.com/jcmoraisjr/haproxy-ingress/pull/1207)
* configure test matrix for haproxy and kubernetes [#1208](https://github.com/jcmoraisjr/haproxy-ingress/pull/1208) (jcmoraisjr)
* update dependencies [f9240c6](https://github.com/jcmoraisjr/haproxy-ingress/commit/f9240c67bcff0796e0f073e2da7958669d01e6b2) (Joao Morais)
* Support list of server crt on tls tcp service [#1171](https://github.com/jcmoraisjr/haproxy-ingress/pull/1171) (jcmoraisjr)
* change integration tests from random ports to sequential [#1209](https://github.com/jcmoraisjr/haproxy-ingress/pull/1209) (jcmoraisjr)
* update docsy to v0.11.0 [29ce839](https://github.com/jcmoraisjr/haproxy-ingress/commit/29ce8398cf003fbb26c78e78b68bee794ed4fcfa) (Joao Morais)
* modernize work queue implementation [#1213](https://github.com/jcmoraisjr/haproxy-ingress/pull/1213) (jcmoraisjr)
* update dependencies [#1221](https://github.com/jcmoraisjr/haproxy-ingress/pull/1221) (jcmoraisjr)
* update go from 1.23.6 to 1.23.7 [fe1f6aa](https://github.com/jcmoraisjr/haproxy-ingress/commit/fe1f6aa7506f18a3646b8a701fa3e6a4687446bd) (Joao Morais)
* change reconciler to a custom type [#1222](https://github.com/jcmoraisjr/haproxy-ingress/pull/1222) (jcmoraisjr)
* improve metrics doc and configuration [#1223](https://github.com/jcmoraisjr/haproxy-ingress/pull/1223) (jcmoraisjr)
* adjust backward compatible debug default version [3259854](https://github.com/jcmoraisjr/haproxy-ingress/commit/3259854c4111a5e9338a4f28accdf393f758ace9) (Joao Morais)
* update k8s dependencies [#1229](https://github.com/jcmoraisjr/haproxy-ingress/pull/1229) (jcmoraisjr)
* allow multiple certificates [#1029](https://github.com/jcmoraisjr/haproxy-ingress/pull/1029) (zanettea)

Chart improvements since `v0.15.0-alpha.3`:

* Allow adding annotations on the ServiceAccount [#82](https://github.com/haproxy-ingress/charts/pull/82) (fredrik-w)
* Set securityContext for haproxy init container [#84](https://github.com/haproxy-ingress/charts/pull/84) (phihos)
* update registry of default backend image [#87](https://github.com/haproxy-ingress/charts/pull/87) (jcmoraisjr)
* Enable deploying external HPA [#89](https://github.com/haproxy-ingress/charts/pull/89) (gdziwoki)
* add gateway status update authorization [#90](https://github.com/haproxy-ingress/charts/pull/90) (jcmoraisjr)
* Add controller.extraServices list [#86](https://github.com/haproxy-ingress/charts/pull/86) (hedgieinsocks)

## Fixes (b1)

* keep restarting leader election [#1210](https://github.com/jcmoraisjr/haproxy-ingress/pull/1210) (jcmoraisjr)
* fix panic if gw does not have a valid class [#1211](https://github.com/jcmoraisjr/haproxy-ingress/pull/1211) (jcmoraisjr)
* fix memory leak on gateway reconciliation [#1212](https://github.com/jcmoraisjr/haproxy-ingress/pull/1212) (jcmoraisjr)
* retry reload haproxy if failed [#1214](https://github.com/jcmoraisjr/haproxy-ingress/pull/1214) (jcmoraisjr)
* add endpoints even if duplicated [#1224](https://github.com/jcmoraisjr/haproxy-ingress/pull/1224) (jcmoraisjr)

# v0.15.0-alpha.3

## Reference (a3)

* Release date: `2024-06-16`
* Helm chart: `--version 0.15.0-alpha.3 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0-alpha.3`
* Image (Docker Hub): `docker.io/jcmoraisjr/haproxy-ingress:v0.15.0-alpha.3`
* Embedded HAProxy version: `2.6.17`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.15.0-alpha.3`

## Release notes (a3)

This is the third and last alpha version of the v0.15 branch. We'll start beta versions soon, when v0.15 will be forked to its own branch, so v0.16 improvements can start shortly in parallel. Regarding v0.16, we are planning to make a really short release, mostly dropping old code base, updating core dependencies, and adding some nice to have features we are still missing. From v0.17 and beyond the plan is to continue with 2 or 3 minor releases per year we used to have.

Find below a list of improvements made since `alpha.2`.

Exclusive v0.15 changes include:

- Master worker mode is true by default, even if external haproxy is not configured. In this mode HAProxy Ingress has a few more configuration options, and it also watches the embedded haproxy process, restarting it in the case it crashes.
- Integration tests
- Gateway API v1 support
- TCPRoute support, from Gateway API
- New leader election implementation, since leader election provided by controller-runtime causes outages when controller looses an election
- New documentation theme version: integration without the need of git submodules, dark theme support, improvements in the design

Other changes already merged to the stable branches:

- Added the steps to configure the embedded HAProxy process to log to stdout, along with controller, useful on dev or small test environments. See [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#syslog)
- Added two distinct helm configurations on the getting started guide: one that uses a service load balancer, another one that uses http(s) ports assigned to the cluster nodes. See [doc](https://haproxy-ingress.github.io/v0.15/docs/getting-started/)

Fixes merged to stable branches:

- Julien fixed the Vary response header, from Cors, when the backend server returns two or more headers
- tomklapka and Jan implemented a more fine-grained response from Coraza WAF
- HAProxy process, when embedded and in master-worker mode, was being prematurely stopped on rolling updates because it was configured in the same pid group of the controller
- Fix backend selection, when a more generic wildcard hostname was being incorrectly chosen, and it collides with a more specific one which uses mTLS
- Secure backend configuration, like backend protocol and client side mTLS, can now be configured globally for all ingress resources
- Auth external configuration can now be configured globally
- Make sure https redirect happens before path redirect when `app-root` is configured

Dependencies:

- embedded haproxy from 2.6.14 to 2.6.17
- client-go from v0.26.6 to v0.30.2
- controller-runtime from v0.14.6 to v0.18.4
- go from 1.19.11 to 1.22.4

## Improvements (a3)

New features and improvements since `v0.15.0-alpha.2`:

* Add gateway version v1beta1 [#994](https://github.com/jcmoraisjr/haproxy-ingress/pull/994) (jcmoraisjr)
* Add a framework for integration tests [#1081](https://github.com/jcmoraisjr/haproxy-ingress/pull/1081) (jcmoraisjr)
* Move leader election to a self managed service [#1087](https://github.com/jcmoraisjr/haproxy-ingress/pull/1087) (jcmoraisjr)
* Status update via merge-patch strategy [#1091](https://github.com/jcmoraisjr/haproxy-ingress/pull/1091) (jcmoraisjr)
* Add Gateway API v1 support [#1102](https://github.com/jcmoraisjr/haproxy-ingress/pull/1102) (jcmoraisjr)
* Update linter [#1104](https://github.com/jcmoraisjr/haproxy-ingress/pull/1104) (jcmoraisjr)
* Add TCPRoute support from Gateway API [#1103](https://github.com/jcmoraisjr/haproxy-ingress/pull/1103) (jcmoraisjr)
* Add net bind capability to haproxy bin [#1096](https://github.com/jcmoraisjr/haproxy-ingress/pull/1096) (jcmoraisjr)
* Add tests for http header generation [#1115](https://github.com/jcmoraisjr/haproxy-ingress/pull/1115) (jcmoraisjr)
* Update RBAC configuration and docs to include leases resource for leader election [#1127](https://github.com/jcmoraisjr/haproxy-ingress/pull/1127) (jzinkweg)
* Add ssl-always-follow-redirect option [#1118](https://github.com/jcmoraisjr/haproxy-ingress/pull/1118) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#ssl-always-add-https)
  * Configuration keys:
    * `ssl-always-follow-redirect`
* Add TLS related integration tests [#1132](https://github.com/jcmoraisjr/haproxy-ingress/pull/1132) (jcmoraisjr)
* Cleanup outdated properties of golangci-lint gh actions plugin [#1140](https://github.com/jcmoraisjr/haproxy-ingress/pull/1140) (Spikhalskiy)
* Upgrade golang from 1.22.2 to 1.22.4 [#1137](https://github.com/jcmoraisjr/haproxy-ingress/pull/1137) (guoard)
* Upgrade embedded haproxy from 2.6.16 to 2.6.17 [#1139](https://github.com/jcmoraisjr/haproxy-ingress/pull/1139) (guoard)
* Change default master-worker config to true [#1134](https://github.com/jcmoraisjr/haproxy-ingress/pull/1134) (jcmoraisjr)
* doc: update docsy from v0.6.0 to v0.10.0 [#1143](https://github.com/jcmoraisjr/haproxy-ingress/pull/1143) (jcmoraisjr)
* Local building improvements [#1135](https://github.com/jcmoraisjr/haproxy-ingress/pull/1135) (jcmoraisjr)
* doc: add haproxy logging to stdout [#1138](https://github.com/jcmoraisjr/haproxy-ingress/pull/1138) (jcmoraisjr)
* update client-go from v0.30.1 to v0.30.2 [0cb2584](https://github.com/jcmoraisjr/haproxy-ingress/commit/0cb2584df1032230f97a75b8c44cecc25ecc7eb8) (Joao Morais)
* doc: add a light weight version of haproxy ingress logo [#1144](https://github.com/jcmoraisjr/haproxy-ingress/pull/1144) (jcmoraisjr)
* doc: reorg items and improve helm values in getting started [#1145](https://github.com/jcmoraisjr/haproxy-ingress/pull/1145) (jcmoraisjr)
* update dependencies [914b581](https://github.com/jcmoraisjr/haproxy-ingress/commit/914b58192a0a76fefc52f46d3a65a608f21ced90) (Joao Morais)

Chart improvements since `v0.15.0-alpha.2`:

* Add support to disable automountServiceAccountToken [#74](https://github.com/haproxy-ingress/charts/pull/74) (jr01)
* Use of automount service account on v1.22 and newer [#75](https://github.com/haproxy-ingress/charts/pull/75) (jcmoraisjr)
* Allow setting the spec.loadBalancerClass of created Services [#77](https://github.com/haproxy-ingress/charts/pull/77) (mlow)
* Allow controller to patch ingress status [#80](https://github.com/haproxy-ingress/charts/pull/80) (jcmoraisjr)
* Fix install output message [#81](https://github.com/haproxy-ingress/charts/pull/81) (jcmoraisjr)

## Fixes (a3)

* Keep all vary header values when adding Origin [#1083](https://github.com/jcmoraisjr/haproxy-ingress/pull/1083) (Jul13nT)
* Fix coraza configuration to use the action variable [#1094](https://github.com/jcmoraisjr/haproxy-ingress/pull/1094) (tomklapka,JanHolger)
* Fix label generation for node discovery [#1116](https://github.com/jcmoraisjr/haproxy-ingress/pull/1116) (jcmoraisjr)
* Ensure https redirect happens before root redirect [#1117](https://github.com/jcmoraisjr/haproxy-ingress/pull/1117) (jcmoraisjr)
* Allows secure backend configuration from global [#1119](https://github.com/jcmoraisjr/haproxy-ingress/pull/1119) (jcmoraisjr)
* Allows to configure auth-url globally [#1120](https://github.com/jcmoraisjr/haproxy-ingress/pull/1120) (jcmoraisjr)
* Move embedded haproxy process to a distinct pid group [#1136](https://github.com/jcmoraisjr/haproxy-ingress/pull/1136) (jcmoraisjr)

# v0.15.0-alpha.2

## Reference (a2)

* Release date: `2023-07-13`
* Helm chart: `--version 0.15.0-alpha.2 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0-alpha.2`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.15.0-alpha.2`
* Embedded HAProxy version: `2.6.14`
* GitHub release: `https://github.com/jcmoraisjr/haproxy-ingress/releases/tag/v0.15.0-alpha.2`

## Release notes (a2)

This is the second tag of the v0.15 branch. Most of the changes are fixes or improvements merged to stable branches. We still have some refactors under development which are prerequisites for a better Gateway API support. Such refactors will also be applied as new configuration keys, benefiting also Ingress workloads.

Exclusive v0.15 changes include:

- Robin Schneider added a new default image for the log sidecar with multi architecture support
- Fix the notification of endpoint changes

Other changes already merged to the stable branches:

- Karan Chaudhary added EndpointSlices support. This option is disabled by default, enable it by adding `--enable-endpointslices-api` command-line option.
- HTTP redirect now has an option to skip some paths, the default configuration adds an exception to `/.well-known/acme-challenge`.
- External HAProxy was failing with the message "cannot open the file '/var/lib/haproxy/crt/default-fake-certificate.pem'.". This happened due to missing permission to read certificate and private key files when HAProxy container starts as non root, which is the default since HAProxy 2.4.
- An update to the External HAProxy example page adds options to fix permission failures to bind ports `:80` and `:443`, see the [example page](https://haproxy-ingress.github.io/v0.15/docs/examples/external-haproxy/#a-word-about-security).

Fixes merged to stable branches:

- ConfigMap based TCP services was randomly missing when the controller started, being reincluded only after the first reconciliation.
- An endless redirect might happen when configuring redirects on domains whose TLS secret declares two or more domains
- Configuration snippet was missing on backends in TCP mode
- ConfigMap based TCP services were making HAProxy to reload without need, depending on the order that service endpoints were being listed
- Unused HAProxy backends might leak in the configuration, depending on how the configuration is changed, when backend sharding is enabled
- A wildcard was not being accepted by the CORS Allowed Header configuration

Dependencies:

- embedded haproxy from 2.6.9 to 2.6.14
- client-go from v0.26.5 to v0.26.6
- controller-runtime from v0.14.4 to v0.14.6
- golang from 1.19.10 to 1.19.11

## Improvements (a2)

New features and improvements since `v0.15.0-alpha.1`:

* Adds support for EndpointSlices API in master [#959](https://github.com/jcmoraisjr/haproxy-ingress/pull/959) (lafolle) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/command-line/#enable-endpointslices-api)
  * Command-line options:
    * `--enable-endpointslices-api`
* Skip acme-challenge path on to/from redirects [#995](https://github.com/jcmoraisjr/haproxy-ingress/pull/995) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#redirect)
  * Configuration keys:
    * `no-redirect-locations`
* Ensure predictable tcp by sorting endpoints [#1003](https://github.com/jcmoraisjr/haproxy-ingress/pull/1003) (jcmoraisjr)
* Change owner of crt/key files to haproxy pid [#1004](https://github.com/jcmoraisjr/haproxy-ingress/pull/1004) (jcmoraisjr)
* Update dependencies [#1006](https://github.com/jcmoraisjr/haproxy-ingress/pull/1006) (mrueg)
* Prefer ingressClassName over annotations in docs [#986](https://github.com/jcmoraisjr/haproxy-ingress/pull/986) (mac-chaffee)
* Add endpointslice api on v0.15 handler [#1013](https://github.com/jcmoraisjr/haproxy-ingress/pull/1013) (jcmoraisjr)
* update golang from 1.19.10 to 1.19.11 [cec71c2](https://github.com/jcmoraisjr/haproxy-ingress/commit/cec71c2f495d31449114c0d2a1513ee826f9cd3f) (Joao Morais)
* update client-go from v0.26.5 to v0.26.6 [ce93e8a](https://github.com/jcmoraisjr/haproxy-ingress/commit/ce93e8a1c408304b3eac4539a0749304b1622153) (Joao Morais)
* update dependencies [925e6b1](https://github.com/jcmoraisjr/haproxy-ingress/commit/925e6b1739e9c9900ba7aca77363ee427e91bf3f) (Joao Morais)

Chart improvements since `v0.15.0-alpha.1`:

* improve log sidecar for multiple architectures [#62](https://github.com/haproxy-ingress/charts/pull/62) (Crisu1710)
* Enables endpointslicesapi [#66](https://github.com/haproxy-ingress/charts/pull/66) (lafolle)
* ignore PodSecurityPolicy on cluster v1.25 or newer [53c8373](https://github.com/haproxy-ingress/charts/commit/53c83735318da4d0dcbba706fdb06cd0a75258ce) (Joao Morais)
* Defaults securityContext to allow privileged ports [#68](https://github.com/haproxy-ingress/charts/pull/68) (jcmoraisjr)
* Revert default securityContext config [#70](https://github.com/haproxy-ingress/charts/pull/70) (jcmoraisjr)
* Add lifecycle hooks to external HAProxy container [#72](https://github.com/haproxy-ingress/charts/pull/72) (bootc)
* chore: update HorizontalPodAutoscaler apiVersion [#71](https://github.com/haproxy-ingress/charts/pull/71) (quarckster)
* add conditional PodDisruptionBudget [#73](https://github.com/haproxy-ingress/charts/pull/73) (jcmoraisjr)

## Fixes (a2)

* Fixes configmap based tcp sync [#1001](https://github.com/jcmoraisjr/haproxy-ingress/pull/1001) (jcmoraisjr)
* Redirect hosts only to domains with associated backends [#1010](https://github.com/jcmoraisjr/haproxy-ingress/pull/1010) (jcmoraisjr)
* fix: config-backend annotation also for TCP-Backends [#1009](https://github.com/jcmoraisjr/haproxy-ingress/pull/1009) (genofire)
* Create endpoints on a predictable order [#1011](https://github.com/jcmoraisjr/haproxy-ingress/pull/1011) (jcmoraisjr)
* Remove generation predicate on endpoints [#1012](https://github.com/jcmoraisjr/haproxy-ingress/pull/1012) (jcmoraisjr)
* Fix shard render when the last backend is removed [#1015](https://github.com/jcmoraisjr/haproxy-ingress/pull/1015) (jcmoraisjr)
* Add wildcard as a valid cors allowed header [#1016](https://github.com/jcmoraisjr/haproxy-ingress/pull/1016) (jcmoraisjr)

# v0.15.0-alpha.1

## Reference (a1)

* Release date: `2023-02-20`
* Helm chart: `--version 0.15.0-alpha.1 --devel`
* Image (Quay): `quay.io/jcmoraisjr/haproxy-ingress:v0.15.0-alpha.1`
* Image (Docker Hub): `jcmoraisjr/haproxy-ingress:v0.15.0-alpha.1`
* Embedded HAProxy version: `2.6.9`

## Release notes (a1)

This is the first tag of the v0.15 branch, which brings most, if not all the breaking changes expected to the v0.15 release:

- Controller now starts as the non root `haproxy` user.
- `haproxy` user ID was changed from `1001` to `99`.
- ElectionID changed for leader election.
- Helm chart has now two separated fields for registry and repository of a container image.
- Log now uses level 2 by default, a low verbosity level with useful debugging info.

See [upgrade notes](https://github.com/jcmoraisjr/haproxy-ingress/blob/master/CHANGELOG/CHANGELOG-v0.15.md#upgrade-notes) for detailed info and before update your environment.

Besides that, the following areas had some improvement since v0.14:

- Embedded and default external HAProxy version was updated to 2.6 instead of the expected 2.5. Non-LTS HAProxy, just like 2.3 and 2.5, have a short lifecycle and we're a few cycles behind their releases. Our plan is to start to release about 2 minor versions per year again, following HAProxy Community Edition releases, so we should expect our v0.16 using HAProxy 2.6 as well. Future controller versions might start to use non LTS again in the future, provided that we're close enough to their release cycle and we don't have a newer LTS version to use instead.
- HTTP header match is a long awaited feature that needed a few internal refactors to work properly. This is one of the challenging implementations for the Gateway API, which's available for Ingress resources as well. See the [HTTP header match documentation](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#http-match) for usage examples.
- HAProxy Ingress now uses [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) as the engine that watches and notifies resource changes. This is a huge internal change that improves code quality and organization, but with almost no externally visible change. The most impacted feature is the Ingress Status Update, which should be rewritten from scratch in order to fit the new controller engine. Give this a few more attention and let us know if you found any problem via our Slack channel, mailing list, or opening a new GitHub issue.

## Improvements (a1)

New features and improvements since `v0.14.2`:

* update embedded haproxy from 2.4.18 to 2.5.8 [6b0a10a](https://github.com/jcmoraisjr/haproxy-ingress/commit/6b0a10a90bd099cf0d27735335b3b4b1b86c5cd4) (Joao Morais)
* update golang from 1.17.13 to 1.19.1 [781dd7e](https://github.com/jcmoraisjr/haproxy-ingress/commit/781dd7e5d20403bda73cfe8c2c47ca77e7f61ea2) (Joao Morais)
* update client-go from v0.23.10 to v0.25.0 [c7d8ae3](https://github.com/jcmoraisjr/haproxy-ingress/commit/c7d8ae39fe4d6e4850a3ef548f1059ee7a8b06c4) (Joao Morais)
* update go mod from 1.17 to 1.19 [2d2cb4e](https://github.com/jcmoraisjr/haproxy-ingress/commit/2d2cb4e247ab0b6af8d0b64377956c3bc23cc83c) (Joao Morais)
* Add http-header-match annotation [#944](https://github.com/jcmoraisjr/haproxy-ingress/pull/944) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#http-match)
  * Configuration keys:
    * `http-header-match`
    * `http-header-match-regex`
* Update gateway-api from v0.4.1 v0.5.0 [#947](https://github.com/jcmoraisjr/haproxy-ingress/pull/947) (jcmoraisjr)
* Update to hugo v0.110.0 and update node deps [#968](https://github.com/jcmoraisjr/haproxy-ingress/pull/968) (mac-chaffee)
* Add controller-runtime support [#933](https://github.com/jcmoraisjr/haproxy-ingress/pull/933) (jcmoraisjr)
* Add source IP related config keys [#987](https://github.com/jcmoraisjr/haproxy-ingress/pull/987) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#forwardfor)
  * Configuration keys:
    * `original-forwarded-for-hdr`
    * `real-ip-hdr`
* update client-go from v0.25.0 to v0.26.1 [1e2fc75](https://github.com/jcmoraisjr/haproxy-ingress/commit/1e2fc75beee9d44f808ae9c5a12b3b2f3fe8ed8b) (Joao Morais)
* update embedded haproxy from 2.5.8 to 2.6.9 [2842a74](https://github.com/jcmoraisjr/haproxy-ingress/commit/2842a74eb98672896a313a93c8e752fbb69f6f74) (Joao Morais)
* Add optional frontend based external authentication call [#988](https://github.com/jcmoraisjr/haproxy-ingress/pull/988) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.15/docs/configuration/keys/#auth-external)
  * Configuration keys:
    * `auth-external-placement`
* update go from 1.19.1 to 1.19.6 [3a8edee](https://github.com/jcmoraisjr/haproxy-ingress/commit/3a8edee35e0a865f4d05bc5b38b2b5b79fe9e0e6) (Joao Morais)
* Change controller container to non root user [#992](https://github.com/jcmoraisjr/haproxy-ingress/pull/992) (jcmoraisjr)

Chart improvements since `v0.14.2`:

* Allow customFiles to be used without custom template [#57](https://github.com/haproxy-ingress/charts/pull/57) (ironashram)
* Add permissions for leases, needed by leaderelection [#58](https://github.com/haproxy-ingress/charts/pull/58) (mac-chaffee)
* Fix securityContext conditional in default backend [#60](https://github.com/haproxy-ingress/charts/pull/60) (doriath)
* Parameterize container port and add missing configs on default backend and prometheus [#59](https://github.com/haproxy-ingress/charts/pull/59) (blafry)
* Extracted registry value to a separate variable [#61](https://github.com/haproxy-ingress/charts/pull/61) (blafry)

## Fixes (a1)

* Skip status update when update-status is false [#991](https://github.com/jcmoraisjr/haproxy-ingress/pull/991) (jcmoraisjr)
