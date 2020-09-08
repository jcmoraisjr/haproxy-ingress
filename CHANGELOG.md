# CHANGELOG

## v0.11

**Highlights of this version**

* HAProxy upgrade from 2.0 to 2.1.
* Negligible IO, CPU usage and reconciliation time, regardless the number of tracked ingress and service objects.
  * HAProxy Ingress deployed on noisy (about 10 reconciliations per minute) and big (about 4000 ingress and services) clusters used to use about 90% CPU. HAProxy Ingress v0.11 uses about 2% CPU on such clusters when using [backend shards](https://haproxy-ingress.github.io/v0.11/docs/configuration/command-line/#backend-shards).
* Ingress API upgrade from `extensions/v1beta1` to `networking.k8s.io/v1beta1`.

**Breaking backward compatibility from [v0.10](#v010)**

* Kubernetes version 1.14 or newer
* HAProxy Ingress service account need `get`, `list`, `watch` and `update` access to `networking.k8s.io` api group - which was the same permissions granted to `extensions/v1beta1` api group. Update your k8s role configuration before deploy v0.11. See an updated version of the [deployment manifest](https://raw.githubusercontent.com/jcmoraisjr/haproxy-ingress/2b3cc6701b27866acd9db35cbbd0c4de114aaec2/docs/static/resources/haproxy-ingress.yaml).
* Major refactor in the haproxy's frontents with the following visible changes:
  * Internal proxy names changed, which will impact metric dashboards that use these names
  * Internal map file names changed, which will impact configuration snippets that use them
* `timeout-client` and `timeout-client-fin` are global scoped only - cannot use as an ingress annotation.
* Template path changed, see the template [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/template/).

**Contributors**

* Alexis Dufour ([AlexisDuf](https://github.com/AlexisDuf))
* Colin Deasy ([coldeasy](https://github.com/coldeasy))
* Dario Tranchitella ([prometherion](https://github.com/prometherion))
* Eliot Hautefeuille ([hileef](https://github.com/hileef))
* Joao Morais ([jcmoraisjr](https://github.com/jcmoraisjr))
* MartinKirchner ([MartinKirchner](https://github.com/MartinKirchner))
* Ricardo Katz ([rikatz](https://github.com/rikatz))
* Robert Agbozo ([RobertTheProfessional](https://github.com/RobertTheProfessional))
* Shagon94 ([Shagon94](https://github.com/Shagon94))
* Unichron ([Unichron](https://github.com/Unichron))

### v0.11-beta.1

New features and improvements:

* Update to haproxy 2.1.4 [#542](https://github.com/jcmoraisjr/haproxy-ingress/pull/542) (jcmoraisjr)
* Converting to cache.Listers [#545](https://github.com/jcmoraisjr/haproxy-ingress/pull/545) (prometherion)
* Sorting imports and code linting [#550](https://github.com/jcmoraisjr/haproxy-ingress/pull/550) (prometherion)
* Change timeout-client(-fin) scope from host to global [#552](https://github.com/jcmoraisjr/haproxy-ingress/pull/552) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#timeout)
  * Configuration keys:
    * `timeout-client` (update)
    * `timeout-client-fin` (update)
* Remove frontend group [#553](https://github.com/jcmoraisjr/haproxy-ingress/pull/553) (jcmoraisjr)
* Move backend data and funcs to its own entity [#555](https://github.com/jcmoraisjr/haproxy-ingress/pull/555) (jcmoraisjr)
* Add host lookup with hash table [#556](https://github.com/jcmoraisjr/haproxy-ingress/pull/556) (jcmoraisjr)
* Add backend lookup with hash table [#557](https://github.com/jcmoraisjr/haproxy-ingress/pull/557) (jcmoraisjr)
* Move max body size to the backend [#554](https://github.com/jcmoraisjr/haproxy-ingress/pull/554) (jcmoraisjr)
* Parsing and lookup optimizations [#558](https://github.com/jcmoraisjr/haproxy-ingress/pull/558) (jcmoraisjr)
* Follow gofmt convention [#564](https://github.com/jcmoraisjr/haproxy-ingress/pull/564) (jcmoraisjr)
* Move listers and informers to the new controller [#563](https://github.com/jcmoraisjr/haproxy-ingress/pull/563) (jcmoraisjr)
* Add check interval on tcp service [#576](https://github.com/jcmoraisjr/haproxy-ingress/pull/576) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/command-line/#tcp-services-configmap)
  * Command-line options:
    * `--tcp-services-configmap` (update)
* Add use-forwarded-proto config key [#577](https://github.com/jcmoraisjr/haproxy-ingress/pull/577) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#fronting-proxy-port)
  * Configuration keys:
    * `use-forwarded-proto`
* Add headers config key [#575](https://github.com/jcmoraisjr/haproxy-ingress/pull/575) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#headers)
  * Configuration keys:
    * `headers`
* Allow overriding CPU Map [#588](https://github.com/jcmoraisjr/haproxy-ingress/pull/588) (coldeasy) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#cpu-map)
  * Configuration keys:
    * `cpu-map`
    * `use-cpu-map`
* TCP Services : SSL : Optionally Verify Client [#589](https://github.com/jcmoraisjr/haproxy-ingress/pull/589) (hileef) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/command-line/#tcp-services-configmap)
  * Command-line options:
    * `--tcp-services-configmap` (update)
* Add session-cookie-keywords [#601](https://github.com/jcmoraisjr/haproxy-ingress/pull/601) (MartinKirchner) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#affinity)
  * Configuration keys:
    * `session-cookie-keywords`
* Host scoped cipher options [#609](https://github.com/jcmoraisjr/haproxy-ingress/pull/609) (Unichron) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#ssl-ciphers)
  * Configuration keys:
    * `ssl-cipher-suites`
    * `ssl-ciphers`
* Update deprecated APIs in Docs [#613](https://github.com/jcmoraisjr/haproxy-ingress/pull/613) (rikatz)
* Improve parsing time on big clusters [#571](https://github.com/jcmoraisjr/haproxy-ingress/pull/571) (jcmoraisjr)
* Add backend-shards command-line option [#623](https://github.com/jcmoraisjr/haproxy-ingress/pull/623) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/command-line/#backend-shards)
  * Command-line options:
    * `--backend-shards`
* Add disable-pod-list command-line option [#622](https://github.com/jcmoraisjr/haproxy-ingress/pull/622) (jcmoraisjr) - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/command-line/#disable-pod-list)
  * Command-line options:
    * `--disable-pod-list`
* Log changed objects [#625](https://github.com/jcmoraisjr/haproxy-ingress/pull/625) (jcmoraisjr)
* Optimize haproxy maps building [#629](https://github.com/jcmoraisjr/haproxy-ingress/pull/629) (jcmoraisjr)
* Shrink list of changed hosts and backends [#630](https://github.com/jcmoraisjr/haproxy-ingress/pull/630) (jcmoraisjr)
* Host scope tls-alpn and ssl-options [#617](https://github.com/jcmoraisjr/haproxy-ingress/pull/617) (Unichron)
  * Configuration keys:
    * `ssl-options-backend` - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#ssl-options)
    * `ssl-options-host` - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#ssl-options)
    * `tls-alpn` - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#tls-alpn)
* Update to haproxy 2.1.8 [#635](https://github.com/jcmoraisjr/haproxy-ingress/pull/635) (jcmoraisjr)
* Partial build of backend maps [#637](https://github.com/jcmoraisjr/haproxy-ingress/pull/637) (jcmoraisjr)
* Update to client-go v0.18.6 [#638](https://github.com/jcmoraisjr/haproxy-ingress/pull/638) (jcmoraisjr)
* Update to go1.13.15 [#640](https://github.com/jcmoraisjr/haproxy-ingress/pull/640) (jcmoraisjr)
* Add support to multiple match types [#641](https://github.com/jcmoraisjr/haproxy-ingress/pull/641) (jcmoraisjr)
  * Configuration keys:
    * `path-type` - [doc](https://haproxy-ingress.github.io/v0.11/docs/configuration/keys/#path-type)
* Improve backend shrinking [#644](https://github.com/jcmoraisjr/haproxy-ingress/pull/644) (jcmoraisjr)
* Improve time of frontend maps build [#647](https://github.com/jcmoraisjr/haproxy-ingress/pull/647) (jcmoraisjr)
* Move files to /etc, /var/lib or /var/run dirs [#654](https://github.com/jcmoraisjr/haproxy-ingress/pull/654) (jcmoraisjr)
* Add wait-before-update command-line option [#658](https://github.com/jcmoraisjr/haproxy-ingress/pull/658) (jcmoraisjr)

Fixes:

* Fix logging messages [#559](https://github.com/jcmoraisjr/haproxy-ingress/pull/559) (jcmoraisjr)
* Fix server-alias on http/80 [#570](https://github.com/jcmoraisjr/haproxy-ingress/pull/570) (AlexisDuf)
* Fix permission using watch-namespace [#578](https://github.com/jcmoraisjr/haproxy-ingress/pull/578) (jcmoraisjr)
* Fix watch-namespace option [#579](https://github.com/jcmoraisjr/haproxy-ingress/pull/579) (jcmoraisjr)
* Fix cleaning cache of changed objects [#626](https://github.com/jcmoraisjr/haproxy-ingress/pull/626) (jcmoraisjr)
* Configure default crt on ingress parsing phase [#634](https://github.com/jcmoraisjr/haproxy-ingress/pull/634) (jcmoraisjr)
* Add hostname and backend tracking on addIngress [#646](https://github.com/jcmoraisjr/haproxy-ingress/pull/646) (jcmoraisjr)
* Fix sigsegv tracking added ingress [#648](https://github.com/jcmoraisjr/haproxy-ingress/pull/648) (jcmoraisjr)
* Add implicit starting boundary char in regex path match [#651](https://github.com/jcmoraisjr/haproxy-ingress/pull/651) (jcmoraisjr)
* Fix tracking and partial parsing of spec.backend [#653](https://github.com/jcmoraisjr/haproxy-ingress/pull/653) (jcmoraisjr)
* Fix ssl-passthrough counter [#656](https://github.com/jcmoraisjr/haproxy-ingress/pull/656) (jcmoraisjr)

Docs:

* Fixed typos [#580](https://github.com/jcmoraisjr/haproxy-ingress/pull/580) (Shagon94)
* Typo on configuration keys docs [#585](https://github.com/jcmoraisjr/haproxy-ingress/pull/585) (RobertTheProfessional)

## v0.10

Highlights of this version:

* HAProxy upgrade from 1.9 to 2.0
* Metrics:
  * HAProxy's internal Prometheus exporter, see the [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#bind-port)
  * HAProxy Ingress exporter for Prometheus
  * HAProxy Ingress dashboard for Grafana, see the [metrics example](https://haproxy-ingress.github.io/docs/examples/metrics/)

### v0.10-beta.1

New features and improvements:

* Update to haproxy 2.0.11 [#414](https://github.com/jcmoraisjr/haproxy-ingress/pull/414)
* Remove v0.7 controller [#483](https://github.com/jcmoraisjr/haproxy-ingress/pull/483)
* Add frontend to the internal prometheus exporter [#486](https://github.com/jcmoraisjr/haproxy-ingress/pull/486)
  * Configuration keys:
    * `bind-ip-addr-prometheus` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#bind-ip-addr)
    * `prometheus-port` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#bind-port)
* Defaults to not create prometheus listener [#491](https://github.com/jcmoraisjr/haproxy-ingress/pull/491)
* Metric collector and exporter [#487](https://github.com/jcmoraisjr/haproxy-ingress/pull/487) - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#stats)
  * Command-line options:
    * `--healthz-port`
    * `--profiling`
    * `--stats-collect-processing-period`
* Change unix sockets user to haproxy [#504](https://github.com/jcmoraisjr/haproxy-ingress/pull/504)
* Add CN label in the cert_expire metric [#501](https://github.com/jcmoraisjr/haproxy-ingress/pull/501)
* Sort tcp services by name and port [#506](https://github.com/jcmoraisjr/haproxy-ingress/pull/506)
* Add backend-server-naming key [#507](https://github.com/jcmoraisjr/haproxy-ingress/pull/507) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#backend-server-naming)
  * Configuration keys:
    * `backend-server-naming`
* Add ssl-redirect-code global config key [#511](https://github.com/jcmoraisjr/haproxy-ingress/pull/511) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#ssl-redirect)
  * Configuration keys:
    * `ssl-redirect-code`
* Add modsecurity timeout connect/server [#512](https://github.com/jcmoraisjr/haproxy-ingress/pull/512) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#modsecurity)
  * Configuration keys:
    * `modsecurity-timeout-connect`
    * `modsecurity-timeout-server`
* Add ssl-fingerprint-lower config key [#515](https://github.com/jcmoraisjr/haproxy-ingress/pull/515) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#auth-tls)
  * Configuration keys:
    * `ssl-fingerprint-lower`
* Remove haproxy warning filter [#514](https://github.com/jcmoraisjr/haproxy-ingress/pull/514)
* Create frontends even without ingress [#516](https://github.com/jcmoraisjr/haproxy-ingress/pull/516)
* Add auth-tls-strict configuration key [#513](https://github.com/jcmoraisjr/haproxy-ingress/pull/513) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#auth-tls)
  * Configuration keys:
    * `auth-tls-strict`
* Update to haproxy 2.0.12 [#518](https://github.com/jcmoraisjr/haproxy-ingress/pull/518)
* Update to haproxy 2.0.13 [#521](https://github.com/jcmoraisjr/haproxy-ingress/pull/521)
* Ignore ingresses without specified class [#527](https://github.com/jcmoraisjr/haproxy-ingress/pull/527) - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#ignore-ingress-without-class)
  * Command-line options:
    * `--ignore-ingress-without-class`
* Improve certificate sign logs [#533](https://github.com/jcmoraisjr/haproxy-ingress/pull/533)
* Add cert signing metrics [#535](https://github.com/jcmoraisjr/haproxy-ingress/pull/535)
* Add buckets-response-time command-line option [#537](https://github.com/jcmoraisjr/haproxy-ingress/pull/537) - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#buckets-response-time)
  * Command-line options:
    * `--buckets-response-time`
* Add external call to certificate check [#539](https://github.com/jcmoraisjr/haproxy-ingress/pull/#539) - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#stats)
* docs: add crt signing metrics in the dashboard [#540](https://github.com/jcmoraisjr/haproxy-ingress/pull/#540) - [doc](https://haproxy-ingress.github.io/docs/examples/metrics/)
* Update HAProxy from 2.0.13 to 2.0.14, which fixes CVE-2020-11100
* Add check interval on tcp service [#576](https://github.com/jcmoraisjr/haproxy-ingress/pull/576)
  * Command-line option:
    * `--tcp-services-configmap` (update) - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#tcp-services-configmap)
* Add use-forwarded-proto config key [#577](https://github.com/jcmoraisjr/haproxy-ingress/pull/577)
  * Configuration keys:
    *  `use-forwarded-proto` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#fronting-proxy-port)

Fixes:

* Fix TLS handshake on backend [#520](https://github.com/jcmoraisjr/haproxy-ingress/pull/520)
* Update crt metric if date changes [#524](https://github.com/jcmoraisjr/haproxy-ingress/pull/524)
* Clear acme work queue on stopped leading [#526](https://github.com/jcmoraisjr/haproxy-ingress/pull/526)
* Restart the leader elector when stop leading [#532](https://github.com/jcmoraisjr/haproxy-ingress/pull/532)
* Fix race on failure rate limit queue [#534](https://github.com/jcmoraisjr/haproxy-ingress/pull/534)
* Fix processing count metric name [#536](https://github.com/jcmoraisjr/haproxy-ingress/pull/536)
* Fix label naming of cert signing metric [#538](https://github.com/jcmoraisjr/haproxy-ingress/pull/#538)
* Fix logging messages [#559](https://github.com/jcmoraisjr/haproxy-ingress/pull/559)
* Fix server-alias on http/80 [#570](https://github.com/jcmoraisjr/haproxy-ingress/pull/570)
* Fix permission using watch-namespace [#578](https://github.com/jcmoraisjr/haproxy-ingress/pull/578)

### v0.10-beta.2

Fixes and improvements since [v0.10-beta.1](#v010-beta1):

* Allow overriding CPU Map [#588](https://github.com/jcmoraisjr/haproxy-ingress/pull/588) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#cpu-map)
  * Configuration keys:
    * `cpu-map`
    * `use-cpu-map`
* TCP Services : SSL : Optionally Verify Client [#589](https://github.com/jcmoraisjr/haproxy-ingress/pull/589) - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#tcp-services-configmap)
* Update haproxy from 2.0.14 to 2.0.15

### v0.10-beta.3

Fixes and improvements since [v0.10-beta.2](#v010-beta2):

* Update haproxy from 2.0.15 to 2.0.17
* Add service event handler [#633](https://github.com/jcmoraisjr/haproxy-ingress/pull/633)
* Configure default crt on ingress parsing phase [#634](https://github.com/jcmoraisjr/haproxy-ingress/pull/634)

## v0.9.1

Fixes and improvements since [v0.9](#v09):

* Update HAProxy from 1.9.15 to 1.9.16
* Add service event handler [#633](https://github.com/jcmoraisjr/haproxy-ingress/pull/633)
* Configure default crt on ingress parsing phase [#634](https://github.com/jcmoraisjr/haproxy-ingress/pull/634)

Docs:

* Typo on configuration keys docs [#585](https://github.com/jcmoraisjr/haproxy-ingress/pull/585)

## v0.9

### v0.9-beta.1

Breaking backward compatibility from [v0.8](#v08):

* TLS 1.0 and 1.1 was dropped in the default configuration. Several cipher suites was dropped as well, mostly non ephemeral key exchange algorithms. This might break old http clients. See the v0.8 default values in the [SSL cipher suite](https://haproxy-ingress.github.io/docs/configuration/keys/#ssl-ciphers) and [SSL options](https://haproxy-ingress.github.io/docs/configuration/keys/#ssl-options) docs and adjust the configuration if needed.
* Some default configurations was changed to improve performance of a vanilla deployment, this might cause unexpected behaviour:
  * Default `dynamic-scaling` configuration key was changed from `false` to `true`
  * Default `nbthread` configuration key was changed from `1` to `2`
  * Default `--reload-strategy` command-line option was changed from `native` to `reusesocket`

Highlights of this version:

* HAProxy upgrade from 1.8 to 1.9
* HTTP/2 support in the backend side
* TLS 1.3 support
* Certificate update using ACME-v2 protocol
* Ability to run as non-root, see the [security](https://haproxy-ingress.github.io/docs/configuration/keys/#security) doc

New features:

* Use one bind per frontend [#382](https://github.com/jcmoraisjr/haproxy-ingress/pull/382)
* Update to haproxy 1.9.10 [#381](https://github.com/jcmoraisjr/haproxy-ingress/pull/381)
* Add h2 backend proto and use-htx global option [#387](https://github.com/jcmoraisjr/haproxy-ingress/pull/387)
  * Configuration keys:
    * `ingress.kubernetes.io/backend-protocol` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#backend-protocol)
    * `use-htx` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#use-htx)
* Make sni optional if a certificate is optional and is not provided [#392](https://github.com/jcmoraisjr/haproxy-ingress/pull/392)
* Add custom-frontend snippet to http:80 frontend [#395](https://github.com/jcmoraisjr/haproxy-ingress/pull/395)
* Join samples using concat [#393](https://github.com/jcmoraisjr/haproxy-ingress/pull/393)
* Use 421 response if sni and headers does not match [#394](https://github.com/jcmoraisjr/haproxy-ingress/pull/394)
* Add syslog-length configmap option [#396](https://github.com/jcmoraisjr/haproxy-ingress/pull/396) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#syslog)
  * Configuration keys:
    * `ingress.kubernetes.io/syslog-length`
* Add CRL Support in the TLS Secret for Client Authentication [#328](https://github.com/jcmoraisjr/haproxy-ingress/pull/328)
* Add CRL support in the new controller [#399](https://github.com/jcmoraisjr/haproxy-ingress/pull/399)
  * Configuration keys:
    * `ingress.kubernetes.io/auth-tls-secret` - new optional file `ca.crl` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#auth-tls)
    * `ingress.kubernetes.io/secure-verify-ca-secret` - new optional file `ca.crl` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#secure-backend)
* Add per request deployment group selection - blue/green deployment [#402](https://github.com/jcmoraisjr/haproxy-ingress/pull/402) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#blue-green)
  * Configuration keys:
    * `ingress.kubernetes.io/blue-green-cookie`
    * `ingress.kubernetes.io/blue-green-header`
* Sort ingress using creation timestamp [#405](https://github.com/jcmoraisjr/haproxy-ingress/pull/405)
* Update default TLS versions and ciphers for client and server connections [#403](https://github.com/jcmoraisjr/haproxy-ingress/pull/403) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#ssl-ciphers)
  * Configuration keys:
    * `ssl-cipher-suites`
    * `ssl-cipher-suites-backend`
    * `ssl-ciphers-backend`
* Update to haproxy 1.9.11 [#406](https://github.com/jcmoraisjr/haproxy-ingress/pull/406)
* Add session-cookie-shared [#419](https://github.com/jcmoraisjr/haproxy-ingress/pull/419)
* Add dynamic-scaling false option [#420](https://github.com/jcmoraisjr/haproxy-ingress/pull/420)
* Improve sorting of internal state [#423](https://github.com/jcmoraisjr/haproxy-ingress/pull/423)
* Tuning default thread number and reload strategy [#424](https://github.com/jcmoraisjr/haproxy-ingress/pull/424)
* Add leader election [#431](https://github.com/jcmoraisjr/haproxy-ingress/pull/431)
* Add work queue [#430](https://github.com/jcmoraisjr/haproxy-ingress/pull/430)
* Add forwardfor option - update [#437](https://github.com/jcmoraisjr/haproxy-ingress/pull/437) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#forwardfor)
  * Configuration keys:
    * `ingress.kubernetes.io/forwardfor` - new option `update`
* Add support for Mod Security DetectionOnly Mode [#443](https://github.com/jcmoraisjr/haproxy-ingress/pull/443) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#waf)
  * Configuration keys:
    * `ingress.kubernetes.io/waf-mode`
* Add initial-weight config key [#444](https://github.com/jcmoraisjr/haproxy-ingress/pull/444)
* Improve fronting proxy config [#434](https://github.com/jcmoraisjr/haproxy-ingress/pull/434)
* Update Go version and use Go mod [#439](https://github.com/jcmoraisjr/haproxy-ingress/pull/439)
* Update to haproxy 1.9.12 [#446](https://github.com/jcmoraisjr/haproxy-ingress/pull/446)
* Initialize leader election only if needed [#447](https://github.com/jcmoraisjr/haproxy-ingress/pull/447)
* Add ip+port bind support for http/https/fronting-proxy [#452](https://github.com/jcmoraisjr/haproxy-ingress/pull/452)
* Add failure rate limit on work queue [#457](https://github.com/jcmoraisjr/haproxy-ingress/pull/457)
* Customizable goarch [#472](https://github.com/jcmoraisjr/haproxy-ingress/pull/472)
* dumb-init added from alpine repo [#471](https://github.com/jcmoraisjr/haproxy-ingress/pull/471)
* Add acme v02 support [#391](https://github.com/jcmoraisjr/haproxy-ingress/pull/391)
  * Configuration keys - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#acme):
    * `acme-emails`
    * `acme-endpoint`
    * `acme-expiring`
    * `acme-shared`
    * `acme-terms-agreed`
    * `ingress.kubernetes.io/cert-signer`
  * Command-line options - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#acme):
    * `--acme-check-period`
    * `--acme-election-id`
    * `--acme-fail-initial-duration`
    * `--acme-fail-max-duration`
    * `--acme-secret-key-name`
    * `--acme-server`
    * `--acme-token-configmap-name`
    * `--acme-track-tls-annotation`
* Update to haproxy 1.9.13 [#475](https://github.com/jcmoraisjr/haproxy-ingress/pull/475)
* Update dependencies to k8s 1.16.3 [#474](https://github.com/jcmoraisjr/haproxy-ingress/pull/474)
* Add 4xx error pages and CORS Preflight as Lua services [#481](https://github.com/jcmoraisjr/haproxy-ingress/pull/481)
* Check acme account before retrieving [#479](https://github.com/jcmoraisjr/haproxy-ingress/pull/479)
* Improve equality comparison with acme changes [#478](https://github.com/jcmoraisjr/haproxy-ingress/pull/478)
* Add security options [#484](https://github.com/jcmoraisjr/haproxy-ingress/pull/484) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#security)
  * Configuration keys:
    * `use-chroot`
    * `use-haproxy-user`

Fixes:

* Fix case on requests from 80/http [#425](https://github.com/jcmoraisjr/haproxy-ingress/pull/425)
* Fix case on per-path backend requests [#427](https://github.com/jcmoraisjr/haproxy-ingress/pull/427)
* Fix cross-namespace command-line option [#433](https://github.com/jcmoraisjr/haproxy-ingress/pull/433)
* Fix host match with a port number [#436](https://github.com/jcmoraisjr/haproxy-ingress/pull/436)
* Fix hostname match of domains with client cert auth [#453](https://github.com/jcmoraisjr/haproxy-ingress/pull/453)
* Fix panic reading empty targetRef from ep [#455](https://github.com/jcmoraisjr/haproxy-ingress/pull/455)
* Fix txn.namespace on http requests [#463](https://github.com/jcmoraisjr/haproxy-ingress/pull/463)
* Do ssl-redirect only if tls declares the hostname [#465](https://github.com/jcmoraisjr/haproxy-ingress/pull/465)
* Fix case on per-path backend maps [#466](https://github.com/jcmoraisjr/haproxy-ingress/pull/466)
* Use the found match pattern [#468](https://github.com/jcmoraisjr/haproxy-ingress/pull/468)
* Improve response error on sni mismatch [#470](https://github.com/jcmoraisjr/haproxy-ingress/pull/470)
* Fix haproxy.cfg permissions [#476](https://github.com/jcmoraisjr/haproxy-ingress/pull/476)

Docs:

* docs: update deployment and DaemonSet APIs to apps/v1 [#415](https://github.com/jcmoraisjr/haproxy-ingress/pull/415)
* docs: starting version [#417](https://github.com/jcmoraisjr/haproxy-ingress/pull/417)
* docs: update deploy and ds api to apps/v1 [#422](https://github.com/jcmoraisjr/haproxy-ingress/pull/422)
* docs: defaults for cors-allow-methods and -headers [#445](https://github.com/jcmoraisjr/haproxy-ingress/pull/445)

### v0.9-beta.2

Fixes and improvements since [v0.9-beta.1](#v09-beta1):

* Change unix sockets user to haproxy [#504](https://github.com/jcmoraisjr/haproxy-ingress/pull/504)
* Sort tcp services by name and port [#506](https://github.com/jcmoraisjr/haproxy-ingress/pull/506)
* Add backend-server-naming key [#507](https://github.com/jcmoraisjr/haproxy-ingress/pull/507) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#backend-server-naming)
  * Configuration keys:
    * `backend-server-naming`
* Add auth-tls-strict configuration key [#513](https://github.com/jcmoraisjr/haproxy-ingress/pull/513) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#auth-tls)
  * Configuration keys:
    * `auth-tls-strict`
* Remove haproxy warning filter [#514](https://github.com/jcmoraisjr/haproxy-ingress/pull/514)
* Create frontends even without ingress [#516](https://github.com/jcmoraisjr/haproxy-ingress/pull/516)

### v0.9-beta.3

Fixes and improvements since [v0.9-beta.2](#v09-beta2):

* Fix TLS handshake on backend [#520](https://github.com/jcmoraisjr/haproxy-ingress/pull/520)
* Update haproxy from 1.9.13 to 1.9.14
* Clear acme work queue on stopped leading [#526](https://github.com/jcmoraisjr/haproxy-ingress/pull/526)
* Restart the leader elector when stop leading [#532](https://github.com/jcmoraisjr/haproxy-ingress/pull/532)
* Improve certificate sign logs [#533](https://github.com/jcmoraisjr/haproxy-ingress/pull/533)
* Fix race on failure rate limit queue [#534](https://github.com/jcmoraisjr/haproxy-ingress/pull/534)

### v0.9-beta.4

Fixes and improvements since [v0.9-beta.3](#v09-beta3):

* Add external call to certificate check [#539](https://github.com/jcmoraisjr/haproxy-ingress/pull/#539) - [doc](https://haproxy-ingress.github.io/docs/configuration/command-line/#stats)
* Update HAProxy from 1.9.14 to 1.9.15, which fixes CVE-2020-11100

### v0.9-post-beta.4 (match v0.9)

Fixes and improvements since [v0.9-beta.4](#v09-beta4):

* Fix logging messages [#559](https://github.com/jcmoraisjr/haproxy-ingress/pull/559)
* Fix server-alias on http/80 [#570](https://github.com/jcmoraisjr/haproxy-ingress/pull/570)

## v0.8.5

Fixes and improvements since [v0.8.4](#v084):

* Add service event handler [#633](https://github.com/jcmoraisjr/haproxy-ingress/pull/633)
* Configure default crt on ingress parsing phase [#634](https://github.com/jcmoraisjr/haproxy-ingress/pull/634)

## v0.8.4

Fixes and improvements since [v0.8.3](#v083):

* Fix server-alias on http/80 [#570](https://github.com/jcmoraisjr/haproxy-ingress/pull/570)

## v0.8.3

Fixes and improvements since [v0.8.2](#v082):

* Update HAProxy from 1.8.24 to 1.8.25, which fixes CVE-2020-11100

## v0.8.2

Fixes and improvements since [v0.8.1](#v081):

* Update HAProxy from 1.8.23 to 1.8.24

## v0.8.1

Fixes and improvements since [v0.8](#v08):

* Sort tcp services by name and port [#506](https://github.com/jcmoraisjr/haproxy-ingress/pull/506)
* Add backend-server-naming key [#507](https://github.com/jcmoraisjr/haproxy-ingress/pull/507) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#backend-server-naming)
  * Configuration keys:
    * `backend-server-naming`
* Add auth-tls-strict configuration key [#513](https://github.com/jcmoraisjr/haproxy-ingress/pull/513) - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#auth-tls)
  * Configuration keys:
    * `auth-tls-strict`
* Remove haproxy warning filter [#514](https://github.com/jcmoraisjr/haproxy-ingress/pull/514)
* Create frontends even without ingress [#516](https://github.com/jcmoraisjr/haproxy-ingress/pull/516)

## v0.8

### v0.8-beta.1

Breaking backward compatibility from [v0.7](#v07):

Note: A new configuration parser and HAProxy config builder is in place. Despite declared incompatibility changes listed below, all configuration options and behavior should be preserved. Please file an issue if something changed in the v0.8 controller which is not listed here.

* HAProxy's backend naming convention used for services changed from `<namespace>-<svcname>-<port>` to `<namespace>_<svcname>_<port>` in order to avoid ambiguity. This should impact as least logging filters and metrics dashboards.
* All the other HAProxy's proxy names changed as well - check your logging filters and metrics dashboards.
* `nbproc-ssl` global configmap option wasn't reimplemented in v0.8, consider use `nbthread` instead.
* `strict-host` global configmap option changed the default value from `true` to `false`. See `strict-host` [doc](/README.md#strict-host).
* `dynamic-scaling` configuration key changed the default value from `false` to `true`
* `nbthread` configuration key changed the default value from `1` to `2`
* `reload-strategy` command-line option changed  the default value from `native` to `reusesocket`

The `--v07-controller=true` command-line option can be used to revert to the old controller and behavior. Note that in this case the `*-v07.tmpl` templates will be used instead. This option will be removed on v0.10.

Improvements on the new internal representation and converters:

* Main issue [#274](https://github.com/jcmoraisjr/haproxy-ingress/issues/274)
* Pull requests [part1](https://github.com/jcmoraisjr/haproxy-ingress/pull/289), [part2](https://github.com/jcmoraisjr/haproxy-ingress/pull/295), [part3](https://github.com/jcmoraisjr/haproxy-ingress/pull/339), [part4](https://github.com/jcmoraisjr/haproxy-ingress/pull/351), [part5](https://github.com/jcmoraisjr/haproxy-ingress/pull/355), [part6](https://github.com/jcmoraisjr/haproxy-ingress/pull/366)
* About 80% of the controller was rewritten from scratch. The new code base has more consistent behavior, it's more decoupled, easier to understand, test and evolve, and ready to ingress v2 without breaking compatibility with ingress v1. The new configuration is also a lot faster - the bigger the cluster, the faster the config generated by the v0.8 controller.
* Configmap and annotations: declare annotations with prefix (defaults to `ingress.kubernetes.io`) on services or ingress objects, declare without prefix as a global configmap option. The configmap declaration act as a default value, and service takes precedence in the case of conflict with ingress.
* The `mode tcp` frontend will be used only if needed:
  * Authentication with client certificate is used - this will not be a limitation on v0.9 controller and HAProxy 1.9.x
  * `ssl-passthrough` is used
  * Conflicting `timeout client` declared as annotations
* Fix HAProxy config parsing of a very long list of whitelist CIDRs or a very long list of overlaping /paths in the same domain

Fixes and improvements since [v0.7](#v07):

* Fix duplication of ConfigFrontend snippets for DefaultBackend [#352](https://github.com/jcmoraisjr/haproxy-ingress/pull/352)
* Fix port retrieval for terminatingPod with named targetPort [#331](https://github.com/jcmoraisjr/haproxy-ingress/pull/331)
* Disable HTTP Basic Auth on CORS pre-flight OPTIONS request [#356](https://github.com/jcmoraisjr/haproxy-ingress/pull/356)
* Configure annotation prefix - [doc](/README.md#annotation-prefix)
  * Command-line options:
    * `--annotations-prefix`
* Agent check [#287](https://github.com/jcmoraisjr/haproxy-ingress/pull/287) - [doc](/README.md#agent-check)
  * Annotations or configmap options (without prefix):
    * `ingress.kubernetes.io/agent-check-port`
    * `ingress.kubernetes.io/agent-check-addr`
    * `ingress.kubernetes.io/agent-check-interval`
    * `ingress.kubernetes.io/agent-check-send`
* Health check [#287](https://github.com/jcmoraisjr/haproxy-ingress/pull/287) - [doc](/README.md#health-check)
  * Annotations or configmap options (without prefix):
    * `ingress.kubernetes.io/health-check-uri`
    * `ingress.kubernetes.io/health-check-addr`
    * `ingress.kubernetes.io/health-check-port`
    * `ingress.kubernetes.io/health-check-interval`
    * `ingress.kubernetes.io/health-check-rise-count`
    * `ingress.kubernetes.io/health-check-fall-count`
* Configure the minimum number of free/empty servers per backend - [doc](/README.md#dynamic-scaling)
  * Annotations or configmap options (without prefix):
    * `ingress.kubernetes.io/slots-min-free`
* Add CORS Expose Headers option [#268](https://github.com/jcmoraisjr/haproxy-ingress/pull/268) - [doc](/README.md#cors)
  * Annotations or configmap options (without prefix):
    * `ingress.kubernetes.io/cors-expose-headers`
* Add SSL Engine options [#269](https://github.com/jcmoraisjr/haproxy-ingress/pull/269) - [doc](/README.md#ssl-engine)
  * Configmap options:
    * `ssl-engine`
    * `ssl-mode-async`
* Add log customizations
  * Configmap options:
    * `syslog-format` [#278](https://github.com/jcmoraisjr/haproxy-ingress/pull/278) - [doc](/README.md#syslog-format)
    * `syslog-tag` [#288](https://github.com/jcmoraisjr/haproxy-ingress/pull/288) - [doc](/README.md#syslog-tag)
* Add TLS ALPN option [#307](https://github.com/jcmoraisjr/haproxy-ingress/pull/307) - [doc](/README.md#tls-alpn)
  * Configmap options:
    * `tls-alpn`
* Allow hostname/pod name to be used as the cookie value [#286](https://github.com/jcmoraisjr/haproxy-ingress/pull/286) - [doc](/README.md#affinity)
  * Annotations or configmap options (without prefix):
    * `ingress.kubernetes.io/session-cookie-dynamic`
* Allow redispatch when drain-support is enabled [#334](https://github.com/jcmoraisjr/haproxy-ingress/pull/334) - [doc](/README.md#drain-support)
  * Configmap options:
    * `drain-support-redispatch`
* Add snippet for defaults section [#335](https://github.com/jcmoraisjr/haproxy-ingress/pull/335) - [doc](/README.md#configuration-snippet)
  * Configmap options:
    * `config-defaults`
* Add option to wait defined time when SIGTERM received [#363](https://github.com/jcmoraisjr/haproxy-ingress/pull/363) - [doc](/README.md#wait-before-shutdown)
  * Command-line options:
    * `--wait-before-shutdown`
* Declare a HAProxy var with the k8s namespace [#378](https://github.com/jcmoraisjr/haproxy-ingress/pull/378) - [doc](/README.md#var-namespace)
  * Annotation or configmap options (without prefix):
    * `ingress.kubernetes.io/var-namespace`

### v0.8-beta.2

Fixes and improvements since [v0.8-beta.1](#v08-beta1):

* Fix service port lookup [#385](https://github.com/jcmoraisjr/haproxy-ingress/pull/385)
* Change dynamic update default values [#388](https://github.com/jcmoraisjr/haproxy-ingress/pull/388)
* Fix port number lookup of terminating pods [#389](https://github.com/jcmoraisjr/haproxy-ingress/pull/389)

### v0.8-beta.3

Fixes and improvements since [v0.8-beta.2](#v08-beta2):

* Make sni optional if a certificate is optional and is not provided [#392](https://github.com/jcmoraisjr/haproxy-ingress/pull/392)
* Add custom-frontend to snippet to http:80 frontend [#395](https://github.com/jcmoraisjr/haproxy-ingress/pull/395)

### v0.8-beta.4

Fixes and improvements since [v0.8-beta.3](#v08-beta3):

* Sort ingress using creation timestamp [#405](https://github.com/jcmoraisjr/haproxy-ingress/pull/405)
* Add session-cookie-shared [#419](https://github.com/jcmoraisjr/haproxy-ingress/pull/419)
  * Configuration keys:
    * `session-cookie-shared` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#affinity)
* Add dynamic-scaling false option [#420](https://github.com/jcmoraisjr/haproxy-ingress/pull/420)
* Improve sorting of internal state [#423](https://github.com/jcmoraisjr/haproxy-ingress/pull/423)
* Tuning default thread number and reload strategy [#424](https://github.com/jcmoraisjr/haproxy-ingress/pull/424)
* Fix case on requests from 80/http [#425](https://github.com/jcmoraisjr/haproxy-ingress/pull/425)

### v0.8-beta.5

Fixes and improvements since [v0.8-beta.4](#v08-beta4):

* Update HAProxy from 1.8.20 to 1.8.22
* Fix case on per-path backend requests [#427](https://github.com/jcmoraisjr/haproxy-ingress/pull/427)
* Fix implementation of cross-namespace command-line option [#433](https://github.com/jcmoraisjr/haproxy-ingress/pull/433)
* Improve fronting proxy config [#434](https://github.com/jcmoraisjr/haproxy-ingress/pull/434)
  * Configuration keys:
    * `fronting-proxy-port` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#fronting-proxy-port)
* Fix host match with a port number [#436](https://github.com/jcmoraisjr/haproxy-ingress/pull/436)
* Add initial-weight config key [#444](https://github.com/jcmoraisjr/haproxy-ingress/pull/444)
  * Configuration keys:
    * `initial-weight` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#initial-weight)
* Add ip+port bind support for http/https/fronting-proxy [#452](https://github.com/jcmoraisjr/haproxy-ingress/pull/452)
  * Configuration keys:
    * `bind-fronting-proxy` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#bind)
    * `bind-http` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#bind)
    * `bind-https` - [doc](https://haproxy-ingress.github.io/docs/configuration/keys/#bind)
* Fix panic reading empty targetRef from ep [#455](https://github.com/jcmoraisjr/haproxy-ingress/pull/455)

### v0.8-post-beta.5 (match v0.8)

Fixes and improvements since [v0.8-beta.5](#v08-beta5):

* Update HAProxy from 1.8.22 to 1.8.23
* Fix txn.namespace on http requests [#463](https://github.com/jcmoraisjr/haproxy-ingress/pull/463)
* Do ssl-redirect only if tls declares the hostname [#465](https://github.com/jcmoraisjr/haproxy-ingress/pull/465)
* Fix case on per-path backend maps [#466](https://github.com/jcmoraisjr/haproxy-ingress/pull/466)
* Fix haproxy.cfg permissions [#476](https://github.com/jcmoraisjr/haproxy-ingress/pull/476)

## v0.7.6

Fixes and improvements since [v0.7.5](#v075):

* Update HAProxy from 1.8.23 to 1.8.25, which fixes CVE-2020-11100

## v0.7.5

Fixes and improvements since [v0.7.4](#v074):

* Update HAProxy from 1.8.22 to 1.8.23

## v0.7.4

Fixes and improvements since [v0.7.3](#v073):

* Update HAProxy from 1.8.21 to 1.8.22, which fixes a segmentation fault when using a spoe filter (ModSecurity)

## v0.7.3

Fixes and improvements since [v0.7.2](#v072):

* Update HAProxy from 1.8.20 to 1.8.21
* Fix duplication of ConfigFrontend snippets for DefaultBackend [#352](https://github.com/jcmoraisjr/haproxy-ingress/pull/352)
* Disable HTTP Basic Auth on CORS pre-flight OPTIONS request [#356](https://github.com/jcmoraisjr/haproxy-ingress/pull/356)

## v0.7.2

Fixes and improvements since [v0.7.1](#v071):

* Update HAProxy from 1.8.19 to 1.8.20
* Fix port retrieval for terminatingPod with named targetPort [#331](https://github.com/jcmoraisjr/haproxy-ingress/pull/331)

## v0.7.1

Fixes and improvements since [v0.7](#v07):

* Update libssl and libcrypto [#318](https://github.com/jcmoraisjr/haproxy-ingress/pull/318)

## v0.7

### v0.7-beta.1

Breaking backward compatibility from [v0.6](#v06):

* Default blue/green deployment mode changed from `pod` to `deploy`. Use `ingress.kubernetes.io/blue-green-mode` annotation to change to the v0.6 behavior. See also the blue/green deployment [doc](/README.md#blue-green).
* Changed default maximum ephemeral DH key size from 1024 to 2048, which might break old TLS clients. Use `ssl-dh-default-max-size` configmap option to change back to 1024 if needed.
* Behavior of `ingress.kubernetes.io/server-alias` annotation was changed to mimic hostname syntax. Use `ingress.kubernetes.io/server-alias-regex` instead if need to use regex. See also the server-alias [doc](/README.md#server-alias)

Fixes and improvements since [v0.6](#v06):

* Add SSL config on TCP services [#192](https://github.com/jcmoraisjr/haproxy-ingress/pull/192) - [doc](/README.md#tcp-services-configmap)
* Disable health check of backends [#195](https://github.com/jcmoraisjr/haproxy-ingress/pull/195)
* Fix endless loop if SSL/TLS secret does not exist [#191](https://github.com/jcmoraisjr/haproxy-ingress/pull/191)
* DNS discovery of backend servers [#154](https://github.com/jcmoraisjr/haproxy-ingress/pull/154) - [doc](/README.md#dns-resolvers)
  * Annotations:
    * `ingress.kubernetes.io/use-resolver`
  * Configmap options:
    * `dns-accepted-payload-size`
    * `dns-cluster-domain`
    * `dns-hold-obsolete`
    * `dns-hold-valid`
    * `dns-resolvers`
    * `dns-timeout-retry`
* ModSecurity web application firewall [#166](https://github.com/jcmoraisjr/haproxy-ingress/pull/166) and [#248](https://github.com/jcmoraisjr/haproxy-ingress/pull/248)
  * Template file - [doc](/README.md#configuration)
  * Annotations:
    * `ingress.kubernetes.io/waf` - [doc](/README.md#waf)
  * Configmap options:
    * `modsecurity-endpoints` - [doc](/README.md#modsecurity-endpoints)
    * `modsecurity-timeout-hello` - [doc](/README.md#modsecurity)
    * `modsecurity-timeout-idle` - [doc](/README.md#modsecurity)
    * `modsecurity-timeout-processing` - [doc](/README.md#modsecurity)
* Multi process and multi thread support [#172](https://github.com/jcmoraisjr/haproxy-ingress/pull/172)
  * Configmap options:
    * `nbproc-ssl` - [doc](/README.md#nbproc)
    * `nbthread` - [doc](/README.md#nbthread)
* Balance mode of blue/green deployment [#201](https://github.com/jcmoraisjr/haproxy-ingress/pull/201) - [doc](/README.md#blue-green)
  * Annotations:
    * `ingress.kubernetes.io/blue-green-balance`
    * `ingress.kubernetes.io/blue-green-mode`
* Add configuration snippet options [#194](https://github.com/jcmoraisjr/haproxy-ingress/pull/194) and [#252](https://github.com/jcmoraisjr/haproxy-ingress/pull/252) - [doc](/README.md#configuration-snippet)
  * Configmap options:
    * `config-frontend`
    * `config-global`
* Add OAuth2 support [#239](https://github.com/jcmoraisjr/haproxy-ingress/pull/239) - [doc](/README.md#oauth)
* Add support to ingress/spec/backend [#212](https://github.com/jcmoraisjr/haproxy-ingress/pull/212)
* Add SSL config on stats endpoint [#193](https://github.com/jcmoraisjr/haproxy-ingress/pull/193) - [doc](/README.md#stats)
  * Configmap options:
    * `stats-ssl-cert`
* Add custom http and https port numbers [#190](https://github.com/jcmoraisjr/haproxy-ingress/pull/190)
  * Configmap options:
    * `http-port`
    * `https-port`
* Add client cert auth for backend [#222](https://github.com/jcmoraisjr/haproxy-ingress/pull/222) - [doc](/README.md#secure-backend)
  * Annotations:
    * `ingress.kubernetes.io/secure-crt-secret`
* Add publish-service doc [#211](https://github.com/jcmoraisjr/haproxy-ingress/pull/211) - [doc](/README.md#publish-service)
  * Command-line options:
    * `--publish-service`
* Add option to match URL path on wildcard hostnames [#213](https://github.com/jcmoraisjr/haproxy-ingress/pull/213) - [doc](/README.md#strict-host)
  * Configmap options:
    * `strict-host`
* Add HSTS on default backend [#214](https://github.com/jcmoraisjr/haproxy-ingress/pull/214)
* Add Sprig template functions [#224](https://github.com/jcmoraisjr/haproxy-ingress/pull/224) - [Sprig doc](https://masterminds.github.io/sprig/)
* Add watch-namespace command-line option [#227](https://github.com/jcmoraisjr/haproxy-ingress/pull/227) - [doc](/README.md#watch-namespace)
  * Command-line options:
    * `--watch-namespace`
* Add http-port on ssl-passthrough [#228](https://github.com/jcmoraisjr/haproxy-ingress/pull/228) - [doc](/README.md#ssl-passthrough)
  * Annotations:
    * `ingress.kubernetes.io/ssl-passthrough-http-port`
* Add proxy-protocol annotation [#236](https://github.com/jcmoraisjr/haproxy-ingress/pull/236) - [doc](/README.md#proxy-protocol)
  * Annotations:
    * `ingress.kubernetes.io/proxy-protocol`
* Add server-alias-regex annotation [#250](https://github.com/jcmoraisjr/haproxy-ingress/pull/250) - [doc](/README.md#server-alias)
  * Annotations:
    * `ingress.kubernetes.io/server-alias-regex`
* Optimize reading of default backend [#234](https://github.com/jcmoraisjr/haproxy-ingress/pull/234)
* Add annotation and configmap validations [#237](https://github.com/jcmoraisjr/haproxy-ingress/pull/237)
* Fix sort-backends behavior [#247](https://github.com/jcmoraisjr/haproxy-ingress/pull/247)

### v0.7-beta.2

Fixes and improvements since [v0.7-beta.1](#v07-beta1):

* Fix ssl-passthrought (only v0.7) [#258](https://github.com/jcmoraisjr/haproxy-ingress/pull/258)

### v0.7-beta.3

Fixes and improvements since [v0.7-beta.2](#v07-beta2):

* Fix panic if an invalid path is used on ssl-passthrough (only v0.7) [#260](https://github.com/jcmoraisjr/haproxy-ingress/pull/260)
* Add ssl-passthrough-http-port validations [#261](https://github.com/jcmoraisjr/haproxy-ingress/pull/261)

### v0.7-beta.4

Fixes and improvements since [v0.7-beta.3](#v07-beta3):

* Update HAProxy from 1.8.14 to 1.8.16 - fix some DNS issues
* Improve optional client cert auth [#275](https://github.com/jcmoraisjr/haproxy-ingress/pull/275)

### v0.7-beta.5

Fixes and improvements since [v0.7-beta.4](#v07-beta4):

* Update HAProxy from 1.8.16 to 1.8.17 - fix CVE-2018-20615 ([release notes](https://www.mail-archive.com/haproxy@formilux.org/msg32304.html))

### v0.7-beta.6

Fixes and improvements since [v0.7-beta.5](#v07-beta5):

* Fix validation of mod security conf [#282](https://github.com/jcmoraisjr/haproxy-ingress/pull/282)

### v0.7-beta.7

Fixes and improvements since [v0.7-beta.6](#v07-beta6):

* Use SRV records on dns resolver if backend port isn’t a valid number [#285](https://github.com/jcmoraisjr/haproxy-ingress/pull/285)
* Fix permission of frontend certs dir [#293](https://github.com/jcmoraisjr/haproxy-ingress/pull/293)

### v0.7-beta.8

Fixes and improvements since [v0.7-beta.7](#v07-beta7):

* Update to HAProxy 1.8.19, which fixes some connection aborts on HTTP/2
* Add TLS ALPN extension advertisement [#307](https://github.com/jcmoraisjr/haproxy-ingress/pull/307)
* Fix overlapping configs on shared frontend [#308](https://github.com/jcmoraisjr/haproxy-ingress/pull/308)

## v0.6.4

Fixes and improvements since [v0.6.3](#v063):

* Update HAProxy from 1.8.19 to 1.8.20
* Fix port retrieval for terminatingPod with named targetPort [#331](https://github.com/jcmoraisjr/haproxy-ingress/pull/331)

## v0.6.3

Fixes and improvements since [v0.6.2](#v062):

* Update libssl and libcrypto [#318](https://github.com/jcmoraisjr/haproxy-ingress/pull/318)

## v0.6.2

Fixes and improvements since [v0.6.1](#v061):

* Update HAProxy from 1.8.17 to 1.8.19, which fixes some connection aborts on HTTP/2

## v0.6.1

Fixes and improvements since [v0.6](#v06):

* Update HAProxy from 1.8.14 to 1.8.17
  * Fix some DNS issues
  * Fix CVE-2018-20615 ([release notes](https://www.mail-archive.com/haproxy@formilux.org/msg32304.html))

## v0.6

### v0.6-beta.1

Breaking backward compatibility from [v0.5](#v05):

* Usage of header `Host` to match https requests instead of using just sni extension, deprecating `use-host-on-https` - [#130](https://github.com/jcmoraisjr/haproxy-ingress/pull/130)
* Multibinder is deprecated, use `reusesocket` reload strategy instead - [#139](https://github.com/jcmoraisjr/haproxy-ingress/pull/139)
* Dynamic scaling do not reload HAProxy if the number of servers of a backend could be reduced
* Broken CIDR lists - `whitelist-source-range` and `limit-whitelist` annotations - will add at least the valid CIDRs found in the list - [#163](https://github.com/jcmoraisjr/haproxy-ingress/pull/163)
* Added `timeout-queue` configmap option which defaults to `5s`. `timeout-queue` didn't exist before v0.6 and its value inherits from the `timeout-connect` configuration. Starting on v0.6, changing `timeout-connect` will not change `timeout-queue` default value.

Fixes and improvements since [v0.5](#v05):

* HAProxy 1.8
* Dynamic cookies on cookie based server affinity
* HTTP/2 support - [#129](https://github.com/jcmoraisjr/haproxy-ingress/pull/129)
* Share http/s connections on the same frontend/socket - [#130](https://github.com/jcmoraisjr/haproxy-ingress/pull/130)
* Add clear userlist on misconfigured basic auth - [#71](https://github.com/jcmoraisjr/haproxy-ingress/issues/71)
* Fix copy endpoints to fullslots - [#84](https://github.com/jcmoraisjr/haproxy-ingress/issues/84)
* Equality improvement on dynamic scaling  - [#138](https://github.com/jcmoraisjr/haproxy-ingress/issues/138) and [#140](https://github.com/jcmoraisjr/haproxy-ingress/issues/140)
* Fix precedence of hosts without wildcard and alias without regex - [#149](https://github.com/jcmoraisjr/haproxy-ingress/pull/149)
* Add v1 as a PROXY protocol option on tcp-services - [#156](https://github.com/jcmoraisjr/haproxy-ingress/pull/156)
* Fix Lets Encrypt certificate generation - [#161](https://github.com/jcmoraisjr/haproxy-ingress/pull/161)
* Add valid CIDRs on whitelists [#163](https://github.com/jcmoraisjr/haproxy-ingress/pull/163)
* New annotations:
  * Cookie persistence strategy [#89](https://github.com/jcmoraisjr/haproxy-ingress/pull/89) - [doc](/README.md#affinity)
    * `ingress.kubernetes.io/session-cookie-strategy`
  * Blue/green deployment [#125](https://github.com/jcmoraisjr/haproxy-ingress/pull/125) - [doc](/README.md#blue-green)
    * `ingress.kubernetes.io/blue-green-deploy`
  * Load balancing algorithm [#144](https://github.com/jcmoraisjr/haproxy-ingress/pull/144)
    * `ingress.kubernetes.io/balance-algorithm`
  * Connection limits and timeout [#148](https://github.com/jcmoraisjr/haproxy-ingress/pull/148) - [doc](/README.md#connection)
    * `ingress.kubernetes.io/maxconn-server`
    * `ingress.kubernetes.io/maxqueue-server`
    * `ingress.kubernetes.io/timeout-queue`
  * CORS [#151](https://github.com/jcmoraisjr/haproxy-ingress/pull/151) - [doc](/README.md#cors)
    * `ingress.kubernetes.io/cors-allow-origin`
    * `ingress.kubernetes.io/cors-allow-methods`
    * `ingress.kubernetes.io/cors-allow-headers`
    * `ingress.kubernetes.io/cors-allow-credentials`
    * `ingress.kubernetes.io/cors-enable`
    * `ingress.kubernetes.io/cors-max-age`
  * Configuration snippet [#155](https://github.com/jcmoraisjr/haproxy-ingress/pull/155) - [doc](/README.md#configuration-snippet)
    * `ingress.kubernetes.io/config-backend`
  * Backend servers slot increment [#164](https://github.com/jcmoraisjr/haproxy-ingress/pull/164) - [doc](/README.md#dynamic-scaling)
    * `ingress.kubernetes.io/slots-increment`
* New configmap options:
  * Drain support for NotReady pods on cookie affinity backends [#95](https://github.com/jcmoraisjr/haproxy-ingress/pull/95) - [doc](/README.md#drain-support)
    * `drain-support`
  * Timeout queue [#148](https://github.com/jcmoraisjr/haproxy-ingress/pull/148) - [doc](/README.md#timeout)
    * `timeout-queue`
  * Time to wait for long lived connections to finish before hard-stop a HAProxy process [#150](https://github.com/jcmoraisjr/haproxy-ingress/pull/150) - [doc](/README.md#timeout)
    * `timeout-stop`
  * Add option to bypass SSL/TLS redirect [#161](https://github.com/jcmoraisjr/haproxy-ingress/pull/161) - [doc](/README.md#no-tls-redirect-locations)
    * `no-tls-redirect-locations`
  * Add configmap options to listening IP address [#162](https://github.com/jcmoraisjr/haproxy-ingress/pull/162)
    * `bind-ip-addr-tcp`
    * `bind-ip-addr-http`
    * `bind-ip-addr-healthz`
    * `bind-ip-addr-stats`
* New command-line options:
  * Maximum timestamped config files [#123](https://github.com/jcmoraisjr/haproxy-ingress/pull/123) - [doc](/README.md#max-old-config-files)
    * `--max-old-config-files`

### v0.6-beta.2

Fixes and improvements since [v0.6-beta.1](#v06-beta1):

* Fix redirect https if path changed with rewrite-target - [#179](https://github.com/jcmoraisjr/haproxy-ingress/pull/179)
* Fix ssl-passthrough annotation - [#183](https://github.com/jcmoraisjr/haproxy-ingress/pull/183) and [#187](https://github.com/jcmoraisjr/haproxy-ingress/pull/187)

### v0.6-beta.3

Fixes and improvements since [v0.6-beta.2](#v06-beta2):

* Fix host match of rate limit on shared frontend - [#202](https://github.com/jcmoraisjr/haproxy-ingress/pull/202)

### v0.6-beta.4

Fixes and improvements since [v0.6-beta.3](#v06-beta3):

* Fix permission denied to mkdir on OpenShift - [#205](https://github.com/jcmoraisjr/haproxy-ingress/issues/205)
* Fix usage of custom DH params (only v0.6) - [#215](https://github.com/jcmoraisjr/haproxy-ingress/issues/215)
* Fix redirect of non TLS hosts (only v0.6) - [#231](https://github.com/jcmoraisjr/haproxy-ingress/issues/231)

### v0.6-beta.5

Fixes and improvements since [v0.6-beta.4](#v06-beta4):

* Fix health check of dynamic reload - [#232](https://github.com/jcmoraisjr/haproxy-ingress/issues/232)
* Fix stop/terminate signal of the controller process - [#233](https://github.com/jcmoraisjr/haproxy-ingress/issues/233)

### v0.6-beta.6

Fixes and improvements since [v0.6-beta.5](#v06-beta5):

* Fix SSL redirect if no TLS config is used (only v0.6) - [#235](https://github.com/jcmoraisjr/haproxy-ingress/issues/235)

### v0.6-post-beta.6 (match v0.6)

Fixes and improvements since [v0.6-beta.6](#v06-beta6):

* Restrict access of sticky session cookie by client Javascript code - [#251](https://github.com/jcmoraisjr/haproxy-ingress/pull/251)

## v0.5

Fixes and improvements since `v0.4`

* [v0.5-beta.1](#v05-beta1) changelog
* [v0.5-beta.2](#v05-beta2) changelog
* [v0.5-beta.3](#v05-beta3) changelog

## v0.5-beta.3

Fixes and improvements since `v0.5-beta.2`

* Fix sync of excluded secrets - [#102](https://github.com/jcmoraisjr/haproxy-ingress/issues/102)
* Fix config with long fqdn - [#112](https://github.com/jcmoraisjr/haproxy-ingress/issues/112)
* Fix non ssl redirect on default backend - [#120](https://github.com/jcmoraisjr/haproxy-ingress/issues/120)

## v0.5-beta.2

Fixes and improvements since `v0.5-beta.1`

* Fix reading of txn.path on http-request keywords - [#102](https://github.com/jcmoraisjr/haproxy-ingress/issues/102)

## v0.5-beta.1

Breaking backward compatibility from `v0.4`

* TLS certificate validation using only SAN extension - common Name (CN) isn't used anymore. Add `--verify-hostname=false` command-line option to bypass hostname verification
* `ingress.kubernetes.io/auth-tls-secret` annotation cannot reference another namespace without `--allow-cross-namespace` command-line option
* `tcp-log-format` configmap option now customizes log of TCP proxies, use `https-log-format` instead to configure log of SNI inspection (https/tcp frontend)

Fixes and improvements since `v0.4`

* Change from Go 1.8.1 to 1.9.2
* Implement full config of default backend - [#73](https://github.com/jcmoraisjr/haproxy-ingress/issues/73)
* Fix removal of TLS if failing to read the secretName - [#78](https://github.com/jcmoraisjr/haproxy-ingress/issues/78)
* New annotations:
  * Rewrite path support - [doc](/README.md#rewrite-target)
    * `ingress.kubernetes.io/rewrite-target`
  * Rate limit support - [doc](/README.md#limit)
    * `ingress.kubernetes.io/limit-connections`
    * `ingress.kubernetes.io/limit-rps`
    * `ingress.kubernetes.io/limit-whitelist`
  * Option to include the X509 certificate on requests with client certificate - [doc](/README.md#auth-tls)
    * `ingress.kubernetes.io/auth-tls-cert-header`
  * HSTS support per host and location - [doc](/README.md#hsts)
    * `ingress.kubernetes.io/hsts`
    * `ingress.kubernetes.io/hsts-include-subdomains`
    * `ingress.kubernetes.io/hsts-max-age`
    * `ingress.kubernetes.io/hsts-preload`
* New configmap options:
  * Option to add and customize log of SNI inspection - https/tcp frontend - [doc](/README.md#log-format)
    * `https-log-format`
  * Option to load the server state between HAProxy reloads - [doc](/README.md#load-server-state)
    * `load-server-state`
  * Custom prefix of client certificate headers - [doc](/README.md#ssl-headers-prefix)
    * `ssl-headers-prefix`
  * Support of `Host` header on TLS requests without SNI extension - [doc](/README.md#use-host-on-https)
    * `use-host-on-https`
* New command-line options:
  * Custom rate limit of HAProxy reloads - [doc](/README.md#rate-limit-update)
    * `--rate-limit-update`
  * Support of loading secrets between another namespaces - [doc](/README.md#allow-cross-namespace)
    * `--allow-cross-namespace`
  * TCP services - [doc](/README.md#tcp-services-configmap)
    * `--tcp-services-configmap`
  * Option to skip X509 certificate verification of the hostname - [doc](/README.md#verify-hostname)
    * `--verify-hostname`

## v0.4

Fixes and improvements since `v0.3`

* [v0.4-beta.1](#v04-beta1) changelog
* [v0.4-beta.2](#v04-beta2) changelog

## v0.4-beta.2

Fixes and improvements since `v0.4-beta.1`

* Fix global `maxconn` configuration
* Add `X-Forwarded-Proto: https` header on ssl/tls connections

## v0.4-beta.1

Fixes and improvements since `v0.3`

* Add dynamic scaling - [doc](https://github.com/jcmoraisjr/haproxy-ingress#dynamic-scaling)
* Add monitoring URI - [doc](https://github.com/jcmoraisjr/haproxy-ingress#healthz-port)
* Add [PROXY](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) protocol configmap options - [doc](https://github.com/jcmoraisjr/haproxy-ingress#use-proxy-protocol)
  * `UseProxyProtocol`
  * `StatsProxyProtocol`
* Add log format configmap options - [doc](https://github.com/jcmoraisjr/haproxy-ingress#log-format)
  * `HTTPLogFormat`
  * `TCPLogFormat`
* Add stick session ingress annotations - [doc](https://github.com/jcmoraisjr/haproxy-ingress#affinity)
  * `ingress.kubernetes.io/affinity`
  * `ingress.kubernetes.io/session-cookie-name`
* Support for wildcard hostnames
* Better and faster synchronization after resource updates
* Support `k`, `m` and `g` suffix on `proxy-body-size` annotation and configmap option - [doc](https://github.com/jcmoraisjr/haproxy-ingress#proxy-body-size)
* HTTP 495 and 496 error pages on auth TLS errors
* Add TLS error page ingress annotation
  * `ingress.kubernetes.io/auth-tls-error-page`
* Add support to SSL/TLS offload outside HAProxy on a configmap option - [doc](https://github.com/jcmoraisjr/haproxy-ingress#https-to-http-port)
  * `https-to-http-port`
* Add support to host alias on ingress annotation - [doc](https://github.com/jcmoraisjr/haproxy-ingress#server-alias)
  * `ingress.kubernetes.io/server-alias`
* Fix multibinder goes zombie [#51](https://github.com/jcmoraisjr/haproxy-ingress/issues/51) updating to multibinder 0.0.5
* Add `X-SSL` headers on client authentication with TLS
  * `X-SSL-Client-SHA1`
  * `X-SSL-Client-DN`
  * `X-SSL-Client-CN`

## v0.3

Fixes and improvements since `v0.2.1`

* [v0.3-beta.1](#v03-beta1) changelog - see notes about backward compatibility
* [v0.3-beta.2](#v03-beta2) changelog

## v0.3-beta.2

Fixes and improvements since `v0.3-beta.1`

* Add `haproxy` as the default value of `--ingress-class` parameter
* Fix create/remove ingress based on ingress-class annotation

## v0.3-beta.1

Fixes and improvements since `v0.2.1`

Breaking backward compatibility:

* Move template to `/etc/haproxy/template/haproxy.tmpl`
* Now `ingress.kubernetes.io/app-root` only applies on ingress with root path `/`

Other changes and improvements:

* Reload strategy with `native` and `multibinder` options
* Ingress Controller check for update every 2 seconds (was every 10 seconds)
* New ingress resource annotations
  * `ingress.kubernetes.io/proxy-body-size`
  * `ingress.kubernetes.io/secure-backends`
  * `ingress.kubernetes.io/secure-verify-ca-secret`
  * `ingress.kubernetes.io/ssl-passthrough`
* New configmap options
  * `balance-algorithm`
  * `backend-check-interval`
  * `forwardfor`
  * `hsts`
  * `hsts-include-subdomains`
  * `hsts-max-age`
  * `hsts-preload`
  * `max-connections`
  * `proxy-body-size`
  * `ssl-ciphers`
  * `ssl-dh-default-max-size`
  * `ssl-dh-param`
  * `ssl-options`
  * `stats-auth`
  * `stats-port`
  * `timeout-client`
  * `timeout-client-fin`
  * `timeout-connect`
  * `timeout-http-request`
  * `timeout-keep-alive`
  * `timeout-server`
  * `timeout-server-fin`
  * `timeout-tunnel`

## v0.2.1

Fixes and improvements since `v0.2`

* Fixes [#14](https://github.com/jcmoraisjr/haproxy-ingress/issues/14) (Incorrect `X-Forwarded-For` handling)

## v0.2

Fixes and improvements since `v0.1`

* White list source IP range
* Optionally force TLS connection
* Basic (user/passwd) authentication
* Client certificate authentication
* Root context redirect

## v0.1

Initial version with basic functionality

* rules.hosts with paths from Ingress resource
* default and per host certificate
* 302 redirect from http to https if TLS (default or per host) is provided
* syslog-endpoint from configmap
