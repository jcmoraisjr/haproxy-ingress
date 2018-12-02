# CHANGELOG

## v0.7 (beta)

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
