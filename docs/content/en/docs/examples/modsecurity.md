---
title: "ModSecurity"
linkTitle: "ModSecurity"
weight: 20
description: >
  Demonstrate how to configure ModSecurity web application firewall.
---

This example demonstrates how to configure ModSecurity
web application firewall on HAProxy Ingress controller.

## Prerequisites

This document has the following prerequisites:

* A Kubernetes cluster with a running HAProxy Ingress controller. See the [five minutes deployment](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/setup-cluster.md#five-minutes-deployment) or the [deployment example](https://github.com/jcmoraisjr/haproxy-ingress/tree/master/examples/deployment)
* `ingress-controller` namespace, the default of the five minutes deployment

## Deploying agent

A ModSecurity agent can be deployed in a number of ways: as a sidecar container
in the same HAProxy Ingress deployment/daemonset resource, as a standalone container
in the same host of ingress, or in dedicated host(s), inside or outside a k8s cluster.
The steps below will deploy ModSecurity in some dedicated hosts of a k8s cluster,
adjust the steps to fit your need.

The ModSecurity agent used is [jcmoraisjr/modsecurity-spoa](https://github.com/jcmoraisjr/modsecurity-spoa).

Create the ModSecurity agent daemonset:

```
$ kubectl create -f https://haproxy-ingress.github.io/resources/modsecurity-daemonset.yaml
daemonset "modsecurity-spoa" created
```

Select the node(s) where ModSecurity agent should run:

```
$ kubectl get node
NAME             STATUS    AGE       VERSION
192.168.100.99   Ready     102d      v1.9.2
...

$ kubectl label node 192.168.100.99 waf=modsec
node "192.168.100.99" labeled
```

Check if the agent is up and running:

```
$ kubectl -n ingress-controller get pod -lrun=modsecurity-spoa -owide
NAME                     READY     STATUS    RESTARTS   AGE       IP               NODE
modsecurity-spoa-pp6jz   1/1       Running   0          7s        192.168.100.99   192.168.100.99
```

## Configuring HAProxy Ingress

Add the ConfigMap key `modsecurity-endpoints` with a comma-separated list of `IP:port`
of the ModSecurity agent server(s). The default port number of the agent is `12345`.
A `kubectl -n ingress-controller edit configmap haproxy-ingress` should work.

Example of a ConfigMap content if ModSecurity agents has IPs `192.168.100.99` and
`192.168.100.100`:

```yaml
apiVersion: v1
data:
  modsecurity-endpoints: 192.168.100.99:12345,192.168.100.100:12345
  ...
kind: ConfigMap
```

## Test

Deploy any application:

```
$ kubectl run echo \
  --image=gcr.io/google_containers/echoserver:1.3 \
  --port=8080 \
  --expose
```

... and create its ingress resource. Remember to annotate waf as `modsecurity`.
No need to use a valid domain, `echo.domain` below is fine:

```console
$ kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    ingress.kubernetes.io/ssl-redirect: "false"
    ingress.kubernetes.io/waf: "modsecurity"
  name: echo
spec:
  rules:
  - host: echo.domain
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: echo
            port:
              number: 8080
EOF
```

Test with a simple request. Change the IP below to the IP of your Ingress controller:

```
$ curl -I 192.168.100.99 -H 'Host: echo.domain'
HTTP/1.1 200 OK
Server: nginx/1.9.11
Date: Sun, 27 May 2018 23:28:58 GMT
Content-Type: text/plain
```

Test now with a malicious request:

```
curl -i '192.168.100.99?p=/etc/passwd' -H 'Host: echo.domain'
HTTP/1.0 403 Forbidden
Cache-Control: no-cache
Connection: close
Content-Type: text/html

<html><body><h1>403 Forbidden</h1>
Request forbidden by administrative rules.
</body></html>
```

Check the agent logs:

```
$ kubectl -n ingress-controller get pod -lrun=modsecurity-spoa
NAME                     READY     STATUS    RESTARTS   AGE
modsecurity-spoa-5g5h2   1/1       Running   0          1h
...

$ kubectl -n ingress-controller logs --tail=10 modsecurity-spoa-5g5h2
...
1527464273.942819 [00] [client 127.0.0.1] ModSecurity: Access denied with code 403 (phase 2). Matche
d phrase "etc/passwd" at ARGS:p. [file "/etc/modsecurity/owasp-modsecurity-crs/rules/REQUEST-930-APP
LICATION-ATTACK-LFI.conf"] [line "108"] [id "930120"] [rev "4"] [msg "OS File Access Attempt"] [data
 "Matched Data: etc/passwd found within ARGS:p: /etc/passwd"] [severity "CRITICAL"] [ver "OWASP_CRS/
3.0.0"] [maturity "9"] [accuracy "9"] [tag "application-multi"] [tag "language-multi"] [tag "platfor
m-multi"] [tag "attack-lfi"] [tag "OWASP_CRS/WEB_ATTACK/FILE_INJECTION"] [tag "WASCTC/WASC-33"] [tag
 "OWASP_TOP_10/A4"] [tag "PCI/6.5.4"] [hostname "ingress.localdomain"] [uri "http://echo.domain/"] [
unique_id ""]
...
```
