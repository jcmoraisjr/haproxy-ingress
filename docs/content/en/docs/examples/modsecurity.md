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

Create the ModSecurity agent deployment with 3 running pods:

```
$ kubectl create -f https://haproxy-ingress.github.io/resources/modsecurity-deployment.yaml
deployment.apps/modsecurity-spoa created
```

{{< alert title="Note" >}}
This deployment configures a small amount of requests and limits resources,
remember to adjust them before moving to production.
{{< /alert >}}


Check if the agent is up and running:

```
$ kubectl -n ingress-controller get deployment modsecurity-spoa
NAME                     READY     UP-TO-DATE   AVAILABLE  AGE
modsecurity-spoa         3/3       3            3          7s
```


You can now create the service that provides a ClusterIP address for the HAProxy ConfigMap.
```
$ kubectl -n ingress-controller expose deployment modsecurity-spoa --port=12345 --type=ClusterIP
service/modsecurity-spoa exposed
```

Once the service is created, you can obtain the ClusterIP address to be used later in the ConfigMap.
```
$ kubectl -n ingress-controller get service modsecurity-spoa
NAME                     TYPE       CLUSTERIP        EXTERNAL-IP  PORT(S)     AGE
modsecurity-spoa         ClusterIP  172.20.216.246   <none>       12345/TCP   7m
```

## Configuring HAProxy Ingress

Add the ConfigMap key `modsecurity-endpoints` with a comma-separated list of `IP:port`
of the ModSecurity agent server(s). The default port number of the agent is `12345`.
A `kubectl -n ingress-controller edit configmap haproxy-ingress` should work.

Example of a ConfigMap content if the ModSecurity service has a ClusterIP of `172.20.216.246`:

```yaml
apiVersion: v1
data:
  modsecurity-endpoints: 172.20.216.246:12345
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
    haproxy-ingress.github.io/ssl-redirect: "false"
    haproxy-ingress.github.io/waf: "modsecurity"
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
NAME                                READY   STATUS    RESTARTS   AGE
modsecurity-spoa-6f757ffd88-9qt2f   1/1     Running   0          11m
modsecurity-spoa-6f757ffd88-vwtzr   1/1     Running   0          11m
modsecurity-spoa-6f757ffd88-q4rvm   1/1     Running   0          11m
...

$ kubectl -n ingress-controller logs --tail=10 modsecurity-spoa-6f757ffd88-9qt2f
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


## Deploy ModSecurity Agent With a Sidecar Container for Audit Logs


A ModSecurity agent can be deployed with an additional sidecar container so you can have access to the logs stored in the AuditLog file. If you are using the default configuration of the ModSecurity agent, the logs written to the AuditLog specified are not reachable in the agent container's STDOUT.

In order to read information written to that file, you must add a sidecar container to the method of deployment of the ModSecurity agent in Kubernetes. This is especially useful if you set the SecRuleEngine configuration to DetectionOnly.

Update the ModSecurity agent deployment to have a sidecar container to read the audit log file to STDOUT

```
$ kubectl apply -f https://haproxy-ingress.github.io/resources/modsecurity-deployment-auditlog-sidecar.yaml
deployment "modsecurity-spoa" configured
```

Now the ModSecurity agent pods will have two containers to get logs from: one for the traditional ModSecurity logs and one for the logs written to the AuditLog file.

```
$ kubectl -n ingress-controller get pod -lrun=modsecurity-spoa
NAME                                READY   STATUS    RESTARTS   AGE
modsecurity-spoa-6596c6b444-cht27   2/2     Running   0          14m
modsecurity-spoa-6596c6b444-kw2tr   2/2     Running   0          14m
modsecurity-spoa-6596c6b444-mkndw   2/2     Running   0          14m
```

## Using Coraza instead of ModSecurity

Since the maintainers of ModSecurity are dropping support in 2024, [OWASP has created a replacement called Coraza](https://coreruleset.org/20211222/talking-about-modsecurity-and-the-new-coraza-waf/) which is a drop-in replacement for ModSecurity.

In order to use Coraza, the process is essentially the same as described in the above sections, with a few exceptions. First, in the haproxy-ingress ConfigMap, add the following two additional keys:

```yaml
  modsecurity-use-coraza: true
  modsecurity-args: "app=hdr(host) id=unique-id src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body"
```

You may require different `modsecurity-args` depending on your Coraza config and your version of coraza-spoa. Check the [coraza-spoa README](https://github.com/corazawaf/coraza-spoa) for full details.

Second, you'll need to change the spoa-modsecurity container image to a coraza-spoa image and create a configmap to hold the Coraza config.yaml. See a [complete example with all the changes](/resources/coraza-deployment.yaml).

{{< alert title="Warning" color="warning" >}}
The coraza-spoa image that we provide in the above example is based on [an experimental branch of coraza-spoa](https://github.com/corazawaf/coraza-spoa/pull/36). For production environments, it would be best to wait until the experimental changes are merged and [an official image is released](https://github.com/corazawaf/coraza-spoa/issues/37).
{{< /alert >}}

### Troubleshooting Coraza

* Ensure that the `bind` port in Coraza's config.yaml matches the port in `modsecurity-endpoints`.
* Pay close attention to the `modsecurity-args` (specifically the `app` arg) and make sure they are set according to the coraza-spoa docs since the exact args may vary depending on your version of coraza-spoa.
* For more complex issues, it may help to set `log_level: debug` in Coraza.
