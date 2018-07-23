# Haproxy Ingress DaemonSet

In some cases, the Ingress controller will be required to be run at all the nodes in cluster. Using [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) can achieve this requirement.

## Prerequisites

If you have another Ingress controller deployed, you will need to make sure your
Ingress resources target exactly one Ingress controller by specifying the
[ingress.class](/examples/PREREQUISITES.md#ingress-class) annotation as
`haproxy`.

This document has also the following prerequisites:

* Create a [TLS secret](/examples/PREREQUISITES.md#tls-certificates) named `tls-secret` to be used as default TLS certificate

Creating the TLS secret:

```console
$ openssl req \
  -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls.key -out tls.crt -subj '/CN=localhost'
$ kubectl create secret tls tls-secret --cert=tls.crt --key=tls.key
$ rm -v tls.crt tls.key
```

## RBAC Authorization

Check the [RBAC sample](/examples/rbac) if deploying on a cluster with
[RBAC authorization](https://kubernetes.io/docs/admin/authorization/rbac/).

## Ingress DaemonSet

Deploy the daemonset as follows:

```console
$ kubectl apply -f haproxy-ingress-daemonset.yaml
```

Check if the controller was successfully deployed:
```console
$ kubectl -n kube-system get ds
NAME               DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
haproxy-ingress   2         2         2         <none>          45s

$ kubectl -n kube-system get pods
NAME                                    READY     STATUS    RESTARTS   AGE
haproxy-ingress-km32x                   1/1       Running   0          1m
```
