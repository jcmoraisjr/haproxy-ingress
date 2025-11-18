# Deploying HAProxy Ingress Controller

If you don't have a Kubernetes cluster, please refer to [Setup cluster](/examples/setup-cluster.md)
for instructions on how to create a new one.

## Prerequisites

If you have another Ingress controller deployed, you will need to make sure your
Ingress resources target exactly one Ingress controller by specifying the
[ingress.class](/examples/PREREQUISITES.md#ingress-class) annotation as
`haproxy`.

This document has also the following prerequisites:

* Create a [TLS secret](/examples/PREREQUISITES.md#tls-certificates) named `tls-secret` to be used as default TLS certificate within the same namespace you will deploy the ingress-controller
* Optional: deploy a web app for testing

Create the ingress-controller namespace:

```console
kubectl create ns ingress-controller
```

Creating the TLS secret:

```console
$ openssl req \
  -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls.key -out tls.crt -subj '/CN=localhost'
$ kubectl --namespace ingress-controller create secret tls tls-secret --cert=tls.crt --key=tls.key
$ rm -v tls.crt tls.key
```

The optional web app can be created as follow:

```console
$ kubectl run http-svc \
  --namespace=ingress-controller \
  --image=gcr.io/google_containers/echoserver:1.3 \
  --port=8080 \
  --replicas=1 \
  --expose
```

## Default backend

Deploy a default backend used to serve `404 Not Found` pages:

```console
$ kubectl run ingress-default-backend \
  --namespace=ingress-controller \
  --image=gcr.io/google_containers/defaultbackend:1.0 \
  --port=8080 \
  --limits=cpu=10m,memory=20Mi \
  --expose
```

Check if the default backend is up and running:

```console
$ kubectl --namespace=ingress-controller get pod
NAME                                       READY     STATUS    RESTARTS   AGE
ingress-default-backend-1110790216-gqr61   1/1       Running   0          10s
```

## ConfigMap

Create a ConfigMap named `haproxy-ingress`:

```console
$ kubectl --namespace=ingress-controller create configmap haproxy-ingress
configmap "haproxy-ingress" created
```

A ConfigMap is used to provide global or default configuration like
timeouts, SSL/TLS settings, a syslog service endpoint and so on. The
ConfigMap can be edited or replaced later in order to apply new
configuration on a running ingress controller. See the [list of supported options](https://github.com/jcmoraisjr/haproxy-ingress#configmap).

## RBAC Authorization

Check the [RBAC sample](/examples/rbac) if deploying on a cluster with
[RBAC authorization](https://kubernetes.io/docs/admin/authorization/rbac/).

## Controller

Deploy HAProxy Ingress:

```console
$ kubectl --namespace=ingress-controller create -f haproxy-ingress.yaml
```

Check if the controller was successfully deployed:

```console
$ kubectl --namespace=ingress-controller get pod -w
NAME                                       READY     STATUS    RESTARTS   AGE
haproxy-ingress-2556761959-tv20k           1/1       Running   0          12s
ingress-default-backend-1110790216-gqr61   1/1       Running   0          3m
^C
```

## Testing

From now the optional web app should be deployed. Deploy an ingress resource to expose this app:

```console
$ kubectl --namespace=ingress-controller create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
spec:
  rules:
  - host: foo.bar
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: http-svc
            port:
              number: 8080
EOF
```

Expose the Ingress controller as a `type=NodePort` service:

```console
$ kubectl --namespace=ingress-controller expose deploy/haproxy-ingress --type=NodePort
$ kubectl --namespace=ingress-controller get svc/haproxy-ingress -oyaml
```

Look for `nodePort` field next to `port: 80`.

Change below `172.17.4.99` to the host's IP and `30876` to the `nodePort`:

```console
$ curl -i 172.17.4.99:30876
HTTP/1.1 404 Not Found
Date: Mon, 05 Feb 2017 22:59:36 GMT
Content-Length: 21
Content-Type: text/plain; charset=utf-8

default backend - 404
```

Using default backend because host was not found.

Now try to send a header:

```console
$ curl -i 172.17.4.99:30876 -H 'Host: foo.bar'
HTTP/1.1 200 OK
Server: nginx/1.9.11
Date: Mon, 05 Feb 2017 23:00:33 GMT
Content-Type: text/plain
Transfer-Encoding: chunked

CLIENT VALUES:
client_address=10.2.18.5
command=GET
real path=/
query=nil
request_version=1.1
request_uri=http://foo.bar:8080/
...
```

## Troubleshooting

If you have any problem, check logs and events of HAProxy Ingress POD:

```console
$ kubectl --namespace=ingress-controller get pod -l run=haproxy-ingress
NAME                                       READY     STATUS    RESTARTS   AGE
haproxy-ingress-2556761959-tv20k           1/1       Running   0          9m
...

$ kubectl --namespace=ingress-controller logs -l run=haproxy-ingress
$ kubectl --namespace=ingress-controller describe pod -l run=haproxy-ingress
```
