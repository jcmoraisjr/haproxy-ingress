# HAProxy Ingress blue/green deployment

This example demonstrates how to configure
[blue/green deployment](https://www.martinfowler.com/bliki/BlueGreenDeployment.html)
on HAProxy Ingress controller, in order to route requests based on distinct weight on
deployment groups as well as selecting a group based on http header or cookie value.

## Prerequisites

This document has the following prerequisite:

* A Kubernetes cluster with a running HAProxy Ingress controller v0.6 or above.
See the [five minutes deployment](/examples/setup-cluster.md#five-minutes-deployment)
or the [deployment example](/examples/deployment)

## Deploying applications

In order to the configuration have effect, at least two deployments, or daemon sets, or replication
controllers should be used with at least two pairs of label name/value.

The following instructions create two deployment objects using `run` label as the service selector
and `group` label as the blue/green deployment selector:

```
$ kubectl run blue \
  --image=jcmoraisjr/whoami \
  --port=8000 --labels=run=bluegreen,group=blue
deployment "blue" created

$ kubectl run green \
  --image=jcmoraisjr/whoami \
  --port=8000 --labels=run=bluegreen,group=green
deployment "green" created
```

Certify that the pods are running and have the correct labels. Note that both `group` and `run`
labels were applied:

```
$ kubectl get pod -lrun=bluegreen --show-labels
NAME                     READY     STATUS    RESTARTS   AGE       LABELS
blue-79c9b67d5b-5hd2r    1/1       Running   0          35s       group=blue,pod-template-hash=3575623816,run=bluegreen
green-7546d648c4-p7pmz   1/1       Running   0          28s       group=green,pod-template-hash=3102820470,run=bluegreen
```

## Configure

Create a service that bind both deployments together using the `run` label. The expose command need
a deployment object, take anyone, we will override it's selector:

```
$ kubectl expose deploy blue --name bluegreen --selector=run=bluegreen
service "bluegreen" exposed

$ kubectl get svc bluegreen -otemplate --template '{{.spec.selector}}'
map[run:bluegreen]
```

Check also the endpoints, it should list both blue and green pods:

```
$ kubectl get ep bluegreen
NAME         ENDPOINTS                           AGE
bluegreen    172.17.0.11:8000,172.17.0.19:8000   2m

$ kubectl get pod -lrun=bluegreen -owide
NAME                     READY     STATUS    RESTARTS   AGE       IP            NODE
blue-79c9b67d5b-5hd2r    1/1       Running   0          2m        172.17.0.11   192.168.100.99
green-7546d648c4-p7pmz   1/1       Running   0          2m        172.17.0.19   192.168.100.99
```

Configure the ingress resource. No need to change the host below, `bluegreen.example.com` is fine:

```
$ kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    ingress.kubernetes.io/balance-algorithm: roundrobin
    ingress.kubernetes.io/blue-green-deploy: group=blue=1,group=green=1
    ingress.kubernetes.io/blue-green-mode: pod
    ingress.kubernetes.io/ssl-redirect: "false"
  name: bluegreen
spec:
  rules:
  - host: bluegreen.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: bluegreen
            port:
              number: 8000
EOF
```

```
$ kubectl get ing
NAME        HOSTS                   ADDRESS   PORTS     AGE
bluegreen   bluegreen.example.com             80        11s
```

## Test blue/green balance

Lets test! The following snippets use an alias `hareq` declared below.
Change `IP` to your HAProxy Ingress controller IP address:

```
$ IP=192.168.100.99
$ alias hareq='echo Running 100 requests...; for i in `seq 1 100`; do
    curl -fsS $IP -H "Host: bluegreen.example.com" | cut -d- -f1
  done | sort | uniq -c'
```

* BG Mode: pod
* BG Balance: blue=1, green=1
* Replicas: blue=1, green=1

```
$ hareq
Running 100 requests...
  50 blue
  50 green
```

---

Now changing green replicas to 3 and wait all the replicas to be running.
BG Mode is pod, so the number of replicas will increase the load of the green deployment.

```
$ kubectl scale deploy green --replicas=3
$ kubectl get pod -w
```

* BG Mode: pod
* BG Balance: blue=1, green=1
* Replicas: blue=1, green=3

```
$ hareq
Running 100 requests...
  25 blue
  75 green
```

---

Changing to *deploy* mode. This mode targets the balance config to the whole deployment
instead of single pods.

**Note:** BG mode was added on v0.7. On v0.6, the only supported mode is `pod`.

```
$ kubectl annotate --overwrite ingress bluegreen \
  ingress.kubernetes.io/blue-green-mode=deploy
```

* BG Mode: deploy
* BG Balance: blue=1, green=1
* Replicas: blue=1, green=3

```
$ hareq
Running 100 requests...
  50 blue
  50 green
```

---

Changing now the balance to 1/3 blue and 2/3 green:

```
$ kubectl annotate --overwrite ingress bluegreen \
  ingress.kubernetes.io/blue-green-deploy=group=blue=1,group=green=2
```

* BG Mode: deploy
* BG Balance: blue=1, green=2
* Replicas: blue=1, green=3

```
$ hareq
Running 100 requests...
  33 blue
  67 green
```

---

The balance will be the same despite the number of replicas:

```
$ kubectl scale deploy green --replicas=6
$ kubectl get pod -w
```

* BG Mode: deploy
* BG Balance: blue=1, green=2
* Replicas: blue=1, green=6

```
$ hareq
Running 100 requests...
  33 blue
  67 green
```

## Test blue/green selector

Blue/green selector requires HAProxy Ingress controller v0.9 or above.

Follow the [deployment](#deploying-applications) and [configuration](#configure)
instructions to deploy the sample application.

After that, add the following annotation:

```
$ kubectl annotate --overwrite ingress bluegreen \
  ingress.kubernetes.io/blue-green-header=x-server:group
```

Create (or update) the `hareq` alias. Change `IP` to your HAProxy Ingress controller
IP address:

```
$ IP=192.168.100.99
$ alias hareq='echo Running 100 requests...; for i in `seq 1 100`; do
    curl -fsS $IP -H "Host: bluegreen.example.com" -H "X-Server: $GROUP" | cut -d- -f1
  done | sort | uniq -c'
```

Choose `blue` group:

```
$ GROUP=blue
```

The envvar `GROUP` will populate the `X-Server` header with the value `blue`.

Run the requests:

```
$ hareq
Running 100 requests...
 100 blue
```

Choose `green` group:

```
$ GROUP=blue
$ hareq
Running 100 requests...
 100 green
```

Choose an invalid group, the configured blue/green balance will be used:

```
$ kubectl annotate --overwrite ingress bluegreen \
  ingress.kubernetes.io/blue-green-deploy=group=blue=1,group=green=3
$ GROUP=invalid
$ hareq
Running 100 requests...
  25 blue
  75 green
```
