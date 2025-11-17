# Cluster Getting Started

This doc outlines the steps needed to set up a local dev cluster within which you
can deploy/test an ingress controller. Note that you can also set up the ingress controller
locally.

## Deploy a Development cluster

### Single node local cluster

You can run the HAProxy Ingress controller locally on any node with access to the
internet, and the following dependencies: [docker](https://docs.docker.com/engine/getstarted/step_one/), [etcd](https://github.com/coreos/etcd/releases), [golang](https://golang.org/doc/install), [cfssl](https://github.com/cloudflare/cfssl#installation), [openssl](https://www.openssl.org/), [make](https://www.gnu.org/software/make/), [gcc](https://gcc.gnu.org/), [git](https://git-scm.com/download/linux).


Clone the kubernetes repo:
```console
$ cd $GOPATH/src/k8s.io
$ git clone https://github.com/kubernetes/kubernetes.git
```

Add yourself to the docker group, if you haven't done so already (or give
local-up-cluster sudo)
```
$ sudo usermod -aG docker $USER
$ sudo reboot
..
$ docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
```

**NB: the next step will bring up Kubernetes daemons directly on your dev
machine, no sandbox, iptables rules, routes, loadbalancers, network bridges
etc are created on the host.**

```console
$ cd $GOPATH/src/k8s.io/kubernetes
$ hack/local-up-cluster.sh
```

Check for Ready nodes
```console
$ kubectl get no --context=local
NAME        STATUS    AGE       VERSION
127.0.0.1   Ready     5s        v1.6.0-alpha.0.1914+8ccecf93aa6db5-dirty
```

### Minikube cluster

[Minikube](https://github.com/kubernetes/minikube) is a popular way to bring up
a sandboxed local cluster. You will first need to [install](https://github.com/kubernetes/minikube/releases)
the minikube binary, then bring up a cluster
```console
$ minikube start
```

Check for Ready nodes
```console
$ kubectl get no
NAME       STATUS    AGE       VERSION
minikube   Ready     42m       v1.4.6
```

List the existing addons
```console
$ minikube addons list
- addon-manager: enabled
- dashboard: enabled
- kube-dns: enabled
- heapster: disabled
```

If this list already contains the ingress controller, you don't need to
redeploy it. If the addon controller is disabled, you can enable it with
```console
$ minikube addons enable ingress
```

If the list *does not* contain the ingress controller, you can either update
minikube, or deploy it yourself as shown in the next section.

You may want to consider [using the VM's docker
daemon](https://github.com/kubernetes/minikube/blob/master/README.md#reusing-the-docker-daemon)
when developing.

### CoreOS Kubernetes

[CoreOS Kubernetes](https://github.com/coreos/coreos-kubernetes/) repository has `Vagrantfile`
scripts to easily create a new Kubernetes cluster on VirtualBox, VMware or AWS.

Follow the CoreOS [doc](https://coreos.com/kubernetes/docs/latest/kubernetes-on-vagrant-single.html)
for detailed instructions.

## Deploy the ingress controller

You can deploy an ingress controller on the cluster setup in the previous step
[like this](/examples/deployment).

### Five minutes deployment

The following steps will create an HAProxy Ingress with the following configurations:

* Create and use `ingress-controller` namespace
* Create `ingress-controller` service account and rbac permissions - this will also work if the cluster doesn't use rbac authorization
* In-cluster configuration and service account token
* Default TLS certificate is self-signed and created on the fly
* Deployed on every node labeled with `role=ingress-controller` via DaemonSet
* Use `hostNetwork`, so the node should not be using the following ports: `80`, `443`, `1936`, `8181`, `10253` and `10254`

Tests was made on Kubernetes 1.6 to 1.9

Create all the resources:

```console
$ kubectl create -f https://raw.githubusercontent.com/jcmoraisjr/haproxy-ingress/master/docs/haproxy-ingress.yaml
```

Optional - edit any default configuration:

```console
$ kubectl -n ingress-controller edit configmap haproxy-ingress
$ kubectl -n ingress-controller edit ds haproxy-ingress
```

Label at least one node; otherwise, the controller won't run:

```console
$ kubectl get node
NAME             STATUS    AGE       VERSION
192.168.100.11   Ready     33m       v1.6.13

$ kubectl label node 192.168.100.11 role=ingress-controller
```

Now HAProxy Ingress should be up and running:

```console
$ kubectl -n ingress-controller get ds
NAME              DESIRED   CURRENT   READY     UP-TO-DATE   AVAILABLE   NODE-SELECTOR             AGE
haproxy-ingress   1         1         1         1            1           role=ingress-controller   3m

$ kubectl -n ingress-controller get pod
NAME                                       READY     STATUS    RESTARTS   AGE
haproxy-ingress-gfhdg                      1/1       Running   0          2m
ingress-default-backend-1408147194-ljw4x   1/1       Running   0          4m
```

## Run against a remote cluster

If the controller you're interested in using supports a "dry-run" flag, you can
run it on any machine that has `kubectl` access to a remote cluster. Eg:

```console
$ cd $GOPATH/k8s.io/ingress/controllers/gce
$ glbc --help
      --running-in-cluster               Optional, if this controller is running in a kubernetes cluster, use the
		 pod secrets for creating a Kubernetes client. (default true)

$ ./glbc --running-in-cluster=false
I1210 17:49:53.202149   27767 main.go:179] Starting GLBC image: glbc:0.9.2, cluster name
```

Note that this is equivalent to running the ingress controller on your local
machine, so if you already have an ingress controller running in the remote
cluster, they will fight for the same ingress.
