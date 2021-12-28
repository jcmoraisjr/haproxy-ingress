.PHONY: default
default: build

GOOS=linux
GOARCH?=amd64
GIT_REPO=$(shell git config --get remote.origin.url)
GIT_COMMIT=git-$(shell git rev-parse --short HEAD)
VERSION_PKG=github.com/jcmoraisjr/haproxy-ingress/pkg/version
CONTROLLER_FLAGS=-X $(VERSION_PKG).RELEASE=local -X $(VERSION_PKG).COMMIT=$(GIT_COMMIT) -X $(VERSION_PKG).REPO=$(GIT_REPO)
CONTROLLER_TAG?=localhost/haproxy-ingress:latest
LOCAL_FS_PREFIX?=/tmp/haproxy-ingress
KUBECONFIG?=$(HOME)/.kube/config
CONTROLLER_CONFIGMAP?=
CONTROLLER_ARGS?=

.PHONY: build
build:
	CGO_ENABLED=0 go build \
	  -v -installsuffix cgo \
	  -ldflags "-s -w $(CONTROLLER_FLAGS)" \
	  -o bin/controller pkg/main.go

.PHONY: run
run: build
	@rm -rf $(LOCAL_FS_PREFIX)/var/run/haproxy/
	@mkdir -p $(LOCAL_FS_PREFIX)/etc/haproxy/lua/
	@cp rootfs/etc/lua/* $(LOCAL_FS_PREFIX)/etc/haproxy/lua/
	./bin/controller \
	  --kubeconfig=$(KUBECONFIG)\
	  --local-filesystem-prefix=$(LOCAL_FS_PREFIX)\
	  --update-status=false\
	  --configmap=$(CONTROLLER_CONFIGMAP)\
	  $(CONTROLLER_ARGS)

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test: lint
	## fix race and add -race param
	go test -tags cgo ./...

.PHONY: linux-build
linux-build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
	  -v -installsuffix cgo \
	  -ldflags "-s -w $(CONTROLLER_FLAGS)" \
	  -o rootfs/haproxy-ingress-controller pkg/main.go

.PHONY: image
image: linux-build
	docker build -t $(CONTROLLER_TAG) rootfs

.PHONY: docker-builder
docker-builder:
	@rm -f rootfs/haproxy-ingress-controller
	docker build -t $(CONTROLLER_TAG) . -f builder/Dockerfile
