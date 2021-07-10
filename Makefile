.PHONY: default
default: build

GOOS=linux
GOARCH?=amd64
GIT_REPO=$(shell git config --get remote.origin.url)
GIT_COMMIT=git-$(shell git rev-parse --short HEAD)
VERSION_PKG=github.com/jcmoraisjr/haproxy-ingress/pkg/version

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
	  -installsuffix cgo \
	  -ldflags "-s -w -X $(VERSION_PKG).RELEASE=local -X $(VERSION_PKG).COMMIT=$(GIT_COMMIT) -X $(VERSION_PKG).REPO=$(GIT_REPO)" \
	  -o rootfs/haproxy-ingress-controller pkg/main.go

.PHONY: test
test:
	## fix race and add -race param
	go test -tags cgo ./...

.PHONY: install
install:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go install \
	  -v -installsuffix cgo pkg/main.go

.PHONY: image
image:
	docker build -t localhost/haproxy-ingress:latest rootfs

.PHONY: docker-builder
docker-builder:
	docker build -t localhost/haproxy-ingress:latest . -f builder/Dockerfile
