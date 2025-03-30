.PHONY: default
default: build

GOOS=linux
GOARCH?=$(shell go env GOARCH)
GIT_REPO=$(shell git config --get remote.origin.url)
GIT_COMMIT=git-$(shell git rev-parse --short HEAD)
VERSION_PKG=github.com/jcmoraisjr/haproxy-ingress/pkg/version
CONTROLLER_FLAGS=-X $(VERSION_PKG).RELEASE=local -X $(VERSION_PKG).COMMIT=$(GIT_COMMIT) -X $(VERSION_PKG).REPO=$(GIT_REPO)
CONTROLLER_TAG?=localhost/haproxy-ingress:latest
LOCAL_FS_PREFIX?=/tmp/haproxy-ingress
KUBECONFIG?=$(HOME)/.kube/config
CONTROLLER_CONFIGMAP?=
CONTROLLER_ARGS?=
HAPROXY_INGRESS_ENVTEST?=1.32.0

LOCALBIN?=$(shell pwd)/bin
LOCAL_GOTESTSUM=$(LOCALBIN)/gotestsum
LOCAL_GOLANGCI_LINT=$(LOCALBIN)/golangci-lint
LOCAL_SETUP_ENVTEST=$(LOCALBIN)/setup-envtest

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

.PHONY: gotestsum
gotestsum:
	test -x $(LOCAL_GOTESTSUM) || GOBIN=$(LOCALBIN) go install gotest.tools/gotestsum@latest

.PHONY: test
test: gotestsum
	## fix race and add -race param
	$(LOCAL_GOTESTSUM) --format=testname -- -tags=cgo ./pkg/...

.PHONY: golangci-lint
golangci-lint:
	test -x $(LOCAL_GOLANGCI_LINT) || GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

.PHONY: lint
lint: golangci-lint
	$(LOCAL_GOLANGCI_LINT) run --verbose

.PHONY: setup-envtest
setup-envtest:
	test -x $(LOCAL_SETUP_ENVTEST) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
	$(LOCAL_SETUP_ENVTEST) use $(HAPROXY_INGRESS_ENVTEST) --bin-dir $(LOCALBIN)

.PHONY: test-integration
test-integration: gotestsum setup-envtest
	@echo
	@echo "Running Kubernetes $(HAPROXY_INGRESS_ENVTEST)"
	KUBEBUILDER_ASSETS="$(shell $(LOCAL_SETUP_ENVTEST) use $(HAPROXY_INGRESS_ENVTEST) --bin-dir $(LOCALBIN) -i -p path)"\
		$(LOCAL_GOTESTSUM) --format=testname -- -count=1 -tags=cgo ./tests/integration/...

.PHONY: linux-build
linux-build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
	  -v -installsuffix cgo \
	  -ldflags "-s -w $(CONTROLLER_FLAGS)" \
	  -o rootfs/haproxy-ingress-controller pkg/main.go

.PHONY: image
image: linux-build
	docker build -t $(CONTROLLER_TAG) rootfs

.PHONY: docker-build
docker-build:
	@rm -f rootfs/haproxy-ingress-controller
	docker build -t $(CONTROLLER_TAG) . -f builder/Dockerfile
