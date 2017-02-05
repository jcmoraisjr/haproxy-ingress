GIT_COMMIT=git-$(shell git rev-parse --short HEAD)
GIT_TAG=false
ifeq ($(DOCKER_ROOTFS),)
DOCKER_ROOTFS=rootfs
endif

ifeq ($(TRAVIS),)
REPO?=$(REPO_LOCAL)
TAG?=latest
else
REPO=$(REPO_PUBLIC)
ifeq ($(TRAVIS_TAG),)
TAG=$(GIT_COMMIT)
else
TAG=$(TRAVIS_TAG)
GIT_TAG=true
endif
endif

.PHONY: image push tag-push
image:
	docker build -t $(REPO):$(TAG) $(DOCKER_ROOTFS)
push:
	docker push $(REPO):$(TAG)
tag-push:
ifeq ($(GIT_TAG),true)
ifeq ($(TRAVIS_PULL_REQUEST),false)
	@docker login -u="$(DOCKER_USR)" -p="$(DOCKER_PWD)" $(DOCKER_HUB)
	@$(MAKE) image push
endif
endif
