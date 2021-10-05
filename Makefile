VERSION ?= "unset"
DATE=$(shell date -u +%Y-%m-%d-%H:%M:%S-%Z)

GEN_SRCS = cmd/hiddenbridge/plugin_config.go
PKG_SRCS = $(shell find ./pkg -name "*.go")

GOBIN ?= $(shell which go)

hiddenbridge: $(shell find ./cmd -name "*.go") $(PKG_SRCS) $(GEN_SRCS)
	$(MAKE) build-ver

signcert: $(shell find ./cmd/signcert -name "*.go")
	$(GOBIN) build -o ./signcert${GO_BUILD_VERSION} ./cmd/signcert

.PHONY: versions
versions:
	rm -rf ./build_versions/*
	./scripts/build_versions.sh

${GO_BUILD_VERSIONS}:
	GOBIN=${HOME}/sdk/go$@/bin/go GO_BUILD_VERSION=$@ ${MAKE} build-ver
	GOBIN=${HOME}/sdk/go$@/bin/go GO_BUILD_VERSION=$@ ${MAKE} signcert

 $(GEN_SRCS): config.yml
	$(GOBIN) generate -x ./...

.PHONY: build
build: $(GEN_SRCS) ## build Hidden Bridge
	$(GOBIN) build -o ./cmd/hiddenbridge/hiddenbridge ./cmd/hiddenbridge

.PHONY: build-ver
build-ver: $(GEN_SRCS) ## build the Hidden Bridge with version number
	GO111MODULE=on CGO_ENABLED=0 GOPROXY="direct" $(GOBIN) build -ldflags "-X hiddenbridge/pkg/build.version=$(VERSION) -X hiddenbridge/pkg/build.buildDate=$(DATE)" -o hiddenbridge ./cmd/hiddenbridge

.PHONY: vendor
vendor:
	$(GOBIN) mod vendor -v 

.PHONY: clean
clean:
	$(GOBIN) clean -x -v -cache -testcache
	rm -rf ./build_versions
	rm -rf ./hiddenbridge ./cmd/hiddenbridge/hiddenbridge
	rm -rf signcert ./cmd/signcert/signcert
	touch config.yml