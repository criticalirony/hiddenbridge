VERSION ?= "unset"
DATE=$(shell date -u +%Y-%m-%d-%H:%M:%S-%Z)

GEN_SRCS = cmd/hiddenbridge/plugin_config.go
PKG_SRCS = $(shell find ./pkg -name "*.go")

hiddenbridge: $(shell find ./cmd -name "*.go") $(PKG_SRCS) $(GEN_SRCS)
	$(MAKE) build-ver

signcert: $(shell find ./cmd/signcert -name "*.go")
	go build -o ./signcert ./cmd/signcert

 $(GEN_SRCS): config.yml
	go generate -x ./...

.PHONY: build
build: $(GEN_SRCS) ## build Hidden Bridge
	go build -o ./cmd/hiddenbridge/hiddenbridge ./cmd/hiddenbridge

.PHONY: build-ver
build-ver: $(GEN_SRCS) ## build the Hidden Bridge with version number
	GO111MODULE=on CGO_ENABLED=0 GOPROXY="direct" go build -ldflags "-X hiddenbridge/pkg/build.version=$(VERSION) -X hiddenbridge/pkg/build.buildDate=$(DATE)" -o hiddenbridge ./cmd/hiddenbridge

.PHONY: vendor
vendor:
	go mod vendor -v 

.PHONY: clean
clean:
	go clean -x -v -cache -testcache
	rm -rf hiddenbridge ./cmd/hiddenbridge/hiddenbridge
	rm -rf signcert ./cmd/signcert/signcert
	touch config.yml