VERSION = "unset"
DATE=$(shell date -u +%Y-%m-%d-%H:%M:%S-%Z)

hiddenbridge:
	$(MAKE) build-ver

.PHONY: build
build: gen-src ## build Hidden Bridge
	go build -o ./cmd/hiddenbridge/hiddenbridge ./cmd/hiddenbridge

.PHONY: build-ver
build-ver: gen-src ## build the Hidden Bridge with version number
	GO111MODULE=on CGO_ENABLED=0 GOPROXY="direct" go build -ldflags "-X hiddenbridge/pkg/build.version=$(VERSION) -X hiddenbridge/pkg/build.buildDate=$(DATE)" -o hiddenbridge ./cmd/hiddenbridge

.PHONY: vendor
vendor:
	go mod vendor -v 

.PHONY: gen-src
gen-src: cmd/hiddenbridge/plugin_config.go

cmd/hiddenbridge/plugin_config.go: config.yml
	go generate -x ./...
