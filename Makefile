VERSION = "unset"
DATE=$(shell date -u +%Y-%m-%d-%H:%M:%S-%Z)

hiddenbridge:
	$(MAKE) build-ver

.PHONY: build
build: ## build Hidden Bridge
	go build -o ./cmd/hiddenbridge/hiddenbridge ./cmd/hiddenbridge

.PHONY: vendor
vendor:
	go mod vendor -v 

.PHONY: build-ver
build-ver: ## build the athens proxy with version number
	GO111MODULE=on CGO_ENABLED=0 GOPROXY="https://proxy.golang.org" go build -ldflags "-X github.com/gomods/athens/pkg/build.version=$(VERSION) -X github.com/gomods/athens/pkg/build.buildDate=$(DATE)" -o athens ./cmd/proxy

hibrid:
	$(MAKE) build-ver