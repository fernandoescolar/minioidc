## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOLANGCI_LINT_VERSION ?= v1.54.0

fmt:
	go fmt ./...

vet:
	go vet ./...

.PHONY: test
test: fmt vet
	go test ./...

.PHONY: build
build: fmt vet
	go build -o bin/minioidc ./cmd/main.go

.PHONY: build-docker
build-docker:
	docker build -t minioidc:latest .

.PHONY: run-docker
run-docker:
	docker run -p 8000:8000 -v ./example2_config.yml:/config/configuration.yml -v ./private.pem:/certificates/private.pem -e MINIOIDC_CONFIG=/config/configuration.yml minioidc:latest

.PHONY: run
run:
	go run ./cmd/minioidc/main.go

golangci-lint: ## Download golangci-lint locally if necessary.
	$(call go-get-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: lint
lint: golangci-lint
	$(GOLANGCI_LINT) run

.PHONY: clean
clean:
	rm -rf bin

.PHONY: hash
hash:
	@go run ./cmd/hasher/main.go $(text)


PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
go get -d $(2)@$(3) ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef
