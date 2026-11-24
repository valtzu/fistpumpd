GO_IMAGE ?= fistpumpd-test
VERSION ?= dev
RUN = podman run --rm -v $(CURDIR):/src -v fistpumpd-gocache:/root/.cache -w /src $(GO_IMAGE)

test:
	$(RUN) go test -race ./...

test-tpm:
	$(RUN) go test -tags swtpm -race -timeout 600s ./cluster

build:
	$(RUN) sh -c 'for arch in arm64 amd64; do CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o out/fistpumpd-$$arch ./cmd/fistpumpd; done'

image:
	podman build -t $(GO_IMAGE) -f Containerfile.test .

.PHONY: test test-tpm build image
