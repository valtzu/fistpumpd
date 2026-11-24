GO_IMAGE ?= rpi-gotest
RUN = podman run --rm -v $(CURDIR):/src -v rpi-gocache:/root/.cache -w /src $(GO_IMAGE)

test:
	$(RUN) go test -race ./...

test-tpm:
	$(RUN) go test -tags swtpm -race -timeout 600s ./cluster

vectors:
	python3 reference/gen_vectors.py testdata/vectors.json

build:
	$(RUN) sh -c 'for arch in arm64 amd64; do CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o out/rpi-cluster-$$arch ./cmd/rpi-cluster; done'

image:
	podman build -t $(GO_IMAGE) -f Containerfile.test .

.PHONY: test test-tpm vectors build image
