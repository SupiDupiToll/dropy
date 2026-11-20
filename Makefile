.PHONY: build test vet run clean

BINARY ?= dropy
LDFLAGS ?= -s -w

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/dropy

test:
	go test ./...

vet:
	go vet ./...

run:
	DROPY_DEV=true DROPY_DEV_AUTH=true DROPY_SECURE_COOKIES=false \
	DROPY_DATA_DIR=./data DROPY_LISTEN=127.0.0.1:8080 \
	go run ./cmd/dropy serve

clean:
	rm -f $(BINARY)
