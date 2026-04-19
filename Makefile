SHELL      := /bin/bash
GO         := go
CC         := gcc

LIB_NAME   := libage.so
HEADER_OUT := libage.h
GO_DIR     := go

DOCKER               := docker
DOCKER_IMAGE         := age-crystal-builder
DOCKER_IMAGE_STATIC  := age-crystal-builder-static
AL2023_IMAGE         := amazonlinux:2023
GO_VERSION           := 1.21.13

.PHONY: all build docker-build docker-build-static clean

all: build

# Local build — requires Go on PATH
build:
	@echo "==> Building $(LIB_NAME) (local)..."
	cd $(GO_DIR) && \
		$(GO) mod download && \
		CGO_ENABLED=1 $(GO) build \
			-buildmode=c-shared \
			-o ../$(LIB_NAME) \
			.
	@echo "==> Done: $(LIB_NAME)"

# AL2023 build — produces an .so compatible with AL2023/RPM targets
# Output lands in dist/ so it's clearly separate from any local build.
docker-build:
	@echo "==> Building $(LIB_NAME) inside Amazon Linux 2023..."
	@mkdir -p dist
	$(DOCKER) build \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-t $(DOCKER_IMAGE) \
		-f Dockerfile.build \
		.
	$(DOCKER) run --rm \
		-v "$(CURDIR)/dist":/output \
		$(DOCKER_IMAGE) \
		cp /build/$(LIB_NAME) /output/$(LIB_NAME)
	@echo "==> Done: dist/$(LIB_NAME)"

# Alpine/musl build — produces a static archive for use in fully static binaries
# Output lands in dist/ alongside the generated header.
docker-build-static:
	@echo "==> Building libage.a (static) inside Alpine..."
	@mkdir -p dist
	$(DOCKER) build \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-t $(DOCKER_IMAGE_STATIC) \
		-f Dockerfile.build.static \
		.
	$(DOCKER) run --rm \
		-v "$(CURDIR)/dist":/output \
		$(DOCKER_IMAGE_STATIC) \
		sh -c "cp /build/libage.a /build/libage.h /output/"
	@echo "==> Done: dist/libage.a dist/libage.h"

clean:
	rm -f $(LIB_NAME) $(HEADER_OUT)
	rm -rf dist/
