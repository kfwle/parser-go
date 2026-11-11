BINARY := parser-go
LDFLAGS := -s -w
TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test race vet fmt cross clean run

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/parser

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal assets

cross:
	@mkdir -p dist
	@for target in $(TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "build $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" \
			-o dist/$(BINARY)-$$os-$$arch$$ext ./cmd/parser || exit 1; \
	done

run: build
	./$(BINARY)

clean:
	rm -rf dist $(BINARY) $(BINARY).exe