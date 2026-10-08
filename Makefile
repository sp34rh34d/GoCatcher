APP     := gocatcher
VERSION := 1.0
OUT     := dist

# Plataformas: GOOS/GOARCH
PLATFORMS := linux/amd64 linux/arm64 linux/arm \
             darwin/amd64 darwin/arm64 \
             windows/amd64 windows/arm64 \
             freebsd/amd64

GOFLAGS := -trimpath -ldflags "-s -w"

.PHONY: all build cross clean fmt vet run

# Compila solo para el SO/arch actual.
build:
	go build $(GOFLAGS) -o $(APP) .

# Compila para todos los sistemas operativos -> dist/
cross: clean
	@mkdir -p $(OUT)
	@$(foreach p,$(PLATFORMS), \
		os=$(word 1,$(subst /, ,$(p))); arch=$(word 2,$(subst /, ,$(p))); \
		name=$(APP)-$(VERSION)-$$os-$$arch; \
		[ "$$os" = "windows" ] && name=$$name.exe; \
		echo ">> $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -o $(OUT)/$$name . ; \
	)
	@echo "" && ls -lh $(OUT)

run: build
	./$(APP)

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -rf $(OUT) $(APP) $(APP).exe
