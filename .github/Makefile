.PHONY: update
update:
	@echo "Updating dependencies..."
	@cd ../ && go get -u ./...
	@go mod tidy

.PHONY: update-linters
update-linters:
	@echo "Updating linters..."
	@go install mvdan.cc/gofumpt@latest
	@go install github.com/daixiang0/gci@latest
	@go install github.com/segmentio/golines@latest
	@go install github.com/google/addlicense@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest
	#@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

.PHONY: fmt
fmt:
	@echo "Formatting ..."
	@go mod tidy
	@go fmt ../...
	@golines -m 120 -t 4 -w ../
	@gofumpt -w -extra ../
	@gci write -s standard -s default -s "Prefix($(shell go list -m))" -s blank -s dot -s alias --skip-generated ../
	@fieldalignment -fix ../...

.PHONY: license
license:
	@echo "Checking License headers ..."
	@if addlicense -check -v -skip yaml -f licence-header.tmpl ../*; then echo "License headers OK"; else return 1; fi;

.PHONY: lint
lint: fmt license
	@echo "Linting ..."
	@if golangci-lint config verify -v --config=.golangci.yml; then echo "Config OK"; else return 1; fi;
	@if golangci-lint run --config=.golangci.yml ../...; then echo "Linting OK"; else return 1; fi;

.PHONY: test
test:
	@echo "Running all tests ..."
	@go test -v -vet=all ../...

.PHONY: cover
cover:
	@echo "Testing with coverage ..."
	@go test -v -race -covermode=atomic -coverpkg=../... -coverprofile=./coverage.out ../tests
