.PHONY: run test vet fmt check

run:
	go run ./examples/graceful

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

check: vet test
	go build ./...
	test -z "$$(gofmt -l .)"
