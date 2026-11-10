.PHONY: test vet fmt check

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

check: vet test
	go build ./...
	test -z "$$(gofmt -l .)"
