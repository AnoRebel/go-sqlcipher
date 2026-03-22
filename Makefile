.PHONY: all test update-modules

all:
	go build -v ./...

test:
	go test -v -race -count=1 ./...

update-modules:
	go get -u
	go mod tidy -v
