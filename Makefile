.PHONY: all build test clean

export GO111MODULE=on

OUTPUT = ping

all: build
build: 
	go build -o ./build/${OUTPUT} ./cmd/ping.go
	@echo Ping built at ./build/${OUUTPUT}

dev: 
	go run cmd/ping.go google.com
	
test:
	go test -v ./pkg/*

clean:
	rm build/*