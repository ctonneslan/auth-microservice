.PHONY: build run test docker clean

build:
	go build -o auth-service .

run: build
	./auth-service

test:
	go test ./...

docker:
	docker build -t auth-service .

clean:
	rm -f auth-service
