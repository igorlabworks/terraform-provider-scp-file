default: fmt lint install generate

export TEST_SSH_HOST := "openssh-server-scp-provider-test"
export TEST_SSH_PORT := "2222"
export TEST_SSH_USER := "testuser"
export TEST_SSH_PASSWORD := "testpass"

build:
  go build -v ./...

install: build
  go install -v ./...

lint:
  golangci-lint run

generate:
  cd tools && go generate ./...

fmt:
  gofmt -s -w -e .

test:
  go test -v -cover -timeout=120s -parallel=10 ./...

test-acc-docker:
  TF_ACC=1 go test -v -cover -timeout 120m ./...

test-host-up:
  docker run --rm -d \
    --name ${TEST_SSH_HOST} \
    -p ${TEST_SSH_PORT}:22 \
    -e PUID=1000 \
    -e PGID=1000 \
    -e TZ=Etc/UTC \
    -e PASSWORD_ACCESS=true \
    -e USER_PASSWORD=${TEST_SSH_PASSWORD} \
    -e USER_NAME=${TEST_SSH_USER} \
    linuxserver/openssh-server:latest

test-host-down:
  docker stop ${TEST_SSH_HOST} || true