default: fmt lint install generate

export SSH_HOST := "openssh-server-test-host"
export TEST_SSH_HOST := "localhost"
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
  TF_ACC=1 go test -v -cover -timeout 120m -parallel=1 ./...

test-host-up:
  docker run --rm -d \
    --name ${SSH_HOST} \
    -p ${TEST_SSH_PORT}:2222 \
    -e PUID=1000 \
    -e PGID=1000 \
    -e TZ=Etc/UTC \
    -e PASSWORD_ACCESS=true \
    -e USER_PASSWORD=${TEST_SSH_PASSWORD} \
    -e USER_NAME=${TEST_SSH_USER} \
    linuxserver/openssh-server:latest
  @echo "Waiting for SSH server to start..."
  @sleep 3
  @echo "Configuring SSH server for higher connection limits..."
  docker exec ${SSH_HOST} sh -c 'echo "MaxStartups 100:30:200" >> /config/sshd/sshd_config'
  docker exec ${SSH_HOST} sh -c 'echo "MaxSessions 100" >> /config/sshd/sshd_config'
  docker exec ${SSH_HOST} pkill -HUP sshd || true
  @echo "SSH server configured and ready for testing"

test-host-down:
  docker stop ${SSH_HOST} || true