package provider

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func protoV5ProviderFactories() map[string]func() (tfprotov5.ProviderServer, error) {
	return map[string]func() (tfprotov5.ProviderServer, error){
		"scp": providerserver.NewProtocol5WithError(New("test")),
	}
}

func checkRemoteFileDeleted(config *scpProviderConfig, remotePath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		exists, err := remoteFileExists(config, remotePath)
		if err != nil {
			return fmt.Errorf("error checking if remote file exists: %s", err)
		}
		if exists {
			return fmt.Errorf("remote file %s was not deleted", remotePath)
		}
		return nil
	}
}

func checkRemoteFileCreation(config *scpProviderConfig, remotePath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		content, err := readRemoteFile(config, remotePath)
		if err != nil {
			return fmt.Errorf("error reading remote file at path: %s, error: %s", remotePath, err)
		}
		checkSums := genFileChecksums(content)

		resource.TestCheckResourceAttr("scp_file.test", "content", string(content))
		resource.TestCheckResourceAttr("scp_file.test", "content_md5", checkSums.md5Hex)
		resource.TestCheckResourceAttr("scp_file.test", "content_sha1", checkSums.sha1Hex)
		resource.TestCheckResourceAttr("scp_file.test", "content_sha256", checkSums.sha256Hex)
		resource.TestCheckResourceAttr("scp_file.test", "content_base64sha256", checkSums.sha256Base64)
		resource.TestCheckResourceAttr("scp_file.test", "content_sha512", checkSums.sha512Hex)
		resource.TestCheckResourceAttr("scp_file.test", "content_base64sha512", checkSums.sha512Base64)

		return nil
	}
}

func checkRemoteFilePermissions(config *scpProviderConfig, remotePath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		exists, err := remoteFileExists(config, remotePath)
		if err != nil {
			return fmt.Errorf("error checking remote file: %s", err)
		}
		if !exists {
			return fmt.Errorf("remote file %s does not exist", remotePath)
		}
		return nil
	}
}

func checkRemoteDirectoryPermissions(config *scpProviderConfig, remotePath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		exists, err := remoteFileExists(config, remotePath)
		if err != nil {
			return fmt.Errorf("error checking remote file: %s", err)
		}
		if !exists {
			return fmt.Errorf("remote file %s does not exist (directory may not have been created)", remotePath)
		}
		return nil
	}
}

func createSourceFile(sourceFilePath, sourceContent string) error {
	return os.WriteFile(sourceFilePath, []byte(sourceContent), 0644)
}

func checkDirExists(destinationFilePath string, isDirExist *bool) func() {
	return func() {
		if _, err := os.Stat(path.Dir(destinationFilePath)); !os.IsNotExist(err) {
			*isDirExist = true
		}
	}
}

func skipTestsWindows() func() (bool, error) {
	return func() (bool, error) {
		if runtime.GOOS == "windows" {
			return true, nil
		}
		return false, nil
	}
}

func setupTestKnownHosts(t *testing.T, host string, port int) string {
	t.Helper()

	tempDir := t.TempDir()
	knownHostsPath := filepath.Join(tempDir, "known_hosts")

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var output []byte
	var err error
	for i := 0; i < 5; i++ {
		cmd := exec.Command("ssh-keyscan", "-p", strconv.Itoa(port), "-T", "10", host)
		output, err = cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			break
		}
		if i < 4 {
			t.Logf("Retry %d: ssh-keyscan failed, retrying in 1s...", i+1)
			os.Getenv("CI")
			time.Sleep(time.Second)
		}
	}
	if err != nil {
		t.Fatalf("Failed to scan SSH host keys after retries: %v, output: %s", err, output)
	}

	lines := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if port != 22 {
					hostWithPort := fmt.Sprintf("[%s]:%d %s %s", host, port, parts[1], parts[2])
					lines = append(lines, hostWithPort)
				} else {
					lines = append(lines, line)
				}
			}
		}
	}

	filteredOutput := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(filteredOutput), 0600); err != nil {
		t.Fatalf("Failed to write known_hosts file: %v", err)
	}

	t.Logf("Created test known_hosts file at %s for %s with %d keys", knownHostsPath, addr, len(lines))
	return knownHostsPath
}

func getTestSSHConfig(t *testing.T) *scpProviderConfig {
	t.Helper()

	host := os.Getenv("TEST_SSH_HOST")
	if host == "" {
		host = "localhost"
	}
	port := 22
	if portStr := os.Getenv("TEST_SSH_PORT"); portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}
	user := os.Getenv("TEST_SSH_USER")
	if user == "" {
		user = "testuser"
	}
	password := os.Getenv("TEST_SSH_PASSWORD")
	if password == "" {
		password = "testpass"
	}
	keyPath := os.Getenv("TEST_SSH_KEY_PATH")
	implementation := os.Getenv("TEST_SSH_IMPLEMENTATION")
	if implementation == "" {
		implementation = "sftp"
	}

	knownHostsPath := setupTestKnownHosts(t, host, port)

	return &scpProviderConfig{
		Host:           host,
		Port:           port,
		User:           user,
		Password:       password,
		KeyPath:        keyPath,
		KnownHostsPath: knownHostsPath,
		IgnoreHostKey:  false,
		Implementation: implementation,
	}
}

func getTestSSHConfigWithImplementation(t *testing.T, impl string) *scpProviderConfig {
	t.Helper()
	config := getTestSSHConfig(t)
	config.Implementation = impl
	return config
}
