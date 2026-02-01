package provider

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		"scp": providerserver.NewProtocol5WithError(New("test")()),
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

func checkRemoteFileContent(config *scpProviderConfig, remotePath, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		content, err := readRemoteFile(config, remotePath)
		if err != nil {
			return fmt.Errorf("error reading remote file at path: %s, error: %s", remotePath, err)
		}
		checkSums := genFileChecksums(content)

		checks := resource.ComposeTestCheckFunc(
			resource.TestCheckResourceAttr(resourceName, "content_md5", checkSums.md5Hex),
			resource.TestCheckResourceAttr(resourceName, "content_sha1", checkSums.sha1Hex),
			resource.TestCheckResourceAttr(resourceName, "content_sha256", checkSums.sha256Hex),
			resource.TestCheckResourceAttr(resourceName, "content_base64sha256", checkSums.sha256Base64),
			resource.TestCheckResourceAttr(resourceName, "content_sha512", checkSums.sha512Hex),
			resource.TestCheckResourceAttr(resourceName, "content_base64sha512", checkSums.sha512Base64),
		)
		return checks(s)
	}
}

func checkRemoteFileExists(config *scpProviderConfig, remotePath string) resource.TestCheckFunc {
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

func checkRemoteFileHasPermissions(config *scpProviderConfig, remotePath string, expectedPerm os.FileMode) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		info, err := getRemoteFileInfo(config, remotePath)
		if err != nil {
			return fmt.Errorf("error getting file info for %s: %s", remotePath, err)
		}

		actualPerm := info.Mode.Perm()
		if actualPerm != expectedPerm {
			return fmt.Errorf("file %s has permissions %04o, expected %04o", remotePath, actualPerm, expectedPerm)
		}

		return nil
	}
}

func checkRemoteDirectoryHasPermissions(config *scpProviderConfig, remotePath string, expectedPerm os.FileMode) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Get the directory path from the file path
		dirPath := filepath.Dir(remotePath)

		info, err := getRemoteFileInfo(config, dirPath)
		if err != nil {
			return fmt.Errorf("error getting directory info for %s: %s", dirPath, err)
		}

		actualPerm := info.Mode.Perm()
		if actualPerm != expectedPerm {
			return fmt.Errorf("directory %s has permissions %04o, expected %04o", dirPath, actualPerm, expectedPerm)
		}

		return nil
	}
}

func checkRemoteDirectoryExists(config *scpProviderConfig, dirPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		info, err := getRemoteFileInfo(config, dirPath)
		if err != nil {
			return fmt.Errorf("directory %s does not exist: %s", dirPath, err)
		}
		if !info.Mode.IsDir() {
			return fmt.Errorf("path %s exists but is not a directory", dirPath)
		}
		return nil
	}
}

func createRemoteDirectory(config *scpProviderConfig, dirPath string, mode os.FileMode) error {
	client, err := createRemoteClient(config)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		return err
	}

	return writeRemoteFile(config, filepath.Join(dirPath, ".keep"), []byte{}, 0644, mode)
}

func checkMultipleDirectoriesHavePermissions(config *scpProviderConfig, dirs []string, expectedPerm os.FileMode) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for _, dir := range dirs {
			info, err := getRemoteFileInfo(config, dir)
			if err != nil {
				return fmt.Errorf("error getting info for directory %s: %s", dir, err)
			}
			if !info.Mode.IsDir() {
				return fmt.Errorf("path %s is not a directory", dir)
			}
			actualPerm := info.Mode.Perm()
			if actualPerm != expectedPerm {
				return fmt.Errorf("directory %s has permissions %04o, expected %04o", dir, actualPerm, expectedPerm)
			}
		}
		return nil
	}
}

func createLocalSourceFile(sourceFilePath, sourceContent string) error {
	return os.WriteFile(sourceFilePath, []byte(sourceContent), 0644)
}

func skipIfWindows() func() (bool, error) {
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
	// Use exponential backoff: 2s, 4s, 8s, 16s, 32s (up to 62s total)
	for i := 0; i < 5; i++ {
		cmd := exec.Command("ssh-keyscan", "-p", strconv.Itoa(port), "-T", "10", host)
		output, err = cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			break
		}
		if i < 4 {
			// Exponential backoff starting at 2s: 2s, 4s, 8s, 16s, 32s
			delay := time.Duration(2<<uint(i)) * time.Second
			t.Logf("Retry %d: ssh-keyscan failed, retrying in %v...", i+1, delay)
			time.Sleep(delay)
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

// createEmptyKnownHostsFile creates an empty known_hosts file for testing scenarios
// where host key verification should fail or be bypassed.
func createEmptyKnownHostsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("Failed to create empty known_hosts: %v", err)
	}
	return path
}

// getTestRootDir returns the root directory for test files on the remote server.
// It can be configured with TEST_SSH_ROOT_DIR environment variable.
// Default is /tmp/terraform-provider-scp-test to avoid accidentally modifying user files.
func getTestRootDir() string {
	rootDir := os.Getenv("TEST_SSH_ROOT_DIR")
	if rootDir == "" {
		rootDir = "/tmp/terraform-provider-scp-test"
	}
	return rootDir
}

// getTestRemotePath builds a remote path for testing under the configured root directory.
func getTestRemotePath(relativePath string) string {
	return filepath.Join(getTestRootDir(), relativePath)
}

func createTestSSHConfig(t *testing.T, content string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write SSH config: %v", err)
	}
	return configPath
}

func getTestSSHConfig(t *testing.T) *scpProviderConfig {
	t.Helper()

	host := os.Getenv("TEST_SSH_HOST")
	if host == "" {
		host = "localhost"
	}
	port := 22
	if portStr := os.Getenv("TEST_SSH_PORT"); portStr != "" {
		_, _ = fmt.Sscanf(portStr, "%d", &port)
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
	_ = implementation // Implementation is read from env for future use

	// Use per-test known_hosts with exponential backoff retry
	knownHostsPath := setupTestKnownHosts(t, host, port)

	return &scpProviderConfig{
		Host:                     host,
		Port:                     port,
		User:                     user,
		Password:                 password,
		KeyPath:                  keyPath,
		KnownHostsPath:           knownHostsPath,
		IgnoreHostKey:            false,
		ConnectionRetries:        6,    // Higher retries for tests (default is 3)
		ConnectionRetryBaseDelay: 2000, // 2s base delay for tests (default is 500ms)
		// This creates exponential backoff: 2s, 4s, 8s, 16s, 32s (max 62s total).
	}
}

func TestAccProvider_MissingHost(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_missing_host.txt")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "scp" {
						user             = %[1]q
						password         = %[2]q
						known_hosts_path = %[3]q
					}

					resource "scp_file" "test" {
						content  = "test"
						filename = %[4]q
					}
				`, config.User, config.Password, config.KnownHostsPath, remotePath),
				ExpectError: regexp.MustCompile(`(?i)host.*required|required.*host|Missing required argument`),
			},
		},
	})
}

func TestAccProvider_InvalidPort(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_invalid_port.txt")

	testCases := []struct {
		name        string
		port        string
		expectError *regexp.Regexp
	}{
		{
			name:        "negative_port",
			port:        "-1",
			expectError: regexp.MustCompile(`(?i)invalid|port|connection|failed|error`),
		},
		{
			name:        "port_out_of_range",
			port:        "99999",
			expectError: regexp.MustCompile(`(?i)invalid|port|range|connection|failed|error`),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
							provider "scp" {
								host             = %[1]q
								port             = %[2]s
								user             = %[3]q
								password         = %[4]q
								known_hosts_path = %[5]q
							}

							resource "scp_file" "test" {
								content  = "test"
								filename = %[6]q
							}
						`, config.Host, tc.port, config.User, config.Password, config.KnownHostsPath, remotePath),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccProvider_InvalidKnownHostsPath(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_invalid_known_hosts.txt")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "scp" {
						host             = %[1]q
						port             = %[2]d
						user             = %[3]q
						password         = %[4]q
						known_hosts_path = "/nonexistent/path/known_hosts"
					}

					resource "scp_file" "test" {
						content  = "test"
						filename = %[5]q
					}
				`, config.Host, config.Port, config.User, config.Password, remotePath),
				ExpectError: regexp.MustCompile(`(?i)known.?hosts|no such file|does not exist|unable to read|failed to create|read-only file system`),
			},
		},
	})
}
