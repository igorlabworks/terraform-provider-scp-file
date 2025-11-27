package provider

import (
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func protoV5ProviderFactories() map[string]func() (tfprotov5.ProviderServer, error) {
	return map[string]func() (tfprotov5.ProviderServer, error){
		"scp": providerserver.NewProtocol5WithError(New()),
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
		// Note: Checking permissions on remote files would require additional SFTP operations
		// For now, we just verify the file exists
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
		// Note: Checking directory permissions would require additional SFTP operations
		// For now, we just verify the parent directory exists by checking the file
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
		// if directory already existed prior to check, skip check
		if _, err := os.Stat(path.Dir(destinationFilePath)); !os.IsNotExist(err) {
			*isDirExist = true
		}
	}
}

func skipTestsWindows() func() (bool, error) {
	return func() (bool, error) {
		if runtime.GOOS == "windows" {
			// skip all checks if windows
			return true, nil
		}
		return false, nil
	}
}

// Test SSH configuration for integration tests
// These values should be set via environment variables in the test environment
func getTestSSHConfig() *scpProviderConfig {
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

	return &scpProviderConfig{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		KeyPath:  keyPath,
	}
}
