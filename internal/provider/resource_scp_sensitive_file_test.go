package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestSCPSensitiveFile_Content(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_sensitive_file_content.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileConfig(config, "This is sensitive content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_sensitive_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_Base64Content(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_sensitive_file_base64.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileBase64ContentConfig(config, "VGhpcyBpcyBzb21lIGJhc2U2NCBjb250ZW50", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_sensitive_file.test"),
			},
			{
				Config: testAccSCPSensitiveFileDecodedBase64ContentConfig(config, "This is some base64 content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_sensitive_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_Source(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)

	// Create a temporary source file
	sourceDirPath := t.TempDir()
	sourceFilePath := filepath.Join(sourceDirPath, "sensitive_source_file.txt")
	sourceFilePath = strings.ReplaceAll(sourceFilePath, `\`, `\\`)
	if err := createLocalSourceFile(sourceFilePath, "local sensitive file content"); err != nil {
		t.Fatal(err)
	}

	remotePath := getTestRemotePath("test_upload/test_sensitive_file_source.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileSourceConfig(config, sourceFilePath, remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_sensitive_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_Validators(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_sensitive_file_validators.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		CheckDestroy:             nil,
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
				provider "scp" {
				  host             = %[1]q
				  port             = %[2]d
				  user             = %[3]q
				  password         = %[4]q
				  known_hosts_path = %[6]q
				}

				resource "scp_sensitive_file" "file" {
				  filename = %[5]q
				}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
				ExpectError: regexp.MustCompile(`.*Error: Invalid Attribute Combination`),
			},
			{
				Config: fmt.Sprintf(`
				provider "scp" {
				  host             = %[1]q
				  port             = %[2]d
				  user             = %[3]q
				  password         = %[4]q
				  known_hosts_path = %[6]q
				}

				resource "scp_sensitive_file" "file" {
				  content = "content"
				  content_base64 = "Y29udGVudA=="
				  filename = %[5]q
				}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
				ExpectError: regexp.MustCompile(`.*Error: Invalid Attribute Combination`),
			},
		},
	})
}

func TestSCPSensitiveFile_Permissions(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/permissions_test/test_sensitive_file_permissions.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "scp" {
					  host             = %[1]q
					  port             = %[2]d
					  user             = %[3]q
					  password         = %[4]q
					  known_hosts_path = %[6]q
					}

					resource "scp_sensitive_file" "file" {
						content              = "This is some sensitive content"
						filename             = %[5]q
						file_permission      = "9999"
					}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
				ExpectError: regexp.MustCompile(`bad mode permission`),
			},
			{
				SkipFunc: skipIfWindows(),
				Config: fmt.Sprintf(`
					provider "scp" {
					  host             = %[1]q
					  port             = %[2]d
					  user             = %[3]q
					  password         = %[4]q
					  known_hosts_path = %[6]q
					}

					resource "scp_sensitive_file" "file" {
						content              = "This is some sensitive content"
						filename             = %[5]q
						file_permission      = "0600"
						directory_permission = "0700"
					}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
				Check: r.ComposeTestCheckFunc(
					checkRemoteFileExists(config, remotePath),
					checkRemoteFileHasPermissions(config, remotePath, 0600),
					checkRemoteDirectoryHasPermissions(config, remotePath, 0700),
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestAccSCPSensitiveFile_DefaultPermissions(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	// Use a unique path with directory to verify directory permission creation
	remotePath := getTestRemotePath("test_upload/test_sensitive_defaults/test_sensitive_file_default_perms.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				SkipFunc: skipIfWindows(),
				Config:   testAccSCPSensitiveFileConfig(config, "sensitive content for defaults", remotePath),
				Check: r.ComposeTestCheckFunc(
					checkRemoteFileExists(config, remotePath),
					// Verify file has default 0700 permissions (restrictive)
					checkRemoteFileHasPermissions(config, remotePath, 0700),
					// Verify parent directory has default 0700 permissions (restrictive)
					checkRemoteDirectoryHasPermissions(config, remotePath, 0700),
					// Verify Terraform state contains the default values
					r.TestCheckResourceAttr("scp_sensitive_file.test", "file_permission", "0700"),
					r.TestCheckResourceAttr("scp_sensitive_file.test", "directory_permission", "0700"),
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_DriftDetection(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_sensitive_file_drift.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileConfig(config, "Initial sensitive content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_sensitive_file.test"),
			},
			{
				// Simulate external modification by changing the file content
				PreConfig: func() {
					// Modify the remote file directly
					err := writeRemoteFile(config, remotePath, []byte("Modified externally"), 0600, 0700)
					if err != nil {
						t.Fatalf("Failed to modify remote file: %s", err)
					}
				},
				// After drift is detected, the resource will be recreated with the original content
				// Verify the file was restored to the original content
				Config: testAccSCPSensitiveFileConfig(config, "Initial sensitive content", remotePath),
				Check: r.ComposeTestCheckFunc(
					// Verify the remote file has been restored to original content
					func(s *terraform.State) error {
						content, err := readRemoteFile(config, remotePath)
						if err != nil {
							return fmt.Errorf("error reading remote file: %s", err)
						}
						if string(content) != "Initial sensitive content" {
							return fmt.Errorf("drift detection failed: expected 'Initial sensitive content', got '%s'", string(content))
						}
						return nil
					},
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestAccSCPSensitiveFile_PermissionDriftDetection(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_sensitive_perm_drift.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				SkipFunc: skipIfWindows(),
				// Step 1: Create sensitive file with specific permissions (0600)
				Config: testAccSCPSensitiveFileWithPermissions(config, "Sensitive permission drift test", remotePath, "0600"),
				Check: r.ComposeTestCheckFunc(
					checkRemoteFileExists(config, remotePath),
					checkRemoteFileHasPermissions(config, remotePath, 0600),
				),
			},
			{
				SkipFunc: skipIfWindows(),
				// Step 2: Externally modify permissions, then verify Terraform detects and restores
				PreConfig: func() {
					// Simulate external process changing permissions to 0777 (insecure)
					err := chmodRemoteFile(config, remotePath, 0777)
					if err != nil {
						t.Fatalf("Failed to chmod remote file: %s", err)
					}
				},
				Config: testAccSCPSensitiveFileWithPermissions(config, "Sensitive permission drift test", remotePath, "0600"),
				Check: r.ComposeTestCheckFunc(
					// Verify permissions were restored to secure 0600
					checkRemoteFileHasPermissions(config, remotePath, 0600),
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func testAccSCPSensitiveFileConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_sensitive_file" "test" {
		  content  = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func testAccSCPSensitiveFileWithPermissions(config *scpProviderConfig, content, filename, filePermission string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_sensitive_file" "test" {
		  content         = %[5]q
		  filename        = %[6]q
		  file_permission = %[8]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath, filePermission)
}

func testAccSCPSensitiveFileBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_sensitive_file" "test" {
		  content_base64 = %[5]q
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func testAccSCPSensitiveFileSourceConfig(config *scpProviderConfig, source, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_sensitive_file" "test" {
		  source   = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, source, filename, config.KnownHostsPath)
}

func testAccSCPSensitiveFileDecodedBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_sensitive_file" "test" {
		  content_base64 = base64encode(%[5]q)
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}
