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

func TestSCPFile_Basic(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_file_basic.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileConfig(config, "This is some content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
			{
				Config: testAccSCPFileSensitiveContentConfig(config, "This is some sensitive content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
			{
				Config: testAccSCPFileBase64ContentConfig(config, "VGhpcyBpcyBzb21lIGJhc2U2NCBjb250ZW50", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
			{
				Config: testAccSCPFileDecodedBase64ContentConfig(config, "This is some base64 content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Content(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_file_content.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileConfig(config, "This is some content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_SensitiveContent(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_file_sensitive.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileSensitiveContentConfig(config, "This is sensitive content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Base64Content(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_file_base64.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileBase64ContentConfig(config, "VGhpcyBpcyBzb21lIGJhc2U2NCBjb250ZW50", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Source(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)

	// Create a temporary source file
	sourceDirPath := t.TempDir()
	sourceFilePath := filepath.Join(sourceDirPath, "source_file.txt")
	sourceFilePath = strings.ReplaceAll(sourceFilePath, `\`, `\\`)
	if err := createLocalSourceFile(sourceFilePath, "local file content"); err != nil {
		t.Fatal(err)
	}

	remotePath := getTestRemotePath("test_upload/test_file_source.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileSourceConfig(config, sourceFilePath, remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Validators(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_file_validators.txt")

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

				resource "scp_file" "file" {
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

				resource "scp_file" "file" {
				  content = "content"
				  sensitive_content = "sensitive_content"
				  filename = %[5]q
				}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
				ExpectError: regexp.MustCompile(`.*Error: Invalid Attribute Combination`),
			},
		},
	})
}

func TestSCPFile_Permissions(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/permissions_test/test_file_permissions.txt")

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

					resource "scp_file" "file" {
						content              = "This is some content"
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

					resource "scp_file" "file" {
						content              = "This is some content"
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

func TestAccSCPFile_DefaultPermissions(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	// Use a unique path with directory to verify directory permission creation
	remotePath := getTestRemotePath("test_upload/test_defaults/test_file_default_perms.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				SkipFunc: skipIfWindows(),
				Config:   testAccSCPFileConfigNoPermissions(config, "test content for defaults", remotePath),
				Check: r.ComposeTestCheckFunc(
					checkRemoteFileExists(config, remotePath),
					// Verify file has default 0777 permissions
					checkRemoteFileHasPermissions(config, remotePath, 0777),
					// Verify parent directory has default 0777 permissions
					checkRemoteDirectoryHasPermissions(config, remotePath, 0777),
					// Verify Terraform state contains the default values
					r.TestCheckResourceAttr("scp_file.test", "file_permission", "0777"),
					r.TestCheckResourceAttr("scp_file.test", "directory_permission", "0777"),
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_DriftDetection(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_file_drift.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileConfig(config, "Initial content", remotePath),
				Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
			},
			{
				// Simulate external modification by changing the file content
				PreConfig: func() {
					// Modify the remote file directly
					err := writeRemoteFile(config, remotePath, []byte("Modified externally"), 0644, 0755)
					if err != nil {
						t.Fatalf("Failed to modify remote file: %s", err)
					}
				},
				// After drift is detected, the resource will be recreated with the original content
				// Verify the file was restored to the original content
				Config: testAccSCPFileConfig(config, "Initial content", remotePath),
				Check: r.ComposeTestCheckFunc(
					// Verify the remote file has been restored to original content
					func(s *terraform.State) error {
						content, err := readRemoteFile(config, remotePath)
						if err != nil {
							return fmt.Errorf("error reading remote file: %s", err)
						}
						if string(content) != "Initial content" {
							return fmt.Errorf("drift detection failed: expected 'Initial content', got '%s'", string(content))
						}
						return nil
					},
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestAccSCPFile_PermissionDriftDetection(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/test_file_perm_drift.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				SkipFunc: skipIfWindows(),
				// Step 1: Create file with specific permissions (0644)
				Config: testAccSCPFileWithPermissions(config, "Permission drift test content", remotePath, "0644"),
				Check: r.ComposeTestCheckFunc(
					checkRemoteFileExists(config, remotePath),
					checkRemoteFileHasPermissions(config, remotePath, 0644),
				),
			},
			{
				SkipFunc: skipIfWindows(),
				// Step 2: Externally modify permissions, then verify Terraform detects and restores
				PreConfig: func() {
					// Simulate external process changing permissions to 0755
					err := chmodRemoteFile(config, remotePath, 0755)
					if err != nil {
						t.Fatalf("Failed to chmod remote file: %s", err)
					}
				},
				// Re-apply the same config - Terraform should detect drift and restore
				Config: testAccSCPFileWithPermissions(config, "Permission drift test content", remotePath, "0644"),
				Check: r.ComposeTestCheckFunc(
					// Verify permissions were restored to 0644
					checkRemoteFileHasPermissions(config, remotePath, 0644),
					// Verify content is still correct
					func(s *terraform.State) error {
						content, err := readRemoteFile(config, remotePath)
						if err != nil {
							return fmt.Errorf("error reading remote file: %s", err)
						}
						if string(content) != "Permission drift test content" {
							return fmt.Errorf("content mismatch: expected 'Permission drift test content', got '%s'", string(content))
						}
						return nil
					},
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestAccSCPFile_SSHConfigHostAlias(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/ssh_config_alias.txt")

	// SSH config resolves Hostname, User, and Port from the alias.
	sshConfigPath := createTestSSHConfig(t, fmt.Sprintf(`Host testalias
    Hostname %s
    User %s
    Port %d
`, config.Host, config.User, config.Port))

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "scp" {
					  host             = "testalias"
					  password         = %[1]q
					  known_hosts_path = %[2]q
					  ssh_config_path  = %[3]q
					  ignore_host_key  = true
					}

					resource "scp_file" "test" {
					  content  = "ssh config alias test"
					  filename = %[4]q
					}`, config.Password, config.KnownHostsPath, sshConfigPath, remotePath),
				Check: checkRemoteFileExists(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestAccSCPFile_SSHConfigUserPort(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/ssh_config_user_port.txt")

	// SSH config provides User via wildcard match; provider omits user.
	sshConfigPath := createTestSSHConfig(t, fmt.Sprintf(`Host *
    User %s
`, config.User))

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "scp" {
					  host             = %[1]q
					  port             = %[2]d
					  password         = %[3]q
					  known_hosts_path = %[4]q
					  ssh_config_path  = %[5]q
					  ignore_host_key  = true
					}

					resource "scp_file" "test" {
					  content  = "ssh config user test"
					  filename = %[6]q
					}`, config.Host, config.Port, config.Password, config.KnownHostsPath, sshConfigPath, remotePath),
				Check: checkRemoteFileExists(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestAccSCPFile_CustomSSHConfigPath(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig(t)
	remotePath := getTestRemotePath("test_upload/ssh_config_custom_path.txt")

	// SSH config in a non-default location provides the User directive.
	// If the provider correctly reads the custom path, User will be resolved
	// and the connection will succeed.
	sshConfigPath := createTestSSHConfig(t, fmt.Sprintf(`Host %s
    User %s
`, config.Host, config.User))

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "scp" {
					  host             = %[1]q
					  port             = %[2]d
					  password         = %[3]q
					  known_hosts_path = %[4]q
					  ssh_config_path  = %[5]q
					  ignore_host_key  = true
					}

					resource "scp_file" "test" {
					  content  = "custom ssh config path test"
					  filename = %[6]q
					}`, config.Host, config.Port, config.Password, config.KnownHostsPath, sshConfigPath, remotePath),
				Check: checkRemoteFileExists(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func testAccSCPFileConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  content  = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func testAccSCPFileConfigNoPermissions(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  content  = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func testAccSCPFileWithPermissions(config *scpProviderConfig, content, filename, filePermission string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  content         = %[5]q
		  filename        = %[6]q
		  file_permission = %[8]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath, filePermission)
}

func testAccSCPFileSensitiveContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  sensitive_content = %[5]q
		  filename          = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func testAccSCPFileBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  content_base64 = %[5]q
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func testAccSCPFileSourceConfig(config *scpProviderConfig, source, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  source   = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, source, filename, config.KnownHostsPath)
}

func testAccSCPFileDecodedBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  content_base64 = base64encode(%[5]q)
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func TestAccSCPFile_IgnoreHostKey(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	// Build config manually without setupTestKnownHosts since we want empty known_hosts
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

	config := &scpProviderConfig{
		Host:                     host,
		Port:                     port,
		User:                     user,
		Password:                 password,
		KnownHostsPath:           createEmptyKnownHostsFile(t),
		IgnoreHostKey:            true, // This is the key setting for this test
		ConnectionRetries:        6,
		ConnectionRetryBaseDelay: 2000,
	}

	remotePath := getTestRemotePath("test_upload/test_ignore_host_key.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileIgnoreHostKeyConfig(config, "test content with ignored host key", remotePath),
				Check: r.ComposeTestCheckFunc(
					checkRemoteFileExists(config, remotePath),
					checkRemoteFileContent(config, remotePath, "scp_file.test"),
				),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestAccSCPFile_HostKeyNotFoundFailure(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	// Create a config with empty known_hosts and ignore_host_key = false (default)
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

	// Use empty known_hosts file (no keys)
	knownHostsPath := createEmptyKnownHostsFile(t)

	config := &scpProviderConfig{
		Host:                     host,
		Port:                     port,
		User:                     user,
		Password:                 password,
		KnownHostsPath:           knownHostsPath,
		IgnoreHostKey:            false, // Explicitly set to false
		ConnectionRetries:        6,
		ConnectionRetryBaseDelay: 2000,
	}

	remotePath := getTestRemotePath("test_upload/test_host_key_fail.txt")

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config:      testAccSCPFileConfig(config, "this should fail", remotePath),
				ExpectError: regexp.MustCompile(`host key not found`),
			},
		},
	})
}

func testAccSCPFileIgnoreHostKeyConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		  ignore_host_key  = true
		}

		resource "scp_file" "test" {
		  content  = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath)
}
