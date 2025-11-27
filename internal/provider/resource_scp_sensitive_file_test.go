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

func TestSCPSensitiveFile_Basic(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_sensitive_file_basic.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileConfig(config, "This is some sensitive content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
			{
				Config: testAccSCPSensitiveFileBase64ContentConfig(config, "VGhpcyBpcyBzb21lIGJhc2U2NCBjb250ZW50", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
			{
				Config: testAccSCPSensitiveFileDecodedBase64ContentConfig(config, "This is some base64 content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_Content(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_sensitive_file_content.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileConfig(config, "This is sensitive content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_Base64Content(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_sensitive_file_base64.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileBase64ContentConfig(config, "VGhpcyBpcyBzb21lIGJhc2U2NCBjb250ZW50", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_Source(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()

	// Create a temporary source file
	sourceDirPath := t.TempDir()
	sourceFilePath := filepath.Join(sourceDirPath, "sensitive_source_file.txt")
	sourceFilePath = strings.ReplaceAll(sourceFilePath, `\`, `\\`)
	if err := createSourceFile(sourceFilePath, "local sensitive file content"); err != nil {
		t.Fatal(err)
	}

	remotePath := "/config/test_upload/test_sensitive_file_source.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileSourceConfig(config, sourceFilePath, remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPSensitiveFile_Validators(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_sensitive_file_validators.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		CheckDestroy:             nil,
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
				provider "scp" {
				  host     = %[1]q
				  port     = %[2]d
				  user     = %[3]q
				  password = %[4]q
				}
				
				resource "scp_sensitive_file" "file" {
				  filename = %[5]q
				}`, config.Host, config.Port, config.User, config.Password, remotePath),
				ExpectError: regexp.MustCompile(`.*Error: Invalid Attribute Combination`),
			},
			{
				Config: fmt.Sprintf(`
				provider "scp" {
				  host     = %[1]q
				  port     = %[2]d
				  user     = %[3]q
				  password = %[4]q
				}
				
				resource "scp_sensitive_file" "file" {
				  content = "content"
				  content_base64 = "Y29udGVudA=="
				  filename = %[5]q
				}`, config.Host, config.Port, config.User, config.Password, remotePath),
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

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_sensitive_file_permissions.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "scp" {
					  host     = %[1]q
					  port     = %[2]d
					  user     = %[3]q
					  password = %[4]q
					}
					
					resource "scp_sensitive_file" "file" {
						content              = "This is some sensitive content"
						filename             = %[5]q
						file_permission      = "9999"
					}`, config.Host, config.Port, config.User, config.Password, remotePath),
				ExpectError: regexp.MustCompile(`bad mode permission`),
			},
			{
				SkipFunc: skipTestsWindows(),
				Config: fmt.Sprintf(`
					provider "scp" {
					  host     = %[1]q
					  port     = %[2]d
					  user     = %[3]q
					  password = %[4]q
					}
					
					resource "scp_sensitive_file" "file" {
						content              = "This is some sensitive content"
						filename             = %[5]q
						file_permission      = "0600"
						directory_permission = "0700"
					}`, config.Host, config.Port, config.User, config.Password, remotePath),
				Check: r.ComposeTestCheckFunc(
					checkRemoteFilePermissions(config, remotePath),
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

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_sensitive_file_drift.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPSensitiveFileConfig(config, "Initial sensitive content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
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

func testAccSCPSensitiveFileConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_sensitive_file" "test" {
		  content  = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename)
}

func testAccSCPSensitiveFileBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_sensitive_file" "test" {
		  content_base64 = %[5]q
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename)
}

func testAccSCPSensitiveFileSourceConfig(config *scpProviderConfig, source, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_sensitive_file" "test" {
		  source   = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, source, filename)
}

func testAccSCPSensitiveFileDecodedBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_sensitive_file" "test" {
		  content_base64 = base64encode(%[5]q)
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename)
}
