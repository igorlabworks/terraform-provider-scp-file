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
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_file_basic.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileConfig(config, "This is some content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
			{
				Config: testAccSCPFileSensitiveContentConfig(config, "This is some sensitive content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
			{
				Config: testAccSCPFileBase64ContentConfig(config, "VGhpcyBpcyBzb21lIGJhc2U2NCBjb250ZW50", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
			{
				Config: testAccSCPFileDecodedBase64ContentConfig(config, "This is some base64 content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Content(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_file_content.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileConfig(config, "This is some content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_SensitiveContent(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_file_sensitive.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileSensitiveContentConfig(config, "This is sensitive content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Base64Content(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_file_base64.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileBase64ContentConfig(config, "VGhpcyBpcyBzb21lIGJhc2U2NCBjb250ZW50", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Source(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()

	// Create a temporary source file
	sourceDirPath := t.TempDir()
	sourceFilePath := filepath.Join(sourceDirPath, "source_file.txt")
	sourceFilePath = strings.ReplaceAll(sourceFilePath, `\`, `\\`)
	if err := createSourceFile(sourceFilePath, "local file content"); err != nil {
		t.Fatal(err)
	}

	remotePath := "/config/test_upload/test_file_source.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileSourceConfig(config, sourceFilePath, remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
			},
		},
		CheckDestroy: checkRemoteFileDeleted(config, remotePath),
	})
}

func TestSCPFile_Validators(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_file_validators.txt"

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
				
				resource "scp_file" "file" {
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
				
				resource "scp_file" "file" {
				  content = "content"
				  sensitive_content = "sensitive_content"
				  filename = %[5]q
				}`, config.Host, config.Port, config.User, config.Password, remotePath),
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

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_file_permissions.txt"

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
					
					resource "scp_file" "file" {
						content              = "This is some content"
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
					
					resource "scp_file" "file" {
						content              = "This is some content"
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

func TestSCPFile_DriftDetection(t *testing.T) {
	// Skip if not in acceptance test mode
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance tests skipped unless TF_ACC is set")
	}

	config := getTestSSHConfig()
	remotePath := "/config/test_upload/test_file_drift.txt"

	r.Test(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: testAccSCPFileConfig(config, "Initial content", remotePath),
				Check:  checkRemoteFileCreation(config, remotePath),
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

func testAccSCPFileConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_file" "test" {
		  content  = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename)
}

func testAccSCPFileSensitiveContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_file" "test" {
		  sensitive_content = %[5]q
		  filename          = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename)
}

func testAccSCPFileBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_file" "test" {
		  content_base64 = %[5]q
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename)
}

func testAccSCPFileSourceConfig(config *scpProviderConfig, source, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_file" "test" {
		  source   = %[5]q
		  filename = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, source, filename)
}

func testAccSCPFileDecodedBase64ContentConfig(config *scpProviderConfig, content, filename string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host     = %[1]q
		  port     = %[2]d
		  user     = %[3]q
		  password = %[4]q
		}

		resource "scp_file" "test" {
		  content_base64 = base64encode(%[5]q)
		  filename       = %[6]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename)
}
