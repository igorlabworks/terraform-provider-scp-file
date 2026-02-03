package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/igorlabworks/terraform-provider-scp/internal/remote"
)

func scpSensitiveFileSchema() schema.Schema {
	res := NewSCPSensitiveFileResource()
	var schemaResp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

// scpSensitiveFileAttrTypes matches scpFileResourceModel — identical shape to scpFileAttrTypes.
func scpSensitiveFileAttrTypes() map[string]tftypes.Type {
	return scpFileAttrTypes()
}

func scpSensitiveFilePlanValue(attrs map[string]tftypes.Value) tftypes.Value {
	return scpFilePlanValueWithDefaults("0700", attrs)
}

func scpSensitiveFileStateValue(attrs map[string]tftypes.Value) tftypes.Value {
	checksums := genFileChecksums([]byte("secret"))
	defaults := map[string]tftypes.Value{
		"filename":             tftypes.NewValue(tftypes.String, "/remote/secret.txt"),
		"content":              tftypes.NewValue(tftypes.String, "secret"),
		"content_base64":       tftypes.NewValue(tftypes.String, nil),
		"source":               tftypes.NewValue(tftypes.String, nil),
		"file_permission":      tftypes.NewValue(tftypes.String, "0600"),
		"directory_permission": tftypes.NewValue(tftypes.String, "0700"),
		"id":                   tftypes.NewValue(tftypes.String, checksums.sha1Hex),
		"content_md5":          tftypes.NewValue(tftypes.String, checksums.md5Hex),
		"content_sha1":         tftypes.NewValue(tftypes.String, checksums.sha1Hex),
		"content_sha256":       tftypes.NewValue(tftypes.String, checksums.sha256Hex),
		"content_base64sha256": tftypes.NewValue(tftypes.String, checksums.sha256Base64),
		"content_sha512":       tftypes.NewValue(tftypes.String, checksums.sha512Hex),
		"content_base64sha512": tftypes.NewValue(tftypes.String, checksums.sha512Base64),
	}
	for k, v := range attrs {
		defaults[k] = v
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: scpSensitiveFileAttrTypes()}, defaults)
}

func TestSCPSensitiveFileResource_Metadata(t *testing.T) {
	res := NewSCPSensitiveFileResource()
	var resp resource.MetadataResponse
	res.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "scp"}, &resp)
	if resp.TypeName != "scp_sensitive_file" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "scp_sensitive_file")
	}
}

func TestSCPSensitiveFileResource_Schema(t *testing.T) {
	res := NewSCPSensitiveFileResource()
	var resp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	s := resp.Schema

	// Required attributes
	for _, name := range []string{"filename"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("missing attribute %q", name)
		}
		if !attr.IsRequired() {
			t.Errorf("attribute %q should be required", name)
		}
	}

	// Optional content sources
	for _, name := range []string{"content", "content_base64", "source"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("missing attribute %q", name)
		}
		if !attr.IsOptional() {
			t.Errorf("attribute %q should be optional", name)
		}
	}

	// Permission defaults are more restrictive than scp_file
	for _, name := range []string{"file_permission", "directory_permission"} {
		attr, ok := s.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("attribute %q is not a StringAttribute", name)
		}
		var defResp defaults.StringResponse
		attr.Default.DefaultString(context.Background(), defaults.StringRequest{}, &defResp)
		if defResp.PlanValue.ValueString() != "0700" {
			t.Errorf("%s default = %q, want %q", name, defResp.PlanValue.ValueString(), "0700")
		}
	}

	// content and content_base64 must be marked sensitive
	for _, name := range []string{"content", "content_base64"} {
		attr, ok := s.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("attribute %q is not a StringAttribute", name)
		}
		if !attr.Sensitive {
			t.Errorf("attribute %q should be sensitive", name)
		}
	}

	// Computed checksum attributes
	for _, name := range []string{"id", "content_md5", "content_sha1", "content_sha256", "content_base64sha256", "content_sha512", "content_base64sha512"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("missing attribute %q", name)
		}
		if !attr.IsComputed() {
			t.Errorf("attribute %q should be computed", name)
		}
	}
}

func TestSCPSensitiveFileResource_Configure(t *testing.T) {
	t.Run("nil provider data", func(t *testing.T) {
		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		resp := &resource.ConfigureResponse{}
		res.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error diagnostics: %v", resp.Diagnostics)
		}
		if res.config != nil {
			t.Error("expected config to remain nil")
		}
	})

	t.Run("correct type", func(t *testing.T) {
		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		cfg := &scpProviderConfig{Host: "example.com"}
		resp := &resource.ConfigureResponse{}
		res.Configure(context.Background(), resource.ConfigureRequest{ProviderData: cfg}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error diagnostics: %v", resp.Diagnostics)
		}
		if res.config != cfg {
			t.Error("config was not assigned")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		resp := &resource.ConfigureResponse{}
		res.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not a config"}, resp)
		if !resp.Diagnostics.HasError() {
			t.Fatal("expected error diagnostics for wrong type")
		}
		if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "string") {
			t.Errorf("error detail = %q, want mention of string type", resp.Diagnostics.Errors()[0].Detail())
		}
	})
}

func TestSCPSensitiveFileResource_Create(t *testing.T) {
	resSchema := scpSensitiveFileSchema()

	t.Run("success", func(t *testing.T) {
		mock := &mockClient{}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		resp := &resource.CreateResponse{
			State: tfsdk.State{
				Schema: resSchema,
				Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: scpSensitiveFileAttrTypes()}, nil),
			},
		}
		req := resource.CreateRequest{
			Plan: tfsdk.Plan{
				Schema: resSchema,
				Raw: scpSensitiveFilePlanValue(map[string]tftypes.Value{
					"filename": tftypes.NewValue(tftypes.String, "/remote/secret.txt"),
					"content":  tftypes.NewValue(tftypes.String, "secret"),
				}),
			},
		}

		res.Create(context.Background(), req, resp)

		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics)
		}
		if len(mock.writeCalls) != 1 {
			t.Fatalf("expected 1 write call, got %d", len(mock.writeCalls))
		}
		if mock.writeCalls[0].path != "/remote/secret.txt" {
			t.Errorf("write path = %q, want %q", mock.writeCalls[0].path, "/remote/secret.txt")
		}
		if string(mock.writeCalls[0].content) != "secret" {
			t.Errorf("write content = %q, want %q", mock.writeCalls[0].content, "secret")
		}
		if mock.writeCalls[0].fileMode != 0700 {
			t.Errorf("fileMode = %04o, want %04o", mock.writeCalls[0].fileMode, os.FileMode(0700))
		}

		var state scpFileResourceModel
		resp.State.Get(context.Background(), &state)
		checksums := genFileChecksums([]byte("secret"))
		if state.ID.ValueString() != checksums.sha1Hex {
			t.Errorf("id = %q, want %q", state.ID.ValueString(), checksums.sha1Hex)
		}
		if state.ContentMd5.ValueString() != checksums.md5Hex {
			t.Errorf("content_md5 = %q, want %q", state.ContentMd5.ValueString(), checksums.md5Hex)
		}
	})

	t.Run("invalid base64 content", func(t *testing.T) {
		mock := &mockClient{}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		resp := &resource.CreateResponse{
			State: tfsdk.State{
				Schema: resSchema,
				Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: scpSensitiveFileAttrTypes()}, nil),
			},
		}
		req := resource.CreateRequest{
			Plan: tfsdk.Plan{
				Schema: resSchema,
				Raw: scpSensitiveFilePlanValue(map[string]tftypes.Value{
					"filename":       tftypes.NewValue(tftypes.String, "/remote/secret.txt"),
					"content":        tftypes.NewValue(tftypes.String, nil),
					"content_base64": tftypes.NewValue(tftypes.String, "!!!invalid!!!"),
				}),
			},
		}

		res.Create(context.Background(), req, resp)

		if !resp.Diagnostics.HasError() {
			t.Fatal("expected error diagnostics for invalid base64")
		}
		if len(mock.writeCalls) != 0 {
			t.Error("expected no write calls on content resolution failure")
		}
	})

	t.Run("write error", func(t *testing.T) {
		mock := &mockClient{writeErr: errors.New("disk full")}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		resp := &resource.CreateResponse{
			State: tfsdk.State{
				Schema: resSchema,
				Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: scpSensitiveFileAttrTypes()}, nil),
			},
		}
		req := resource.CreateRequest{
			Plan: tfsdk.Plan{
				Schema: resSchema,
				Raw: scpSensitiveFilePlanValue(map[string]tftypes.Value{
					"filename": tftypes.NewValue(tftypes.String, "/remote/secret.txt"),
					"content":  tftypes.NewValue(tftypes.String, "secret"),
				}),
			},
		}

		res.Create(context.Background(), req, resp)

		if !resp.Diagnostics.HasError() {
			t.Fatal("expected error diagnostics for write failure")
		}
		if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "disk full") {
			t.Errorf("error detail = %q, want mention of disk full", resp.Diagnostics.Errors()[0].Detail())
		}
	})
}

func TestSCPSensitiveFileResource_Read(t *testing.T) {
	resSchema := scpSensitiveFileSchema()
	checksums := genFileChecksums([]byte("secret"))

	stateForRead := func(overrides map[string]tftypes.Value) tftypes.Value {
		return scpSensitiveFileStateValue(overrides)
	}

	t.Run("file exists matching checksum and permissions", func(t *testing.T) {
		mock := &mockClient{
			readResult: []byte("secret"),
			fileInfo:   &remote.FileInfo{Mode: 0600, Size: 6},
		}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		state := tfsdk.State{Schema: resSchema, Raw: stateForRead(nil)}
		resp := &resource.ReadResponse{State: state}
		req := resource.ReadRequest{State: state}

		res.Read(context.Background(), req, resp)

		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics)
		}
		if resp.State.Raw.IsNull() {
			t.Error("state was removed, expected it to be preserved")
		}
	})

	t.Run("read error removes resource", func(t *testing.T) {
		mock := &mockClient{readErr: errors.New("connection lost")}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		state := tfsdk.State{Schema: resSchema, Raw: stateForRead(nil)}
		resp := &resource.ReadResponse{State: state}
		req := resource.ReadRequest{State: state}

		res.Read(context.Background(), req, resp)

		if !resp.State.Raw.IsNull() {
			t.Error("expected state to be removed after read error")
		}
	})

	t.Run("checksum mismatch removes resource", func(t *testing.T) {
		mock := &mockClient{
			readResult: []byte("tampered"),
			fileInfo:   &remote.FileInfo{Mode: 0600, Size: 8},
		}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		state := tfsdk.State{Schema: resSchema, Raw: stateForRead(map[string]tftypes.Value{
			"id": tftypes.NewValue(tftypes.String, checksums.sha1Hex), // sha1 of "secret"
		})}
		resp := &resource.ReadResponse{State: state}
		req := resource.ReadRequest{State: state}

		res.Read(context.Background(), req, resp)

		if !resp.State.Raw.IsNull() {
			t.Error("expected state to be removed on checksum mismatch")
		}
	})

	t.Run("permission mismatch removes resource", func(t *testing.T) {
		mock := &mockClient{
			readResult: []byte("secret"),
			fileInfo:   &remote.FileInfo{Mode: 0777, Size: 6}, // 0777 != expected 0600
		}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		state := tfsdk.State{Schema: resSchema, Raw: stateForRead(nil)}
		resp := &resource.ReadResponse{State: state}
		req := resource.ReadRequest{State: state}

		res.Read(context.Background(), req, resp)

		if !resp.State.Raw.IsNull() {
			t.Error("expected state to be removed on permission mismatch")
		}
	})

	t.Run("file info error removes resource", func(t *testing.T) {
		mock := &mockClient{
			readResult:  []byte("secret"),
			fileInfoErr: errors.New("stat failed"),
		}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		state := tfsdk.State{Schema: resSchema, Raw: stateForRead(nil)}
		resp := &resource.ReadResponse{State: state}
		req := resource.ReadRequest{State: state}

		res.Read(context.Background(), req, resp)

		if !resp.State.Raw.IsNull() {
			t.Error("expected state to be removed on file info error")
		}
	})
}

func TestSCPSensitiveFileResource_Delete(t *testing.T) {
	resSchema := scpSensitiveFileSchema()

	t.Run("success", func(t *testing.T) {
		mock := &mockClient{}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		state := tfsdk.State{
			Schema: resSchema,
			Raw:    scpSensitiveFileStateValue(map[string]tftypes.Value{"filename": tftypes.NewValue(tftypes.String, "/remote/secret.txt")}),
		}
		resp := &resource.DeleteResponse{}
		req := resource.DeleteRequest{State: state}

		res.Delete(context.Background(), req, resp)

		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected error: %v", resp.Diagnostics)
		}
		if len(mock.deleteCalls) != 1 || mock.deleteCalls[0] != "/remote/secret.txt" {
			t.Errorf("deleteCalls = %v, want [/remote/secret.txt]", mock.deleteCalls)
		}
	})

	t.Run("delete error", func(t *testing.T) {
		mock := &mockClient{deleteErr: errors.New("permission denied")}
		withMockClient(t, mock)

		res, ok := NewSCPSensitiveFileResource().(*scpSensitiveFileResource)
		if !ok {
			t.Fatal("failed to cast to scpSensitiveFileResource")
		}
		res.config = &scpProviderConfig{Host: "test"}
		state := tfsdk.State{
			Schema: resSchema,
			Raw:    scpSensitiveFileStateValue(map[string]tftypes.Value{"filename": tftypes.NewValue(tftypes.String, "/remote/secret.txt")}),
		}
		resp := &resource.DeleteResponse{}
		req := resource.DeleteRequest{State: state}

		res.Delete(context.Background(), req, resp)

		if !resp.Diagnostics.HasError() {
			t.Fatal("expected error diagnostics for delete failure")
		}
		if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "permission denied") {
			t.Errorf("error detail = %q, want mention of permission denied", resp.Diagnostics.Errors()[0].Detail())
		}
	})
}

func TestSCPSensitiveFile_Content(t *testing.T) {
	markAccTest(t)

	config := accTestConfig
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
	markAccTest(t)

	config := accTestConfig
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
	markAccTest(t)

	config := accTestConfig

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
	markAccTest(t)

	config := accTestConfig
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
	markAccTest(t)

	config := accTestConfig
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
	markAccTest(t)

	config := accTestConfig
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
	markAccTest(t)

	config := accTestConfig
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
	markAccTest(t)

	config := accTestConfig
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
