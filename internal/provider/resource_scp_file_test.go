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

func scpFileSchema() schema.Schema {
	res := NewSCPFileResource()
	var schemaResp resource.SchemaResponse
	res.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	return schemaResp.Schema
}

// scpFileAttrTypes returns the tftypes.Object attribute types matching scpFileResourceModel.
func scpFileAttrTypes() map[string]tftypes.Type {
	return map[string]tftypes.Type{
		"filename":             tftypes.String,
		"content":              tftypes.String,
		"content_base64":       tftypes.String,
		"source":               tftypes.String,
		"file_permission":      tftypes.String,
		"directory_permission": tftypes.String,
		"id":                   tftypes.String,
		"content_md5":          tftypes.String,
		"content_sha1":         tftypes.String,
		"content_sha256":       tftypes.String,
		"content_base64sha256": tftypes.String,
		"content_sha512":       tftypes.String,
		"content_base64sha512": tftypes.String,
	}
}

func scpFilePlanValueWithDefaults(defaultPerm string, attrs map[string]tftypes.Value) tftypes.Value {
	defaults := map[string]tftypes.Value{
		"filename":             tftypes.NewValue(tftypes.String, ""),
		"content":              tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"content_base64":       tftypes.NewValue(tftypes.String, nil),
		"source":               tftypes.NewValue(tftypes.String, nil),
		"file_permission":      tftypes.NewValue(tftypes.String, defaultPerm),
		"directory_permission": tftypes.NewValue(tftypes.String, defaultPerm),
		"id":                   tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"content_md5":          tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"content_sha1":         tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"content_sha256":       tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"content_base64sha256": tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"content_sha512":       tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"content_base64sha512": tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
	}
	for k, v := range attrs {
		defaults[k] = v
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: scpFileAttrTypes()}, defaults)
}

func scpFilePlanValue(attrs map[string]tftypes.Value) tftypes.Value {
	return scpFilePlanValueWithDefaults("0777", attrs)
}

func scpFileStateValue(attrs map[string]tftypes.Value) tftypes.Value {
	defaults := map[string]tftypes.Value{
		"filename":             tftypes.NewValue(tftypes.String, "/remote/file.txt"),
		"content":              tftypes.NewValue(tftypes.String, "hello"),
		"content_base64":       tftypes.NewValue(tftypes.String, nil),
		"source":               tftypes.NewValue(tftypes.String, nil),
		"file_permission":      tftypes.NewValue(tftypes.String, "0644"),
		"directory_permission": tftypes.NewValue(tftypes.String, "0755"),
		"id":                   tftypes.NewValue(tftypes.String, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
		"content_md5":          tftypes.NewValue(tftypes.String, "5d41402abc4b2a76b9719d911017c592"),
		"content_sha1":         tftypes.NewValue(tftypes.String, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
		"content_sha256":       tftypes.NewValue(tftypes.String, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
		"content_base64sha256": tftypes.NewValue(tftypes.String, "LPJNul+wowomboOyrFueKeGxYeXB+nJeZwQzNik4mYI="),
		"content_sha512":       tftypes.NewValue(tftypes.String, "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"),
		"content_base64sha512": tftypes.NewValue(tftypes.String, "m3HSJL1i83eNltRq0+o9czGb+8KJDKrepd/3JRlnPKcjI8PZm6XBHXx6zG4Uuc1aBGY0dcLlw+re9G9z3EDAM="),
	}
	for k, v := range attrs {
		defaults[k] = v
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: scpFileAttrTypes()}, defaults)
}

func TestSCPFileResource(t *testing.T) {
	t.Run("Metadata", func(t *testing.T) {
		res := NewSCPFileResource()
		var resp resource.MetadataResponse
		res.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "scp"}, &resp)
		if resp.TypeName != "scp_file" {
			t.Errorf("TypeName = %q, want %q", resp.TypeName, "scp_file")
		}
	})

	t.Run("Schema", func(t *testing.T) {
		res := NewSCPFileResource()
		var resp resource.SchemaResponse
		res.Schema(context.Background(), resource.SchemaRequest{}, &resp)
		s := resp.Schema

		for _, name := range []string{"filename"} {
			attr, ok := s.Attributes[name]
			if !ok {
				t.Fatalf("missing attribute %q", name)
			}
			if !attr.IsRequired() {
				t.Errorf("attribute %q should be required", name)
			}
		}

		for _, name := range []string{"content", "content_base64", "source"} {
			attr, ok := s.Attributes[name]
			if !ok {
				t.Fatalf("missing attribute %q", name)
			}
			if !attr.IsOptional() {
				t.Errorf("attribute %q should be optional", name)
			}
		}

		for _, name := range []string{"file_permission", "directory_permission"} {
			attr, ok := s.Attributes[name].(schema.StringAttribute)
			if !ok {
				t.Fatalf("attribute %q is not a StringAttribute", name)
			}
			var defResp defaults.StringResponse
			attr.Default.DefaultString(context.Background(), defaults.StringRequest{}, &defResp)
			if defResp.PlanValue.ValueString() != "0777" {
				t.Errorf("%s default = %q, want %q", name, defResp.PlanValue.ValueString(), "0777")
			}
		}

		for _, name := range []string{"id", "content_md5", "content_sha1", "content_sha256", "content_base64sha256", "content_sha512", "content_base64sha512"} {
			attr, ok := s.Attributes[name]
			if !ok {
				t.Fatalf("missing attribute %q", name)
			}
			if !attr.IsComputed() {
				t.Errorf("attribute %q should be computed", name)
			}
		}
	})

	t.Run("Configure", func(t *testing.T) {
		t.Run("nil provider data", func(t *testing.T) {
			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
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
			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
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
			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
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
	})

	t.Run("Create", func(t *testing.T) {
		resSchema := scpFileSchema()

		t.Run("success", func(t *testing.T) {
			mock := &mockClient{}
			withMockClient(t, mock)

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
			}
			res.config = &scpProviderConfig{Host: "test"}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Schema: resSchema,
					Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: scpFileAttrTypes()}, nil),
				},
			}
			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Schema: resSchema,
					Raw: scpFilePlanValue(map[string]tftypes.Value{
						"filename": tftypes.NewValue(tftypes.String, "/remote/file.txt"),
						"content":  tftypes.NewValue(tftypes.String, "hello"),
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
			if mock.writeCalls[0].path != "/remote/file.txt" {
				t.Errorf("write path = %q, want %q", mock.writeCalls[0].path, "/remote/file.txt")
			}
			if string(mock.writeCalls[0].content) != "hello" {
				t.Errorf("write content = %q, want %q", mock.writeCalls[0].content, "hello")
			}

			var state scpFileResourceModel
			resp.State.Get(context.Background(), &state)
			checksums := genFileChecksums([]byte("hello"))
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

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
			}
			res.config = &scpProviderConfig{Host: "test"}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Schema: resSchema,
					Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: scpFileAttrTypes()}, nil),
				},
			}
			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Schema: resSchema,
					Raw: scpFilePlanValue(map[string]tftypes.Value{
						"filename":       tftypes.NewValue(tftypes.String, "/remote/file.txt"),
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

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
			}
			res.config = &scpProviderConfig{Host: "test"}
			resp := &resource.CreateResponse{
				State: tfsdk.State{
					Schema: resSchema,
					Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: scpFileAttrTypes()}, nil),
				},
			}
			req := resource.CreateRequest{
				Plan: tfsdk.Plan{
					Schema: resSchema,
					Raw: scpFilePlanValue(map[string]tftypes.Value{
						"filename": tftypes.NewValue(tftypes.String, "/remote/file.txt"),
						"content":  tftypes.NewValue(tftypes.String, "hello"),
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
	})

	t.Run("Read", func(t *testing.T) {
		resSchema := scpFileSchema()
		checksums := genFileChecksums([]byte("hello"))

		stateForRead := func(overrides map[string]tftypes.Value) tftypes.Value {
			return scpFileStateValue(overrides)
		}

		t.Run("file exists matching checksum and permissions", func(t *testing.T) {
			mock := &mockClient{
				readResult: []byte("hello"),
				fileInfo:   &remote.FileInfo{Mode: 0644, Size: 5},
			}
			withMockClient(t, mock)

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
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

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
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
				readResult: []byte("different content"),
				fileInfo:   &remote.FileInfo{Mode: 0644, Size: 17},
			}
			withMockClient(t, mock)

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
			}
			res.config = &scpProviderConfig{Host: "test"}
			state := tfsdk.State{Schema: resSchema, Raw: stateForRead(map[string]tftypes.Value{
				"id": tftypes.NewValue(tftypes.String, checksums.sha1Hex),
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
				readResult: []byte("hello"),
				fileInfo:   &remote.FileInfo{Mode: 0755, Size: 5},
			}
			withMockClient(t, mock)

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
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
				readResult:  []byte("hello"),
				fileInfoErr: errors.New("stat failed"),
			}
			withMockClient(t, mock)

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
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
	})

	t.Run("Delete", func(t *testing.T) {
		resSchema := scpFileSchema()

		t.Run("success", func(t *testing.T) {
			mock := &mockClient{}
			withMockClient(t, mock)

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
			}
			res.config = &scpProviderConfig{Host: "test"}
			state := tfsdk.State{
				Schema: resSchema,
				Raw:    scpFileStateValue(map[string]tftypes.Value{"filename": tftypes.NewValue(tftypes.String, "/remote/file.txt")}),
			}
			resp := &resource.DeleteResponse{}
			req := resource.DeleteRequest{State: state}

			res.Delete(context.Background(), req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected error: %v", resp.Diagnostics)
			}
			if len(mock.deleteCalls) != 1 || mock.deleteCalls[0] != "/remote/file.txt" {
				t.Errorf("deleteCalls = %v, want [/remote/file.txt]", mock.deleteCalls)
			}
		})

		t.Run("delete error", func(t *testing.T) {
			mock := &mockClient{deleteErr: errors.New("permission denied")}
			withMockClient(t, mock)

			res, ok := NewSCPFileResource().(*scpFileResource)
			if !ok {
				t.Fatal("failed to cast to scpFileResource")
			}
			res.config = &scpProviderConfig{Host: "test"}
			state := tfsdk.State{
				Schema: resSchema,
				Raw:    scpFileStateValue(map[string]tftypes.Value{"filename": tftypes.NewValue(tftypes.String, "/remote/file.txt")}),
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
	})
}

func TestAccSCPFile(t *testing.T) {
	markAccTest(t)

	t.Run("Content", func(t *testing.T) {
		config := accTestConfig
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
	})

	t.Run("Base64Content", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/test_file_base64.txt")

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
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
	})

	t.Run("Source", func(t *testing.T) {
		config := accTestConfig

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
	})

	t.Run("Validator_NoContentSource", func(t *testing.T) {
		config := accTestConfig
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
			},
		})
	})

	t.Run("Validator_ConflictingContentSources", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/test_file_conflicting_sources.txt")

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
					  content        = "content"
					  content_base64 = "Y29udGVudA=="
					  filename       = %[5]q
					}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
					ExpectError: regexp.MustCompile(`.*Error: Invalid Attribute Combination`),
				},
			},
		})
	})

	t.Run("Permissions", func(t *testing.T) {
		config := accTestConfig
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
					Config: fmt.Sprintf(`
						provider "scp" {
						  host             = %[1]q
						  port             = %[2]d
						  user             = %[3]q
						  password         = %[4]q
						  known_hosts_path = %[6]q
						}

						resource "scp_file" "file" {
							content         = "This is some content"
							filename        = %[5]q
							file_permission = "77"
						}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
					ExpectError: regexp.MustCompile(`string length should be 3 or 4`),
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
							content         = "This is some content"
							filename        = %[5]q
							file_permission = "07777"
						}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
					ExpectError: regexp.MustCompile(`string length should be 3 or 4`),
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
							content         = "This is some content"
							filename        = %[5]q
							file_permission = "abc"
						}`, config.Host, config.Port, config.User, config.Password, remotePath, config.KnownHostsPath),
					ExpectError: regexp.MustCompile(`must be expressed in octal`),
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
	})

	t.Run("DefaultPermissions", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/test_defaults/test_file_default_perms.txt")

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					SkipFunc: skipIfWindows(),
					Config:   testAccSCPFileConfig(config, "test content for defaults", remotePath),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileExists(config, remotePath),
						checkRemoteFileHasPermissions(config, remotePath, 0777),
						checkRemoteDirectoryHasPermissions(config, remotePath, 0777),
						r.TestCheckResourceAttr("scp_file.test", "file_permission", "0777"),
						r.TestCheckResourceAttr("scp_file.test", "directory_permission", "0777"),
					),
				},
			},
			CheckDestroy: checkRemoteFileDeleted(config, remotePath),
		})
	})

	t.Run("DriftDetection", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/test_file_drift.txt")

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					Config: testAccSCPFileConfig(config, "Initial content", remotePath),
					Check:  checkRemoteFileContent(config, remotePath, "scp_file.test"),
				},
				{
					PreConfig: func() {
						err := writeRemoteFile(config, remotePath, []byte("Modified externally"), 0644, 0755)
						if err != nil {
							t.Fatalf("Failed to modify remote file: %s", err)
						}
					},
					Config: testAccSCPFileConfig(config, "Initial content", remotePath),
					Check: r.ComposeTestCheckFunc(
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
	})

	t.Run("PermissionDriftDetection", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/test_file_perm_drift.txt")

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					SkipFunc: skipIfWindows(),
					Config:   testAccSCPFileWithPermissions(config, "Permission drift test content", remotePath, "0644"),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileExists(config, remotePath),
						checkRemoteFileHasPermissions(config, remotePath, 0644),
					),
				},
				{
					SkipFunc: skipIfWindows(),
					PreConfig: func() {
						err := chmodRemoteFile(config, remotePath, 0755)
						if err != nil {
							t.Fatalf("Failed to chmod remote file: %s", err)
						}
					},
					Config: testAccSCPFileWithPermissions(config, "Permission drift test content", remotePath, "0644"),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileHasPermissions(config, remotePath, 0644),
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
	})

	t.Run("SSHConfigHostAlias", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/ssh_config_alias.txt")

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
	})

	t.Run("SSHConfigUserPort", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/ssh_config_user_port.txt")

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
	})

	t.Run("CustomSSHConfigPath", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/ssh_config_custom_path.txt")

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
	})

	t.Run("ExplicitCustomPort", func(t *testing.T) {
		config := accTestConfig

		if config.Port == 22 {
			t.Skip("This test requires a custom port (not 22)")
		}

		remotePath := getTestRemotePath("test_upload/test_explicit_custom_port.txt")

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					Config: testAccSCPFileExplicitPortConfig(config, "test content with explicit port", remotePath, config.Port),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileExists(config, remotePath),
						checkRemoteFileContent(config, remotePath, "scp_file.test"),
					),
				},
			},
			CheckDestroy: checkRemoteFileDeleted(config, remotePath),
		})
	})

	t.Run("IgnoreHostKey", func(t *testing.T) {
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
			IgnoreHostKey:            true,
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
	})

	t.Run("HostKeyNotFoundFailure", func(t *testing.T) {
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
			IgnoreHostKey:            false,
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
	})

	t.Run("DeepDirectoryCreation", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/deep/nested/path/structure/file.txt")

		dirs := []string{
			getTestRemotePath("test_upload/deep"),
			getTestRemotePath("test_upload/deep/nested"),
			getTestRemotePath("test_upload/deep/nested/path"),
			getTestRemotePath("test_upload/deep/nested/path/structure"),
		}

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					Config: testAccSCPFileWithDirectoryPermissions(config, "test content", remotePath, "0644", "0755"),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileExists(config, remotePath),
						checkRemoteFileHasPermissions(config, remotePath, 0644),
						checkMultipleDirectoriesHavePermissions(config, dirs, 0755),
					),
				},
			},
			CheckDestroy: checkRemoteFileDeleted(config, remotePath),
		})
	})

	t.Run("DirectoryCreationWithDefaults", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/default_dir_test/subdir/file.txt")

		dirs := []string{
			getTestRemotePath("test_upload/default_dir_test"),
			getTestRemotePath("test_upload/default_dir_test/subdir"),
		}

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					Config: testAccSCPFileConfig(config, "test content", remotePath),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileExists(config, remotePath),
						checkMultipleDirectoriesHavePermissions(config, dirs, 0777),
					),
				},
			},
			CheckDestroy: checkRemoteFileDeleted(config, remotePath),
		})
	})

	t.Run("ExistingDirectoryNotModified", func(t *testing.T) {
		config := accTestConfig
		preexistingDir := getTestRemotePath("test_upload/preexisting_dir")
		remotePath := getTestRemotePath("test_upload/preexisting_dir/subdir/file.txt")
		subdirPath := getTestRemotePath("test_upload/preexisting_dir/subdir")

		if err := createRemoteDirectory(config, preexistingDir, 0700); err != nil {
			t.Fatalf("Failed to create pre-existing directory: %v", err)
		}

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					Config: testAccSCPFileWithDirectoryPermissions(config, "test content", remotePath, "0644", "0755"),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileExists(config, remotePath),
						checkRemoteFileHasPermissions(config, remotePath, 0644),
						checkRemoteDirectoryExists(config, preexistingDir),
						checkMultipleDirectoriesHavePermissions(config, []string{preexistingDir}, 0700),
						checkRemoteDirectoryExists(config, subdirPath),
						checkMultipleDirectoriesHavePermissions(config, []string{subdirPath}, 0755),
					),
				},
			},
			CheckDestroy: checkRemoteFileDeleted(config, remotePath),
		})
	})

	t.Run("SingleLevelDirectory", func(t *testing.T) {
		config := accTestConfig
		remotePath := getTestRemotePath("test_upload/single_level_test/file.txt")
		dirPath := getTestRemotePath("test_upload/single_level_test")

		r.Test(t, r.TestCase{
			ProtoV5ProviderFactories: protoV5ProviderFactories(),
			Steps: []r.TestStep{
				{
					Config: testAccSCPFileWithDirectoryPermissions(config, "test content", remotePath, "0644", "0755"),
					Check: r.ComposeTestCheckFunc(
						checkRemoteFileExists(config, remotePath),
						checkRemoteFileHasPermissions(config, remotePath, 0644),
						checkRemoteDirectoryExists(config, dirPath),
						checkMultipleDirectoriesHavePermissions(config, []string{dirPath}, 0755),
					),
				},
			},
			CheckDestroy: checkRemoteFileDeleted(config, remotePath),
		})
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

func testAccSCPFileExplicitPortConfig(config *scpProviderConfig, content, filename string, explicitPort int) string {
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
		}`, config.Host, explicitPort, config.User, config.Password, content, filename, config.KnownHostsPath)
}

func testAccSCPFileWithDirectoryPermissions(config *scpProviderConfig, content, filename, filePermission, directoryPermission string) string {
	return fmt.Sprintf(`
		provider "scp" {
		  host             = %[1]q
		  port             = %[2]d
		  user             = %[3]q
		  password         = %[4]q
		  known_hosts_path = %[7]q
		}

		resource "scp_file" "test" {
		  content              = %[5]q
		  filename             = %[6]q
		  file_permission      = %[8]q
		  directory_permission = %[9]q
		}`, config.Host, config.Port, config.User, config.Password, content, filename, config.KnownHostsPath, filePermission, directoryPermission)
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
