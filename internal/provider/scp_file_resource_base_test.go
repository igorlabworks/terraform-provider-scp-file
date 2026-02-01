package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/defaults"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestResolveContent(t *testing.T) {
	t.Run("plain content", func(t *testing.T) {
		plan := scpFileResourceModel{
			Content:       types.StringValue("hello world"),
			ContentBase64: types.StringNull(),
			Source:        types.StringNull(),
		}
		got, err := resolveContent(plan)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "hello world" {
			t.Errorf("content = %q, want %q", got, "hello world")
		}
	})

	t.Run("base64 content", func(t *testing.T) {
		plan := scpFileResourceModel{
			Content:       types.StringNull(),
			ContentBase64: types.StringValue("aGVsbG8="),
			Source:        types.StringNull(),
		}
		got, err := resolveContent(plan)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "hello" {
			t.Errorf("content = %q, want %q", got, "hello")
		}
	})

	t.Run("source file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source.txt")
		if err := os.WriteFile(path, []byte("from file"), 0644); err != nil {
			t.Fatal(err)
		}
		plan := scpFileResourceModel{
			Content:       types.StringNull(),
			ContentBase64: types.StringNull(),
			Source:        types.StringValue(path),
		}
		got, err := resolveContent(plan)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "from file" {
			t.Errorf("content = %q, want %q", got, "from file")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		plan := scpFileResourceModel{
			Content:       types.StringNull(),
			ContentBase64: types.StringValue("not-valid-base64!!!"),
			Source:        types.StringNull(),
		}
		_, err := resolveContent(plan)
		if err == nil {
			t.Fatal("expected error for invalid base64, got nil")
		}
	})

	t.Run("missing source file", func(t *testing.T) {
		plan := scpFileResourceModel{
			Content:       types.StringNull(),
			ContentBase64: types.StringNull(),
			Source:        types.StringValue("/nonexistent/path/file.txt"),
		}
		_, err := resolveContent(plan)
		if err == nil {
			t.Fatal("expected error for missing source file, got nil")
		}
	})
}

func TestBuildSchema_NonSensitive(t *testing.T) {
	base := &scpFileResourceBase{
		resConfig: scpFileResourceConfig{
			DefaultFilePermission: "0777",
			DefaultDirPermission:  "0777",
			ContentIsSensitive:    false,
		},
	}
	s := base.buildSchema()

	// content and content_base64 should NOT be sensitive
	for _, name := range []string{"content", "content_base64"} {
		attr, ok := s.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("attribute %q is not a StringAttribute", name)
		}
		if attr.Sensitive {
			t.Errorf("attribute %q should not be sensitive", name)
		}
	}

	// Permission defaults should be 0777
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
}

func TestBuildSchema_Sensitive(t *testing.T) {
	base := &scpFileResourceBase{
		resConfig: scpFileResourceConfig{
			DefaultFilePermission: "0700",
			DefaultDirPermission:  "0700",
			ContentIsSensitive:    true,
		},
	}
	s := base.buildSchema()

	// content and content_base64 must be sensitive
	for _, name := range []string{"content", "content_base64"} {
		attr, ok := s.Attributes[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("attribute %q is not a StringAttribute", name)
		}
		if !attr.Sensitive {
			t.Errorf("attribute %q should be sensitive", name)
		}
	}

	// source must NOT be sensitive regardless of config
	sourceAttr, ok := s.Attributes["source"].(schema.StringAttribute)
	if !ok {
		t.Fatal("attribute \"source\" is not a StringAttribute")
	}
	if sourceAttr.Sensitive {
		t.Error("attribute \"source\" should not be sensitive")
	}

	// Permission defaults should be 0700
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

	// Schema description should mention "sensitive"
	if s.Description != "Generates a file on a remote host via SCP/SFTP with the given sensitive content." {
		t.Errorf("schema description = %q, want sensitive variant", s.Description)
	}
}
