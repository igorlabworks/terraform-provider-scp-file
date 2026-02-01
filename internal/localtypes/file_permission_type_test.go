package localtypes

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestFilePermissionType_Equal(t *testing.T) {
	t1 := NewFilePermissionType()
	t2 := NewFilePermissionType()

	if !t1.Equal(t2) {
		t.Error("Expected two FilePermissionType values to be equal")
	}
	if t1.Equal(types.StringType) {
		t.Error("Expected FilePermissionType to not equal types.StringType")
	}
}

func TestFilePermissionType_String(t *testing.T) {
	t1 := NewFilePermissionType()
	if t1.String() != "FilePermissionType" {
		t.Errorf("String() = %q, want %q", t1.String(), "FilePermissionType")
	}
}

func TestFilePermissionType_ValueFromString(t *testing.T) {
	typ := NewFilePermissionType()
	stringVal := types.StringValue("0755")

	result, diags := typ.ValueFromString(context.Background(), stringVal)
	if diags.HasError() {
		t.Fatalf("ValueFromString returned errors: %v", diags)
	}

	fpVal, ok := result.(FilePermissionValue)
	if !ok {
		t.Fatalf("Expected FilePermissionValue, got %T", result)
	}
	if fpVal.ValueString() != "0755" {
		t.Errorf("ValueString() = %q, want %q", fpVal.ValueString(), "0755")
	}
}

func TestFilePermissionType_ValueFromTerraform(t *testing.T) {
	typ := NewFilePermissionType()

	tests := []struct {
		name    string
		input   tftypes.Value
		wantErr bool
	}{
		{
			name:  "valid string",
			input: tftypes.NewValue(tftypes.String, "0755"),
		},
		{
			name:  "null value",
			input: tftypes.NewValue(tftypes.String, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := typ.ValueFromTerraform(context.Background(), tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValueFromTerraform() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result == nil {
				t.Error("Expected non-nil result")
			}
		})
	}
}

func TestFilePermissionValue_Equal(t *testing.T) {
	v1 := FilePermissionValue{StringValue: types.StringValue("0755")}
	v2 := FilePermissionValue{StringValue: types.StringValue("0755")}
	v3 := FilePermissionValue{StringValue: types.StringValue("0644")}

	if !v1.Equal(v2) {
		t.Error("Expected v1 and v2 to be equal")
	}
	if v1.Equal(v3) {
		t.Error("Expected v1 and v3 to not be equal")
	}
	if v1.Equal(types.StringValue("0755")) {
		t.Error("Expected FilePermissionValue to not equal a plain StringValue")
	}
}

func TestFilePermissionValue_ValidateAttribute(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
		errorMsg  string
	}{
		{"valid 3-digit", "755", false, ""},
		{"valid 4-digit", "0755", false, ""},
		{"valid 0777", "0777", false, ""},
		{"valid 644", "644", false, ""},
		{"too short", "77", true, "string length should be 3 or 4"},
		{"too long", "07777", true, "string length should be 3 or 4"},
		{"invalid octal 8", "888", true, "must be expressed in octal"},
		{"invalid octal 9", "799", true, "must be expressed in octal"},
		{"non-numeric", "abc", true, "must be expressed in octal"},
		{"exceeds 0777", "1000", true, "must be expressed in octal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := FilePermissionValue{StringValue: types.StringValue(tt.value)}
			resp := &xattr.ValidateAttributeResponse{
				Diagnostics: diag.Diagnostics{},
			}
			v.ValidateAttribute(context.Background(), xattr.ValidateAttributeRequest{
				Path: path.Empty(),
			}, resp)

			if tt.wantError && !resp.Diagnostics.HasError() {
				t.Errorf("Expected validation error for %q, got none", tt.value)
			}
			if !tt.wantError && resp.Diagnostics.HasError() {
				t.Errorf("Expected no validation error for %q, got: %v", tt.value, resp.Diagnostics)
			}
			if tt.wantError && resp.Diagnostics.HasError() {
				detail := resp.Diagnostics[0].Detail()
				if !strings.Contains(detail, tt.errorMsg) {
					t.Errorf("Expected error detail to contain %q, got %q", tt.errorMsg, detail)
				}
			}
		})
	}
}
