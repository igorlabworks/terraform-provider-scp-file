package provider

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/igorlabworks/terraform-provider-scp/internal/localtypes"
)

type scpFileResourceConfig struct {
	TypeNameSuffix        string
	DisplayName           string
	DefaultFilePermission string
	DefaultDirPermission  string
	ContentIsSensitive    bool
}

type scpFileResourceModel struct {
	Filename            types.String                   `tfsdk:"filename"`
	Content             types.String                   `tfsdk:"content"`
	ContentBase64       types.String                   `tfsdk:"content_base64"`
	Source              types.String                   `tfsdk:"source"`
	FilePermission      localtypes.FilePermissionValue `tfsdk:"file_permission"`
	DirectoryPermission localtypes.FilePermissionValue `tfsdk:"directory_permission"`
	ID                  types.String                   `tfsdk:"id"`
	ContentMd5          types.String                   `tfsdk:"content_md5"`
	ContentSha1         types.String                   `tfsdk:"content_sha1"`
	ContentSha256       types.String                   `tfsdk:"content_sha256"`
	ContentBase64sha256 types.String                   `tfsdk:"content_base64sha256"`
	ContentSha512       types.String                   `tfsdk:"content_sha512"`
	ContentBase64sha512 types.String                   `tfsdk:"content_base64sha512"`
}

type scpFileResourceBase struct {
	config    *scpProviderConfig
	resConfig scpFileResourceConfig
}

func (r *scpFileResourceBase) configure(req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(*scpProviderConfig)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *scpProviderConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.config = config
}

func (r *scpFileResourceBase) buildSchema() schema.Schema {
	contentDesc := "Content"
	if r.resConfig.ContentIsSensitive {
		contentDesc = "Sensitive Content"
	}

	schemaDesc := "Generates a file on a remote host via SCP/SFTP with the given content."
	if r.resConfig.ContentIsSensitive {
		schemaDesc = "Generates a file on a remote host via SCP/SFTP with the given sensitive content."
	}

	return schema.Schema{
		Description: schemaDesc,
		Attributes: map[string]schema.Attribute{
			"filename": schema.StringAttribute{
				Description: "The path to the file that will be created on the remote host.\n " +
					"Missing parent directories will be created.\n " +
					"If the file already exists, it will be overridden with the given content.",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"content": schema.StringAttribute{
				Description: contentDesc + " to store in the file, expected to be a UTF-8 encoded string.\n " +
					"Conflicts with `content_base64` and `source`.\n " +
					"Exactly one of these three arguments must be specified.",
				Sensitive: r.resConfig.ContentIsSensitive,
				Optional:  true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content_base64"),
						path.MatchRoot("source")),
				},
			},
			"content_base64": schema.StringAttribute{
				Description: contentDesc + " to store in the file, expected to be binary encoded as base64 string.\n " +
					"Conflicts with `content` and `source`.\n " +
					"Exactly one of these three arguments must be specified.",
				Sensitive: r.resConfig.ContentIsSensitive,
				Optional:  true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content"),
						path.MatchRoot("source")),
				},
			},
			"source": schema.StringAttribute{
				Description: "Path to a local file to use as source for the remote file.\n " +
					"Conflicts with `content` and `content_base64`.\n " +
					"Exactly one of these three arguments must be specified.",
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content"),
						path.MatchRoot("content_base64")),
				},
			},
			"file_permission": schema.StringAttribute{
				CustomType: localtypes.NewFilePermissionType(),
				Description: "Permissions to set for the output file (before umask), expressed as string in\n " +
					"[numeric notation](https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation).\n " +
					fmt.Sprintf("Default value is `\"%s\"`.", r.resConfig.DefaultFilePermission),
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(r.resConfig.DefaultFilePermission),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"directory_permission": schema.StringAttribute{
				CustomType: localtypes.NewFilePermissionType(),
				Description: "Permissions to set for directories created (before umask), expressed as string in\n " +
					"[numeric notation](https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation).\n " +
					fmt.Sprintf("Default value is `\"%s\"`.", r.resConfig.DefaultDirPermission),
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(r.resConfig.DefaultDirPermission),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"id": schema.StringAttribute{
				Description: "The hexadecimal encoding of the SHA1 checksum of the file content.",
				Computed:    true,
			},
			"content_md5": schema.StringAttribute{
				Description: "MD5 checksum of file content.",
				Computed:    true,
			},
			"content_sha1": schema.StringAttribute{
				Description: "SHA1 checksum of file content.",
				Computed:    true,
			},
			"content_sha256": schema.StringAttribute{
				Description: "SHA256 checksum of file content.",
				Computed:    true,
			},
			"content_base64sha256": schema.StringAttribute{
				Description: "Base64 encoded SHA256 checksum of file content.",
				Computed:    true,
			},
			"content_sha512": schema.StringAttribute{
				Description: "SHA512 checksum of file content.",
				Computed:    true,
			},
			"content_base64sha512": schema.StringAttribute{
				Description: "Base64 encoded SHA512 checksum of file content.",
				Computed:    true,
			},
		},
	}
}

func (r *scpFileResourceBase) doCreate(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scpFileResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	content, err := resolveContent(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Create %s error", r.resConfig.DisplayName),
			"An unexpected error occurred while parsing file content\n\n"+
				fmt.Sprintf("Original Error: %s", err),
		)
		return
	}

	if err := writeRemoteFile(
		r.config,
		plan.Filename.ValueString(),
		content,
		parseFilePermissions(plan.FilePermission.ValueString()),
		parseFilePermissions(plan.DirectoryPermission.ValueString()),
	); err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Create %s error", r.resConfig.DisplayName),
			"An unexpected error occurred while writing the remote file\n\n"+
				fmt.Sprintf("Original Error: %s", err),
		)
		return
	}

	checksums := genFileChecksums(content)
	plan.ContentMd5 = types.StringValue(checksums.md5Hex)
	plan.ContentSha1 = types.StringValue(checksums.sha1Hex)
	plan.ContentSha256 = types.StringValue(checksums.sha256Hex)
	plan.ContentBase64sha256 = types.StringValue(checksums.sha256Base64)
	plan.ContentSha512 = types.StringValue(checksums.sha512Hex)
	plan.ContentBase64sha512 = types.StringValue(checksums.sha512Base64)

	plan.ID = types.StringValue(checksums.sha1Hex)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *scpFileResourceBase) doRead(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scpFileResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	outputContent, err := readRemoteFile(r.config, state.Filename.ValueString())
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Error Reading "+
				r.resConfig.DisplayName,
			"An unexpected error occurred while reading the remote file\n\n"+
				fmt.Sprintf("Original Error: %s", err)+
				"\n\nDeleting resource from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	outputChecksum := sha1.Sum(outputContent)
	if hex.EncodeToString(outputChecksum[:]) != state.ID.ValueString() {
		resp.State.RemoveResource(ctx)
		return
	}

	fileInfo, err := getRemoteFileInfo(r.config, state.Filename.ValueString())
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Error Reading "+
				r.resConfig.DisplayName,
			"An unexpected error occurred while getting remote file info\n\n"+
				fmt.Sprintf("Original Error: %s", err)+
				"\n\nDeleting resource from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	expectedPerm := parseFilePermissions(state.FilePermission.ValueString())
	actualPerm := fileInfo.Mode & os.ModePerm
	if actualPerm != expectedPerm {
		resp.State.RemoveResource(ctx)
		return
	}
}

func (r *scpFileResourceBase) doUpdate(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All mutable attributes have RequiresReplace() plan modifiers, so this method
	// should never be called. If it is called, we simply copy the plan to state
	// since the only attributes that could change are computed outputs.
	var plan scpFileResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *scpFileResourceBase) doDelete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var filename string
	req.State.GetAttribute(ctx, path.Root("filename"), &filename)

	if err := deleteRemoteFile(r.config, filename); err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Delete %s error", r.resConfig.DisplayName),
			"An unexpected error occurred while deleting the remote file\n\n"+
				fmt.Sprintf("Original Error: %s", err),
		)
		return
	}
}

func resolveContent(plan scpFileResourceModel) ([]byte, error) {
	if !plan.ContentBase64.IsNull() {
		return base64.StdEncoding.DecodeString(plan.ContentBase64.ValueString())
	}
	if !plan.Source.IsNull() {
		return os.ReadFile(plan.Source.ValueString())
	}
	return []byte(plan.Content.ValueString()), nil
}
