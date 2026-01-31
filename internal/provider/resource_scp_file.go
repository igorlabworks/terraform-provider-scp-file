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

var (
	_ resource.Resource              = (*scpFileResource)(nil)
	_ resource.ResourceWithConfigure = (*scpFileResource)(nil)
)

func NewSCPFileResource() resource.Resource {
	return &scpFileResource{}
}

type scpFileResource struct {
	config *scpProviderConfig
}

func (r *scpFileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *scpFileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a file on a remote host via SCP/SFTP with the given content.",
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
				Description: "Content to store in the file, expected to be a UTF-8 encoded string.\n " +
					"Conflicts with `sensitive_content`, `content_base64` and `source`.\n " +
					"Exactly one of these four arguments must be specified.",
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("sensitive_content"),
						path.MatchRoot("content_base64"),
						path.MatchRoot("source")),
				},
			},
			"content_base64": schema.StringAttribute{
				Description: "Content to store in the file, expected to be binary encoded as base64 string.\n " +
					"Conflicts with `content`, `sensitive_content` and `source`.\n " +
					"Exactly one of these four arguments must be specified.",
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content"),
						path.MatchRoot("sensitive_content"),
						path.MatchRoot("source")),
				},
			},
			"source": schema.StringAttribute{
				Description: "Path to a local file to use as source for the remote file.\n " +
					"Conflicts with `content`, `sensitive_content` and `content_base64`.\n " +
					"Exactly one of these four arguments must be specified.",
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content"),
						path.MatchRoot("sensitive_content"),
						path.MatchRoot("content_base64")),
				},
			},
			"file_permission": schema.StringAttribute{
				CustomType: localtypes.NewFilePermissionType(),
				Description: "Permissions to set for the output file (before umask), expressed as string in\n " +
					"[numeric notation](https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation).\n " +
					"Default value is `\"0777\"`.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("0777"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"directory_permission": schema.StringAttribute{
				CustomType: localtypes.NewFilePermissionType(),
				Description: "Permissions to set for directories created (before umask), expressed as string in\n " +
					"[numeric notation](https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation).\n " +
					"Default value is `\"0777\"`.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("0777"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"id": schema.StringAttribute{
				Description: "The hexadecimal encoding of the SHA1 checksum of the file content.",
				Computed:    true,
			},
			"sensitive_content": schema.StringAttribute{
				DeprecationMessage: "Use the `scp_sensitive_file` resource instead",
				Description: "Sensitive content to store in the file, expected to be an UTF-8 encoded string.\n " +
					"Will not be displayed in diffs.\n " +
					"Conflicts with `content`, `content_base64` and `source`.\n " +
					"Exactly one of these four arguments must be specified.\n " +
					"If in need to use _sensitive_ content, please use the [`scp_sensitive_file`](./sensitive_file.html)\n " +
					"resource instead.",
				Sensitive: true,
				Optional:  true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content"),
						path.MatchRoot("content_base64"),
						path.MatchRoot("source")),
				},
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

func (r *scpFileResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (r *scpFileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scpFileResourceModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	content, err := resolveSCPFileContent(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Create SCP file error",
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
			"Create SCP file error",
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
	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *scpFileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scpFileResourceModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	outputContent, err := readRemoteFile(r.config, state.Filename.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	outputChecksum := sha1.Sum(outputContent)
	if hex.EncodeToString(outputChecksum[:]) != state.ID.ValueString() {
		resp.State.RemoveResource(ctx)
		return
	}

	// Check if file permissions match
	fileInfo, err := getRemoteFileInfo(r.config, state.Filename.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	expectedPerm := parseFilePermissions(state.FilePermission.ValueString())
	actualPerm := fileInfo.Mode & os.ModePerm
	if actualPerm != expectedPerm {
		// Permissions don't match - trigger recreation
		resp.State.RemoveResource(ctx)
		return
	}
}

func (r *scpFileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
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

func (r *scpFileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var filename string
	req.State.GetAttribute(ctx, path.Root("filename"), &filename)

	if err := deleteRemoteFile(r.config, filename); err != nil {
		resp.Diagnostics.AddError(
			"Delete SCP file error",
			"An unexpected error occurred while deleting the remote file\n\n"+
				fmt.Sprintf("Original Error: %s", err),
		)
		return
	}
}

func resolveSCPFileContent(plan scpFileResourceModel) ([]byte, error) {
	if !plan.SensitiveContent.IsNull() {
		return []byte(plan.SensitiveContent.ValueString()), nil
	}
	if !plan.ContentBase64.IsNull() {
		return base64.StdEncoding.DecodeString(plan.ContentBase64.ValueString())
	}
	if !plan.Source.IsNull() {
		return os.ReadFile(plan.Source.ValueString())
	}
	return []byte(plan.Content.ValueString()), nil
}

type scpFileResourceModel struct {
	Filename            types.String                   `tfsdk:"filename"`
	Content             types.String                   `tfsdk:"content"`
	ContentBase64       types.String                   `tfsdk:"content_base64"`
	Source              types.String                   `tfsdk:"source"`
	FilePermission      localtypes.FilePermissionValue `tfsdk:"file_permission"`
	DirectoryPermission localtypes.FilePermissionValue `tfsdk:"directory_permission"`
	ID                  types.String                   `tfsdk:"id"`
	SensitiveContent    types.String                   `tfsdk:"sensitive_content"`
	ContentMd5          types.String                   `tfsdk:"content_md5"`
	ContentSha1         types.String                   `tfsdk:"content_sha1"`
	ContentSha256       types.String                   `tfsdk:"content_sha256"`
	ContentBase64sha256 types.String                   `tfsdk:"content_base64sha256"`
	ContentSha512       types.String                   `tfsdk:"content_sha512"`
	ContentBase64sha512 types.String                   `tfsdk:"content_base64sha512"`
}
