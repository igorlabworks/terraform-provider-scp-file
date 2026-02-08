package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var (
	_ resource.Resource              = (*scpSensitiveFileResource)(nil)
	_ resource.ResourceWithConfigure = (*scpSensitiveFileResource)(nil)
)

func NewSCPSensitiveFileResource() resource.Resource {
	return &scpSensitiveFileResource{
		scpFileResourceBase: scpFileResourceBase{
			resConfig: scpFileResourceConfig{
				TypeNameSuffix:        "_sensitive_file",
				DisplayName:           "SCP Sensitive File",
				DefaultFilePermission: "0700",
				DefaultDirPermission:  "0700",
				ContentIsSensitive:    true,
			},
		},
	}
}

type scpSensitiveFileResource struct {
	scpFileResourceBase
}

func (r *scpSensitiveFileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + r.resConfig.TypeNameSuffix
}

func (r *scpSensitiveFileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = r.buildSchema()
}

func (r *scpSensitiveFileResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

func (r *scpSensitiveFileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.doCreate(ctx, req, resp)
}

func (r *scpSensitiveFileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.doRead(ctx, req, resp)
}

func (r *scpSensitiveFileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.doUpdate(ctx, req, resp)
}

func (r *scpSensitiveFileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.doDelete(ctx, req, resp)
}
