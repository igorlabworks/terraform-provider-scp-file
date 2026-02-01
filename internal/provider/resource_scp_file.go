package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var (
	_ resource.Resource              = (*scpFileResource)(nil)
	_ resource.ResourceWithConfigure = (*scpFileResource)(nil)
)

func NewSCPFileResource() resource.Resource {
	return &scpFileResource{
		scpFileResourceBase: scpFileResourceBase{
			resConfig: scpFileResourceConfig{
				TypeNameSuffix:        "_file",
				DisplayName:           "SCP file",
				DefaultFilePermission: "0777",
				DefaultDirPermission:  "0777",
				ContentIsSensitive:    false,
			},
		},
	}
}

type scpFileResource struct {
	scpFileResourceBase
}

func (r *scpFileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + r.resConfig.TypeNameSuffix
}

func (r *scpFileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = r.buildSchema()
}

func (r *scpFileResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req, resp)
}

func (r *scpFileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.doCreate(ctx, req, resp)
}

func (r *scpFileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.doRead(ctx, req, resp)
}

func (r *scpFileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.doUpdate(ctx, req, resp)
}

func (r *scpFileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.doDelete(ctx, req, resp)
}
