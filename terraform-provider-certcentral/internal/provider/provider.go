package provider

import (
	"context"

	"github.com/menscho/terraform-provider-certcentral/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type CertCentralProvider struct {
	version string
}

type CertCentralProviderModel struct {
	Address types.String `tfsdk:"address"`
	Token   types.String `tfsdk:"token"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &CertCentralProvider{
			version: version,
		}
	}
}

func (p *CertCentralProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "certcentral"
	resp.Version = p.version
}

func (p *CertCentralProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				MarkdownDescription: "The HTTP address of the cert-central server (e.g. http://localhost:8080).",
				Required:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "The Admin API key token used for control plane authorization.",
				Required:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *CertCentralProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data CertCentralProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	address := data.Address.ValueString()
	token := data.Token.ValueString()

	c := client.NewClient(address, token)

	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *CertCentralProvider) Resources(ctx context.Context) []func() resource.Resource {
	return nil
}

func (p *CertCentralProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}
