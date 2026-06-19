package provider

import (
	"context"
	"fmt"

	"github.com/menscho/terraform-provider-certcentral/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &CertificateDataSource{}
var _ datasource.DataSourceWithConfigure = &CertificateDataSource{}

type CertificateDataSource struct {
	client *client.Client
}

type CertificateDataSourceModel struct {
	Domain       types.String   `tfsdk:"domain"`
	Sans         []types.String `tfsdk:"sans"`
	Issued       types.Bool     `tfsdk:"issued"`
	Certificate  types.String   `tfsdk:"certificate"`
	PrivateKey   types.String   `tfsdk:"private_key"`
	CertFilename types.String   `tfsdk:"cert_filename"`
	KeyFilename  types.String   `tfsdk:"key_filename"`
}

func NewCertificateDataSource() datasource.DataSource {
	return &CertificateDataSource{}
}

func (d *CertificateDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate_data"
}

func (d *CertificateDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Fetches certificate PEM data and private keys for a given domain from cert-central.",
		Attributes: map[string]schema.Attribute{
			"domain": schema.StringAttribute{
				MarkdownDescription: "The primary domain name to fetch the certificate data for.",
				Required:            true,
			},
			"sans": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Subject Alternative Names (SANs) for this certificate.",
				Computed:            true,
			},
			"issued": schema.BoolAttribute{
				MarkdownDescription: "Whether the certificate has been issued and stored.",
				Computed:            true,
			},
			"certificate": schema.StringAttribute{
				MarkdownDescription: "The PEM-encoded certificate chain.",
				Computed:            true,
				Sensitive:           true,
			},
			"private_key": schema.StringAttribute{
				MarkdownDescription: "The PEM-encoded private key.",
				Computed:            true,
				Sensitive:           true,
			},
			"cert_filename": schema.StringAttribute{
				MarkdownDescription: "The file name of the certificate in the storage directory.",
				Computed:            true,
			},
			"key_filename": schema.StringAttribute{
				MarkdownDescription: "The file name of the private key in the storage directory.",
				Computed:            true,
			},
		},
	}
}

func (d *CertificateDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected DataSource Configure Type", fmt.Sprintf("Expected *client.Client, got: %T", req.ProviderData))
		return
	}

	d.client = c
}

func (d *CertificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CertificateDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certs, err := d.client.GetCertificateData(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to fetch certificate data: %s", err))
		return
	}

	found := false
	for _, c := range certs {
		if c.Domain == data.Domain.ValueString() {
			found = true
			sansVal := []types.String{}
			for _, s := range c.Sans {
				sansVal = append(sansVal, types.StringValue(s))
			}
			data.Sans = sansVal
			data.Issued = types.BoolValue(c.Issued)
			data.Certificate = types.StringValue(c.Certificate)
			data.PrivateKey = types.StringValue(c.PrivateKey)
			data.CertFilename = types.StringValue(c.CertFilename)
			data.KeyFilename = types.StringValue(c.KeyFilename)
			break
		}
	}

	if !found {
		resp.Diagnostics.AddError("Certificate Not Found", fmt.Sprintf("No certificate found for domain %q. Make sure it is configured and has been issued.", data.Domain.ValueString()))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
