package provider

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/igorlabworks/terraform-provider-scp/internal/remote"
)

const (
	defaultSSHPort        = 22
	defaultImplementation = "sftp"
)

var (
	_ provider.Provider = (*scpProvider)(nil)
)

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &scpProvider{
			version: version,
		}
	}
}

type scpProvider struct {
	version string
	config  *scpProviderConfig
}

type scpProviderConfig struct {
	Host           string
	Port           int
	User           string
	Password       string
	KeyPath        string
	KnownHostsPath string
	IgnoreHostKey  bool
	SSHConfigPath  string
	Implementation string
}

type scpProviderModel struct {
	Host           types.String `tfsdk:"host"`
	Port           types.Int64  `tfsdk:"port"`
	User           types.String `tfsdk:"user"`
	Password       types.String `tfsdk:"password"`
	KeyPath        types.String `tfsdk:"key_path"`
	KnownHostsPath types.String `tfsdk:"known_hosts_path"`
	IgnoreHostKey  types.Bool   `tfsdk:"ignore_host_key"`
	SSHConfigPath  types.String `tfsdk:"ssh_config_path"`
	Implementation types.String `tfsdk:"implementation"`
}

func (p *scpProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "scp"
	resp.Version = p.version
}

func (p *scpProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config scpProviderModel

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	port := defaultSSHPort
	if !config.Port.IsNull() && !config.Port.IsUnknown() {
		port = int(config.Port.ValueInt64())
	}

	implementation := defaultImplementation
	if !config.Implementation.IsNull() && !config.Implementation.IsUnknown() {
		implementation = config.Implementation.ValueString()
	}

	p.config = &scpProviderConfig{
		Host:           config.Host.ValueString(),
		Port:           port,
		User:           config.User.ValueString(),
		Password:       config.Password.ValueString(),
		KeyPath:        config.KeyPath.ValueString(),
		KnownHostsPath: config.KnownHostsPath.ValueString(),
		IgnoreHostKey:  config.IgnoreHostKey.ValueBool(),
		SSHConfigPath:  config.SSHConfigPath.ValueString(),
		Implementation: implementation,
	}

	resp.ResourceData = p.config
}

func (p *scpProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *scpProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSCPFileResource,
		NewSCPSensitiveFileResource,
	}
}

func (p *scpProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provider for managing files on remote hosts via SCP/SFTP.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Description: "The hostname or IP address of the remote SSH server. " +
					"Can also be a host alias defined in ~/.ssh/config.",
				Required: true,
			},
			"port": schema.Int64Attribute{
				Description: "The port of the remote SSH server. Defaults to 22. " +
					"Can be overridden by ~/.ssh/config settings.",
				Optional: true,
			},
			"user": schema.StringAttribute{
				Description: "The username for SSH authentication. " +
					"Can be overridden by ~/.ssh/config settings.",
				Optional: true,
			},
			"password": schema.StringAttribute{
				Description: "The password for SSH authentication. Conflicts with key_path.",
				Optional:    true,
				Sensitive:   true,
			},
			"key_path": schema.StringAttribute{
				Description: "The path to the SSH private key for authentication. " +
					"Supports ~ expansion. Can be overridden by ~/.ssh/config IdentityFile directive. " +
					"If not specified, default keys from ~/.ssh/ will be tried.",
				Optional: true,
			},
			"known_hosts_path": schema.StringAttribute{
				Description: "The path to the known_hosts file for host key verification. " +
					"Defaults to ~/.ssh/known_hosts. Supports ~ expansion.",
				Optional: true,
			},
			"ignore_host_key": schema.BoolAttribute{
				Description: "If true, skip host key verification. " +
					"WARNING: This is insecure and should only be used for testing. " +
					"Defaults to false.",
				Optional: true,
			},
			"ssh_config_path": schema.StringAttribute{
				Description: "The path to the SSH config file. " +
					"Defaults to ~/.ssh/config. Supports ~ expansion. " +
					"The provider will read User, Hostname, Port, and IdentityFile directives.",
				Optional: true,
			},
			"implementation": schema.StringAttribute{
				Description: "The implementation to use for remote file operations. " +
					"Valid values are 'sftp' (default) or 'rig'. " +
					"The 'sftp' implementation uses pkg/sftp, while 'rig' uses k0sproject/rig v2.",
				Optional: true,
			},
		},
	}
}

type fileChecksums struct {
	md5Hex       string
	sha1Hex      string
	sha256Hex    string
	sha256Base64 string
	sha512Hex    string
	sha512Base64 string
}

func genFileChecksums(data []byte) fileChecksums {
	md5Sum := md5.Sum(data)
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)
	sha512Sum := sha512.Sum512(data)

	return fileChecksums{
		md5Hex:       hex.EncodeToString(md5Sum[:]),
		sha1Hex:      hex.EncodeToString(sha1Sum[:]),
		sha256Hex:    hex.EncodeToString(sha256Sum[:]),
		sha256Base64: base64.StdEncoding.EncodeToString(sha256Sum[:]),
		sha512Hex:    hex.EncodeToString(sha512Sum[:]),
		sha512Base64: base64.StdEncoding.EncodeToString(sha512Sum[:]),
	}
}

func createRemoteClient(config *scpProviderConfig) (remote.Client, error) {
	return remote.NewClient(&remote.Config{
		Host:           config.Host,
		Port:           config.Port,
		User:           config.User,
		Password:       config.Password,
		KeyPath:        config.KeyPath,
		KnownHostsPath: config.KnownHostsPath,
		IgnoreHostKey:  config.IgnoreHostKey,
		SSHConfigPath:  config.SSHConfigPath,
		Implementation: config.Implementation,
	})
}

func writeRemoteFile(config *scpProviderConfig, remotePath string, content []byte, fileMode, dirMode os.FileMode) error {
	client, err := createRemoteClient(config)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		return err
	}

	return client.WriteFile(remotePath, content, fileMode, dirMode)
}

func readRemoteFile(config *scpProviderConfig, remotePath string) ([]byte, error) {
	client, err := createRemoteClient(config)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		return nil, err
	}

	return client.ReadFile(remotePath)
}

func remoteFileExists(config *scpProviderConfig, remotePath string) (bool, error) {
	client, err := createRemoteClient(config)
	if err != nil {
		return false, err
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		return false, err
	}

	return client.FileExists(remotePath)
}

func deleteRemoteFile(config *scpProviderConfig, remotePath string) error {
	client, err := createRemoteClient(config)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		return err
	}

	return client.DeleteFile(remotePath)
}

func getRemoteFileInfo(config *scpProviderConfig, remotePath string) (*remote.FileInfo, error) {
	client, err := createRemoteClient(config)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		return nil, err
	}

	return client.GetFileInfo(remotePath)
}

func parseFilePermissions(permStr string) os.FileMode {
	perm, _ := strconv.ParseInt(permStr, 8, 64)
	return os.FileMode(perm)
}
