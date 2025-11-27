package provider

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	_ provider.Provider = (*scpProvider)(nil)
)

func New() provider.Provider {
	return &scpProvider{}
}

type scpProvider struct {
	config *scpProviderConfig
}

type scpProviderConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	KeyPath  string
}

type scpProviderModel struct {
	Host     types.String `tfsdk:"host"`
	Port     types.Int64  `tfsdk:"port"`
	User     types.String `tfsdk:"user"`
	Password types.String `tfsdk:"password"`
	KeyPath  types.String `tfsdk:"key_path"`
}

func (p *scpProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "scp"
}

func (p *scpProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config scpProviderModel

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set default port if not specified
	port := 22
	if !config.Port.IsNull() && !config.Port.IsUnknown() {
		port = int(config.Port.ValueInt64())
	}

	p.config = &scpProviderConfig{
		Host:     config.Host.ValueString(),
		Port:     port,
		User:     config.User.ValueString(),
		Password: config.Password.ValueString(),
		KeyPath:  config.KeyPath.ValueString(),
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
				Description: "The hostname or IP address of the remote SSH server.",
				Required:    true,
			},
			"port": schema.Int64Attribute{
				Description: "The port of the remote SSH server. Defaults to 22.",
				Optional:    true,
			},
			"user": schema.StringAttribute{
				Description: "The username for SSH authentication.",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description: "The password for SSH authentication. Conflicts with key_path.",
				Optional:    true,
				Sensitive:   true,
			},
			"key_path": schema.StringAttribute{
				Description: "The path to the SSH private key for authentication. " +
					"If not specified, authentication is assumed to be configured in ~/.ssh/config.",
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
	var checksums fileChecksums

	md5Sum := md5.Sum(data)
	checksums.md5Hex = hex.EncodeToString(md5Sum[:])

	sha1Sum := sha1.Sum(data)
	checksums.sha1Hex = hex.EncodeToString(sha1Sum[:])

	sha256Sum := sha256.Sum256(data)
	checksums.sha256Hex = hex.EncodeToString(sha256Sum[:])
	checksums.sha256Base64 = base64.StdEncoding.EncodeToString(sha256Sum[:])

	sha512Sum := sha512.Sum512(data)
	checksums.sha512Hex = hex.EncodeToString(sha512Sum[:])
	checksums.sha512Base64 = base64.StdEncoding.EncodeToString(sha512Sum[:])

	return checksums
}

// sshClient creates an SSH client connection to the remote server
func sshClient(config *scpProviderConfig) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	// Try password authentication first if provided
	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	// Try key-based authentication if key_path is provided
	if config.KeyPath != "" {
		keyPath := config.KeyPath
		// Expand ~ to home directory
		if len(keyPath) >= 2 && keyPath[:2] == "~/" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get home directory: %w", err)
			}
			keyPath = filepath.Join(home, keyPath[2:])
		}

		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH key from %s: %w", keyPath, err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH key: %w", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// If no explicit auth methods, try default SSH agent or keys from ~/.ssh
	if len(authMethods) == 0 {
		// Try default keys
		defaultKeys := []string{"id_rsa", "id_ecdsa", "id_ed25519"}
		home, err := os.UserHomeDir()
		if err == nil {
			for _, keyName := range defaultKeys {
				keyPath := filepath.Join(home, ".ssh", keyName)
				key, err := os.ReadFile(keyPath)
				if err != nil {
					continue
				}
				signer, err := ssh.ParsePrivateKey(key)
				if err != nil {
					continue
				}
				authMethods = append(authMethods, ssh.PublicKeys(signer))
				break
			}
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication methods available")
	}

	sshConfig := &ssh.ClientConfig{
		User:            config.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For simplicity; in production, use proper host key verification
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH server %s: %w", addr, err)
	}

	return client, nil
}

// sftpClient creates an SFTP client from an SSH client
func sftpClient(sshClient *ssh.Client) (*sftp.Client, error) {
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create SFTP client: %w", err)
	}
	return client, nil
}

// writeRemoteFile writes content to a remote file via SFTP
func writeRemoteFile(config *scpProviderConfig, remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error {
	ssh, err := sshClient(config)
	if err != nil {
		return err
	}
	defer ssh.Close()

	sftp, err := sftpClient(ssh)
	if err != nil {
		return err
	}
	defer sftp.Close()

	// Create parent directories if they don't exist
	dir := filepath.Dir(remotePath)
	if err := sftp.MkdirAll(dir); err != nil {
		return fmt.Errorf("failed to create remote directory %s: %w", dir, err)
	}

	// Write the file
	f, err := sftp.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file %s: %w", remotePath, err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("failed to write to remote file %s: %w", remotePath, err)
	}

	// Set file permissions
	if err := sftp.Chmod(remotePath, fileMode); err != nil {
		return fmt.Errorf("failed to set permissions on remote file %s: %w", remotePath, err)
	}

	return nil
}

// readRemoteFile reads content from a remote file via SFTP
func readRemoteFile(config *scpProviderConfig, remotePath string) ([]byte, error) {
	ssh, err := sshClient(config)
	if err != nil {
		return nil, err
	}
	defer ssh.Close()

	sftp, err := sftpClient(ssh)
	if err != nil {
		return nil, err
	}
	defer sftp.Close()

	f, err := sftp.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open remote file %s: %w", remotePath, err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote file %s: %w", remotePath, err)
	}

	return content, nil
}

// remoteFileExists checks if a remote file exists
func remoteFileExists(config *scpProviderConfig, remotePath string) (bool, error) {
	ssh, err := sshClient(config)
	if err != nil {
		return false, err
	}
	defer ssh.Close()

	sftp, err := sftpClient(ssh)
	if err != nil {
		return false, err
	}
	defer sftp.Close()

	_, err = sftp.Stat(remotePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// deleteRemoteFile deletes a remote file via SFTP
func deleteRemoteFile(config *scpProviderConfig, remotePath string) error {
	ssh, err := sshClient(config)
	if err != nil {
		return err
	}
	defer ssh.Close()

	sftp, err := sftpClient(ssh)
	if err != nil {
		return err
	}
	defer sftp.Close()

	if err := sftp.Remove(remotePath); err != nil {
		// Ignore error if file doesn't exist
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete remote file %s: %w", remotePath, err)
		}
	}

	return nil
}
