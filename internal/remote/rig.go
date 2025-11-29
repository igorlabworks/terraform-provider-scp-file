package remote

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/k0sproject/rig/v2"
	"github.com/k0sproject/rig/v2/protocol/ssh"
	"github.com/skeema/knownhosts"
	gossh "golang.org/x/crypto/ssh"
)

// RigClient implements the Client interface using the k0sproject/rig library.
type RigClient struct {
	config *Config
	client *rig.Client
}

// NewRigClient creates a new Rig client with the given configuration.
func NewRigClient(config *Config) (*RigClient, error) {
	// Apply SSH config file settings
	if config.SSHConfigPath != "" || config.Host != "" {
		sshConfig, err := ParseSSHConfig(config.SSHConfigPath)
		if err == nil {
			sshConfig.ApplyToConfig(config.Host, config)
		}
	}

	return &RigClient{config: config}, nil
}

// Connect establishes a connection using rig.
func (c *RigClient) Connect() error {
	port := c.config.Port
	if port == 0 {
		port = 22
	}

	user := c.config.User
	if user == "" {
		user = "root"
	}

	// Build SSH config
	sshConfig := ssh.Config{
		Address: c.config.Host,
		User:    user,
		Port:    port,
	}

	// Set authentication methods
	var authMethods []gossh.AuthMethod

	if c.config.Password != "" {
		authMethods = append(authMethods, gossh.Password(c.config.Password))
	}

	if c.config.KeyPath != "" {
		keyPath := expandPath(c.config.KeyPath)
		sshConfig.KeyPath = &keyPath
	}

	// If no explicit auth methods, try default SSH keys
	if c.config.Password == "" && c.config.KeyPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			// OpenSSH key precedence order
			defaultKeys := []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}
			for _, keyName := range defaultKeys {
				keyPath := filepath.Join(home, ".ssh", keyName)
				if _, err := os.Stat(keyPath); err == nil {
					sshConfig.KeyPath = &keyPath
					break
				}
			}
		}
	}

	if len(authMethods) > 0 {
		sshConfig.AuthMethods = authMethods
	}

	// Create the connection
	conn, err := sshConfig.Connection()
	if err != nil {
		return fmt.Errorf("failed to create SSH connection config: %w", err)
	}

	// Create rig client
	client, err := rig.NewClient(rig.WithConnection(conn))
	if err != nil {
		return fmt.Errorf("failed to create rig client: %w", err)
	}

	// Connect to the remote host
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to SSH server %s:%d: %w", c.config.Host, port, err)
	}

	c.client = client
	return nil
}

// Close closes the rig connection.
func (c *RigClient) Close() error {
	if c.client != nil {
		c.client.Disconnect()
		c.client = nil
	}
	return nil
}

// WriteFile writes content to a remote file using rig.
func (c *RigClient) WriteFile(remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error {
	if c.client == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}

	fsys := c.client.FS()

	// Create parent directories if they don't exist
	dir := filepath.Dir(remotePath)
	if err := fsys.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("failed to create remote directory %s: %w", dir, err)
	}

	// Write the file
	if err := fsys.WriteFile(remotePath, content, fileMode); err != nil {
		return fmt.Errorf("failed to write remote file %s: %w", remotePath, err)
	}

	return nil
}

// ReadFile reads content from a remote file using rig.
func (c *RigClient) ReadFile(remotePath string) ([]byte, error) {
	if c.client == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	fsys := c.client.FS()

	content, err := fsys.ReadFile(remotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote file %s: %w", remotePath, err)
	}

	return content, nil
}

// FileExists checks if a remote file exists using rig.
func (c *RigClient) FileExists(remotePath string) (bool, error) {
	if c.client == nil {
		if err := c.Connect(); err != nil {
			return false, err
		}
	}

	fsys := c.client.FS()

	_, err := fsys.Stat(remotePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteFile deletes a remote file using rig.
func (c *RigClient) DeleteFile(remotePath string) error {
	if c.client == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}

	fsys := c.client.FS()

	if err := fsys.Remove(remotePath); err != nil {
		// Ignore error if file doesn't exist
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete remote file %s: %w", remotePath, err)
		}
	}

	return nil
}

// createHostKeyCallback creates the host key callback for SSH connections.
// This is kept for reference but rig handles host key verification internally.
func (c *RigClient) createHostKeyCallback() (gossh.HostKeyCallback, error) {
	if c.config.IgnoreHostKey {
		return gossh.InsecureIgnoreHostKey(), nil
	}

	// Determine known_hosts file path
	knownHostsPath := c.config.KnownHostsPath
	if knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	} else {
		knownHostsPath = expandPath(knownHostsPath)
	}

	// Check if known_hosts file exists
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		// Create the directory if it doesn't exist
		dir := filepath.Dir(knownHostsPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create .ssh directory: %w", err)
		}
		// Create an empty known_hosts file
		if err := os.WriteFile(knownHostsPath, []byte{}, 0600); err != nil {
			return nil, fmt.Errorf("failed to create known_hosts file: %w", err)
		}
	}

	// Use skeema/knownhosts for host key verification
	kh, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	// Wrap the callback to provide helpful error messages
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		err := kh(hostname, remote, key)
		if err != nil {
			// Check if this is a key not found error
			if knownhosts.IsHostKeyChanged(err) {
				return &HostKeyError{
					Host:           hostname,
					KeyType:        key.Type(),
					KeyFingerprint: gossh.FingerprintSHA256(key),
					KnownHostsLine: knownhosts.Line([]string{hostname}, key),
					Err:            fmt.Errorf("host key has changed for %s. This could indicate a man-in-the-middle attack. "+
						"If you trust the new key, remove the old entry from %s and add this line:\n%s",
						hostname, knownHostsPath, knownhosts.Line([]string{hostname}, key)),
				}
			}
			if knownhosts.IsHostUnknown(err) {
				return &HostKeyError{
					Host:           hostname,
					KeyType:        key.Type(),
					KeyFingerprint: gossh.FingerprintSHA256(key),
					KnownHostsLine: knownhosts.Line([]string{hostname}, key),
					Err:            fmt.Errorf("host key not found for %s. To add this host, append this line to %s:\n%s",
						hostname, knownHostsPath, knownhosts.Line([]string{hostname}, key)),
				}
			}
			return err
		}
		return nil
	}, nil
}
