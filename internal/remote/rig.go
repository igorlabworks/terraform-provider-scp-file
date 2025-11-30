package remote

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/k0sproject/rig/v2"
	"github.com/k0sproject/rig/v2/protocol/ssh"
	"github.com/skeema/knownhosts"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	defaultRigTimeout = 5 * time.Second
)

// RigClient implements the Client interface using the k0sproject/rig library.
type RigClient struct {
	config *Config
	client *rig.Client
}

// NewRigClient creates a new Rig client with the given configuration.
func NewRigClient(config *Config) (*RigClient, error) {
	// Apply SSH config file settings
	sshConfig, err := ParseSSHConfig(config.SSHConfigPath)
	if err == nil {
		sshConfig.ApplyToConfig(config.Host, config)
	}

	return &RigClient{config: config}, nil
}

func (c *RigClient) Connect() error {
	port := c.config.Port
	if port == 0 {
		port = defaultSSHPort
	}

	sshConfig := ssh.Config{
		Address: c.config.Host,
		User:    c.config.User,
		Port:    port,
	}

	if c.config.User == "" {
		sshConfig.User = "root"
	}

	var authMethods []gossh.AuthMethod

	if c.config.Password != "" {
		authMethods = append(authMethods, gossh.Password(c.config.Password))
	}

	if agentAuth := loadSSHAgent(); agentAuth != nil {
		authMethods = append(authMethods, agentAuth)
	}

	if c.config.KeyPath != "" {
		keyPath := expandPath(c.config.KeyPath)
		sshConfig.KeyPath = &keyPath
	}

	if c.config.Password == "" && c.config.KeyPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			for _, keyName := range defaultKeyNames {
				keyPath := filepath.Join(home, ".ssh", keyName)
				sshConfig.KeyPath = &keyPath
				break
			}
		}
	}

	if len(authMethods) > 0 {
		sshConfig.AuthMethods = authMethods
	}

	conn, err := sshConfig.Connection()
	if err != nil {
		return fmt.Errorf("failed to create SSH connection config: %w", err)
	}

	client, err := rig.NewClient(rig.WithConnection(conn))
	if err != nil {
		return fmt.Errorf("failed to create rig client: %w", err)
	}

	// Pre-verify host key using skeema/knownhosts before rig connects
	// to ensure we support multiple key algorithms for the same host
	if !c.config.IgnoreHostKey {
		if err := c.verifyHostKey(c.config.Host, port); err != nil {
			return err
		}
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to SSH server %s:%d: %w", c.config.Host, port, err)
	}

	c.client = client
	return nil
}

func (c *RigClient) Close() error {
	if c.client != nil {
		c.client.Disconnect()
		c.client = nil
	}
	return nil
}

func (c *RigClient) WriteFile(remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error {
	fsys := c.client.FS()

	dir := filepath.Dir(remotePath)
	if err := fsys.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("failed to create remote directory %s: %w", dir, err)
	}

	if err := fsys.WriteFile(remotePath, content, fileMode); err != nil {
		return fmt.Errorf("failed to write remote file %s: %w", remotePath, err)
	}

	return nil
}

func (c *RigClient) ReadFile(remotePath string) ([]byte, error) {
	fsys := c.client.FS()

	content, err := fsys.ReadFile(remotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote file %s: %w", remotePath, err)
	}

	return content, nil
}

func (c *RigClient) FileExists(remotePath string) (bool, error) {
	fsys := c.client.FS()
	_, err := fsys.Stat(remotePath)
	return err == nil, nil
}

func (c *RigClient) DeleteFile(remotePath string) error {
	fsys := c.client.FS()
	fsys.Remove(remotePath)
	return nil
}

func (c *RigClient) verifyHostKey(host string, port int) error {
	// Determine known_hosts file path
	knownHostsPath := c.config.KnownHostsPath
	if knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	} else {
		knownHostsPath = expandPath(knownHostsPath)
	}

	dir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(dir, sshDirPerm); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}
	if err := os.WriteFile(knownHostsPath, []byte{}, knownHostsPerm); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create known_hosts file: %w", err)
	}

	// Use skeema/knownhosts for host key verification
	kh, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	// Create a test connection to verify the host key
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	config := &gossh.ClientConfig{
		User: c.config.User,
		Auth: []gossh.AuthMethod{
			// We need at least one auth method, but we'll fail before auth anyway
			gossh.Password("dummy"),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			// Use knownhosts to verify
			err := kh(hostname, remote, key)
			if err != nil {
				keyLine := knownhosts.Line([]string{host}, key)
				fingerprint := gossh.FingerprintSHA256(key)

				// Check if this is a key changed or unknown error
				if knownhosts.IsHostKeyChanged(err) {
					return fmt.Errorf("host key has changed for %s. This could indicate a man-in-the-middle attack.\n"+
						"Server presented key:\n"+
						"  Type: %s\n"+
						"  Fingerprint: %s\n"+
						"  Key line: %s\n"+
						"If you trust this new key, remove the old entry from %s and add the above line.",
						hostname, key.Type(), fingerprint, keyLine, knownHostsPath)
				}
				if knownhosts.IsHostUnknown(err) {
					return fmt.Errorf("host key not found for %s.\n"+
						"Server presented key:\n"+
						"  Type: %s\n"+
						"  Fingerprint: %s\n"+
						"  Key line: %s\n"+
						"To accept this host, append the above key line to %s",
						hostname, key.Type(), fingerprint, keyLine, knownHostsPath)
				}
				return err
			}
			// Host key is valid - abort the connection since we only wanted to verify
			return fmt.Errorf("host key verified")
		},
		Timeout: defaultRigTimeout,
	}

	client, err := gossh.Dial("tcp", addr, config)
	if client != nil {
		client.Close()
	}

	// If the error is "host key verified", that means verification succeeded
	if err != nil && strings.Contains(err.Error(), "host key verified") {
		return nil
	}

	// If we got a different error, it might be a host key error
	if err != nil {
		return fmt.Errorf("host key verification failed: %w", err)
	}

	return nil
}

func loadSSHAgent() gossh.AuthMethod {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		return nil
	}

	conn, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		return nil
	}

	agentClient := agent.NewClient(conn)
	return gossh.PublicKeysCallback(agentClient.Signers)
}

// isHostKeyError checks if an error is related to host key verification.
func isHostKeyError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "host key") ||
		strings.Contains(errStr, "knownhosts") ||
		strings.Contains(errStr, "key mismatch")
}
