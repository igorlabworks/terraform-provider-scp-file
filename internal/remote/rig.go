package remote

import (
	"context"
	"errors"
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

	// The rig library handles host key verification internally
	// We need to configure it through other means

	// Set authentication methods
	var authMethods []gossh.AuthMethod

	if c.config.Password != "" {
		authMethods = append(authMethods, gossh.Password(c.config.Password))
	}

	// Try SSH agent authentication
	if agentAuth := loadSSHAgent(); agentAuth != nil {
		authMethods = append(authMethods, agentAuth)
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

	// Pre-verify host key using skeema/knownhosts before rig connects
	// This ensures we support multiple key algorithms for the same host
	if !c.config.IgnoreHostKey {
		if err := c.verifyHostKey(c.config.Host, port); err != nil {
			return err
		}
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

// verifyHostKey pre-verifies the host key using skeema/knownhosts.
// This allows us to support multiple key algorithms for the same host.
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

	// Check if known_hosts file exists
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		// Create the directory if it doesn't exist
		dir := filepath.Dir(knownHostsPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create .ssh directory: %w", err)
		}
		// Create an empty known_hosts file
		if err := os.WriteFile(knownHostsPath, []byte{}, 0600); err != nil {
			return fmt.Errorf("failed to create known_hosts file: %w", err)
		}
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
		Timeout: 5 * time.Second,
	}

	// Attempt connection - we expect it to fail after host key verification
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

// loadSSHAgent attempts to connect to the SSH agent and returns an AuthMethod.
// Returns nil if the SSH agent is not available.
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

// enhanceHostKeyError fetches the server's actual public key and enhances the error message.
func enhanceHostKeyError(originalErr error, host string, port int) error {
	// Try to fetch the server's public key by connecting with InsecureIgnoreHostKey
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// Create a simple SSH config that ignores host keys
	config := &gossh.ClientConfig{
		User:            "dummy", // We don't need to auth, just get the key
		Auth:            []gossh.AuthMethod{},
		HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			// Capture the key and return an error to abort the connection
			// We'll use a custom error that includes the key info
			return &capturedKeyError{
				hostname: hostname,
				key:      key,
			}
		},
		Timeout: 5 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, config)
	if client != nil {
		client.Close()
	}

	// Check if we captured the key
	var capturedErr *capturedKeyError
	if err != nil && errors.As(err, &capturedErr) {
		keyLine := knownhosts.Line([]string{host}, capturedErr.key)
		fingerprint := gossh.FingerprintSHA256(capturedErr.key)

		return fmt.Errorf("%w\n"+
			"Server presented key:\n"+
			"  Hostname: %s\n"+
			"  Type: %s\n"+
			"  Fingerprint: %s\n"+
			"  Key line: %s\n"+
			"To accept this host, add the above key line to your ~/.ssh/known_hosts file.",
			originalErr, capturedErr.hostname, capturedErr.key.Type(), fingerprint, keyLine)
	}

	// If we couldn't fetch the key, return the original error
	return originalErr
}

// capturedKeyError is used to capture the server's public key during connection.
type capturedKeyError struct {
	hostname string
	key      gossh.PublicKey
}

func (e *capturedKeyError) Error() string {
	return "captured key"
}

