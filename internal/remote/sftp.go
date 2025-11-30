package remote

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/sftp"
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SFTPClient implements the Client interface using the pkg/sftp library.
type SFTPClient struct {
	config     *Config
	sshClient  *ssh.Client
	sftpClient *sftp.Client
}

// NewSFTPClient creates a new SFTP client with the given configuration.
func NewSFTPClient(config *Config) (*SFTPClient, error) {
	// Apply SSH config file settings
	sshConfig, err := ParseSSHConfig(config.SSHConfigPath)
	if err == nil {
		sshConfig.ApplyToConfig(config.Host, config)
	}

	return &SFTPClient{config: config}, nil
}

// Connect establishes an SSH connection and creates an SFTP client.
func (c *SFTPClient) Connect() error {
	var authMethods []ssh.AuthMethod

	// Try password authentication first if provided
	if c.config.Password != "" {
		authMethods = append(authMethods, ssh.Password(c.config.Password))
	}

	// Try SSH agent authentication
	if agentAuth := c.loadSSHAgent(); agentAuth != nil {
		authMethods = append(authMethods, agentAuth)
	}

	// Try key-based authentication if key_path is provided
	if c.config.KeyPath != "" {
		keyPath := expandPath(c.config.KeyPath)
		key, err := os.ReadFile(keyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(key)
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
			// If the key is passphrase-protected or can't be parsed, skip it.
			// The SSH agent should handle passphrase-protected keys.
		}
	}

	// If no explicit auth methods, try default SSH keys from ~/.ssh
	if len(authMethods) == 0 {
		authMethods = c.loadDefaultKeys()
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no SSH authentication methods available")
	}

	// Set up host key callback
	hostKeyCallback, err := c.createHostKeyCallback()
	if err != nil {
		return err
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.config.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
		// Follow OpenSSH key algorithm precedence
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoDSA,
		},
	}

	port := c.config.Port
	if port == 0 {
		port = 22
	}

	addr := net.JoinHostPort(c.config.Host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server %s: %w", addr, err)
	}

	c.sshClient = client

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}

	c.sftpClient = sftpClient
	return nil
}

// Close closes the SFTP and SSH connections.
func (c *SFTPClient) Close() error {
	var errs []error
	if c.sftpClient != nil {
		if err := c.sftpClient.Close(); err != nil {
			errs = append(errs, err)
		}
		c.sftpClient = nil
	}
	if c.sshClient != nil {
		if err := c.sshClient.Close(); err != nil {
			errs = append(errs, err)
		}
		c.sshClient = nil
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing connections: %v", errs)
	}
	return nil
}

// WriteFile writes content to a remote file via SFTP.
func (c *SFTPClient) WriteFile(remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error {
	if c.sftpClient == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}

	// Create parent directories if they don't exist
	dir := filepath.Dir(remotePath)
	if err := c.sftpClient.MkdirAll(dir); err != nil {
		return fmt.Errorf("failed to create remote directory %s: %w", dir, err)
	}

	// Write the file
	f, err := c.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file %s: %w", remotePath, err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("failed to write to remote file %s: %w", remotePath, err)
	}

	// Set file permissions
	if err := c.sftpClient.Chmod(remotePath, fileMode); err != nil {
		return fmt.Errorf("failed to set permissions on remote file %s: %w", remotePath, err)
	}

	return nil
}

// ReadFile reads content from a remote file via SFTP.
func (c *SFTPClient) ReadFile(remotePath string) ([]byte, error) {
	if c.sftpClient == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	f, err := c.sftpClient.Open(remotePath)
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

// FileExists checks if a remote file exists.
func (c *SFTPClient) FileExists(remotePath string) (bool, error) {
	if c.sftpClient == nil {
		if err := c.Connect(); err != nil {
			return false, err
		}
	}

	_, err := c.sftpClient.Stat(remotePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteFile deletes a remote file via SFTP.
func (c *SFTPClient) DeleteFile(remotePath string) error {
	if c.sftpClient == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}

	if err := c.sftpClient.Remove(remotePath); err != nil {
		// Ignore error if file doesn't exist
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete remote file %s: %w", remotePath, err)
		}
	}

	return nil
}

// loadDefaultKeys tries to load default SSH keys from ~/.ssh
// Note: This only loads unencrypted keys. Passphrase-protected keys should be
// handled by the SSH agent.
func (c *SFTPClient) loadDefaultKeys() []ssh.AuthMethod {
	var authMethods []ssh.AuthMethod

	// OpenSSH key precedence order
	defaultKeys := []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}
	home, err := os.UserHomeDir()
	if err != nil {
		return authMethods
	}

	for _, keyName := range defaultKeys {
		keyPath := filepath.Join(home, ".ssh", keyName)
		key, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			// Skip passphrase-protected or invalid keys
			continue
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	return authMethods
}

// loadSSHAgent attempts to connect to the SSH agent and returns an AuthMethod.
// Returns nil if the SSH agent is not available.
func (c *SFTPClient) loadSSHAgent() ssh.AuthMethod {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		return nil
	}

	conn, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		return nil
	}

	agentClient := agent.NewClient(conn)
	return ssh.PublicKeysCallback(agentClient.Signers)
}

// createHostKeyCallback creates the host key callback for SSH connections.
// It uses skeema/knownhosts for proper host key verification.
func (c *SFTPClient) createHostKeyCallback() (ssh.HostKeyCallback, error) {
	if c.config.IgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
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
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh(hostname, remote, key)
		if err != nil {
			keyLine := knownhosts.Line([]string{hostname}, key)
			fingerprint := ssh.FingerprintSHA256(key)

			// Check if this is a key not found error
			if knownhosts.IsHostKeyChanged(err) {
				return &HostKeyError{
					Host:           hostname,
					KeyType:        key.Type(),
					KeyFingerprint: fingerprint,
					KnownHostsLine: keyLine,
					Err:            fmt.Errorf("host key has changed for %s. This could indicate a man-in-the-middle attack.\n"+
						"Server presented key:\n"+
						"  Type: %s\n"+
						"  Fingerprint: %s\n"+
						"  Key line: %s\n"+
						"If you trust this new key, remove the old entry from %s and add the above line.",
						hostname, key.Type(), fingerprint, keyLine, knownHostsPath),
				}
			}
			if knownhosts.IsHostUnknown(err) {
				return &HostKeyError{
					Host:           hostname,
					KeyType:        key.Type(),
					KeyFingerprint: fingerprint,
					KnownHostsLine: keyLine,
					Err:            fmt.Errorf("host key not found for %s.\n"+
						"Server presented key:\n"+
						"  Type: %s\n"+
						"  Fingerprint: %s\n"+
						"  Key line: %s\n"+
						"To accept this host, append the above key line to %s",
						hostname, key.Type(), fingerprint, keyLine, knownHostsPath),
				}
			}
			return err
		}
		return nil
	}, nil
}

// expandPath expands ~ to the home directory in a path.
func expandPath(path string) string {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
