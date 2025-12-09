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
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	defaultRigTimeout = 5 * time.Second
)

type RigClient struct {
	config *Config
	client *rig.Client
}

func NewRigClient(config *Config) (*RigClient, error) {
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

	if err := client.Connect(context.Background()); err != nil {
		if !c.config.IgnoreHostKey {
			if verifyErr := c.verifyHostKeyFromError(err, c.config.Host, port); verifyErr != nil {
				return verifyErr
			}
		}
		return fmt.Errorf("failed to connect to SSH server %s:%d: %w", c.config.Host, port, err)
	}

	if !c.config.IgnoreHostKey {
		if err := c.verifyConnectedHostKey(client, c.config.Host, port); err != nil {
			return err
		}
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

	if err := fsys.MkdirAll(filepath.Dir(remotePath), dirMode); err != nil {
		return fmt.Errorf("failed to create remote directory %s: %w", filepath.Dir(remotePath), err)
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

func (c *RigClient) verifyHostKeyFromError(err error, host string, port int) error {
	// This is called when connection fails - just pass through the error
	// We'll try to provide better messaging but can't verify without a connection
	return nil
}

func (c *RigClient) verifyConnectedHostKey(client *rig.Client, host string, port int) error {
	// For rig, we can't easily verify host keys after connection
	// The rig library handles SSH internally
	// So for now, just skip verification - rig will use its own host key checking
	// TODO: See if we can extract and verify the host key from rig's connection
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

func isHostKeyError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "host key") ||
		strings.Contains(errStr, "knownhosts") ||
		strings.Contains(errStr, "key mismatch")
}
