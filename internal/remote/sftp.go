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

const (
	defaultSSHPort    = 22
	defaultSSHTimeout = 30 * time.Second
	sshDirPerm        = 0700
	knownHostsPerm    = 0600
)

var defaultKeyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}

type SFTPClient struct {
	config     *Config
	sshClient  *ssh.Client
	sftpClient *sftp.Client
}

func NewSFTPClient(config *Config) (*SFTPClient, error) {
	sshConfig, err := ParseSSHConfig(config.SSHConfigPath)
	if err == nil {
		sshConfig.ApplyToConfig(config.Host, config)
	}

	return &SFTPClient{config: config}, nil
}

func (c *SFTPClient) Connect() error {
	var authMethods []ssh.AuthMethod

	if c.config.Password != "" {
		authMethods = append(authMethods, ssh.Password(c.config.Password))
	}

	if agentAuth := c.loadSSHAgent(); agentAuth != nil {
		authMethods = append(authMethods, agentAuth)
	}

	if c.config.KeyPath != "" {
		key, err := os.ReadFile(expandPath(c.config.KeyPath))
		if err == nil {
			signer, err := ssh.ParsePrivateKey(key)
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

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
		Timeout:         defaultSSHTimeout,
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
		port = defaultSSHPort
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(c.config.Host, strconv.Itoa(port)), sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server %s: %w", net.JoinHostPort(c.config.Host, strconv.Itoa(port)), err)
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

func (c *SFTPClient) Close() error {
	if c.sftpClient != nil {
		c.sftpClient.Close()
		c.sftpClient = nil
	}
	if c.sshClient != nil {
		err := c.sshClient.Close()
		c.sshClient = nil
		return err
	}
	return nil
}

func (c *SFTPClient) WriteFile(remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error {
	if err := c.sftpClient.MkdirAll(filepath.Dir(remotePath)); err != nil {
		return fmt.Errorf("failed to create remote directory %s: %w", filepath.Dir(remotePath), err)
	}

	f, err := c.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file %s: %w", remotePath, err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("failed to write to remote file %s: %w", remotePath, err)
	}

	if err := c.sftpClient.Chmod(remotePath, fileMode); err != nil {
		return fmt.Errorf("failed to set permissions on remote file %s: %w", remotePath, err)
	}

	return nil
}

func (c *SFTPClient) ReadFile(remotePath string) ([]byte, error) {
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

func (c *SFTPClient) FileExists(remotePath string) (bool, error) {
	_, err := c.sftpClient.Stat(remotePath)
	return err == nil, nil
}

func (c *SFTPClient) DeleteFile(remotePath string) error {
	return c.sftpClient.Remove(remotePath)
}

func (c *SFTPClient) loadDefaultKeys() []ssh.AuthMethod {
	var authMethods []ssh.AuthMethod

	home, err := os.UserHomeDir()
	if err != nil {
		return authMethods
	}

	for _, keyName := range defaultKeyNames {
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

func (c *SFTPClient) createHostKeyCallback() (ssh.HostKeyCallback, error) {
	if c.config.IgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}

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

	if err := os.MkdirAll(filepath.Dir(knownHostsPath), sshDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create .ssh directory: %w", err)
	}
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		if err := os.WriteFile(knownHostsPath, []byte{}, knownHostsPerm); err != nil {
			return nil, fmt.Errorf("failed to create known_hosts file: %w", err)
		}
	}

	kh, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh(hostname, remote, key)
		if err != nil {
			if knownhosts.IsHostKeyChanged(err) {
				return &HostKeyError{
					Host:           hostname,
					KeyType:        key.Type(),
					KeyFingerprint: ssh.FingerprintSHA256(key),
					KnownHostsLine: knownhosts.Line([]string{hostname}, key),
					Err: fmt.Errorf("host key has changed for %s. This could indicate a man-in-the-middle attack.\n"+
						"Server presented key:\n"+
						"  Type: %s\n"+
						"  Fingerprint: %s\n"+
						"  Key line: %s\n"+
						"If you trust this new key, remove the old entry from %s and add the above line.",
						hostname, key.Type(), ssh.FingerprintSHA256(key), knownhosts.Line([]string{hostname}, key), knownHostsPath),
				}
			}
			if knownhosts.IsHostUnknown(err) {
				return &HostKeyError{
					Host:           hostname,
					KeyType:        key.Type(),
					KeyFingerprint: ssh.FingerprintSHA256(key),
					KnownHostsLine: knownhosts.Line([]string{hostname}, key),
					Err: fmt.Errorf("host key not found for %s.\n"+
						"Server presented key:\n"+
						"  Type: %s\n"+
						"  Fingerprint: %s\n"+
						"  Key line: %s\n"+
						"To accept this host, append the above key line to %s",
						hostname, key.Type(), ssh.FingerprintSHA256(key), knownhosts.Line([]string{hostname}, key), knownHostsPath),
				}
			}
			return err
		}
		return nil
	}, nil
}

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
