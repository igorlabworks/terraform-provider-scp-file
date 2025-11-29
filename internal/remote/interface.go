// Package remote provides interfaces and implementations for remote file operations.
package remote

import (
	"os"
)

// Client defines the interface for remote file operations.
// Implementations can use different libraries (e.g., sftp, rig) to connect to remote hosts.
type Client interface {
	// Connect establishes a connection to the remote host.
	Connect() error

	// Close closes the connection to the remote host.
	Close() error

	// WriteFile writes content to a remote file with the specified permissions.
	// It creates parent directories if they don't exist.
	WriteFile(remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error

	// ReadFile reads and returns the content of a remote file.
	ReadFile(remotePath string) ([]byte, error)

	// FileExists checks if a remote file exists.
	FileExists(remotePath string) (bool, error)

	// DeleteFile deletes a remote file.
	DeleteFile(remotePath string) error
}

// Config holds the configuration for connecting to a remote host.
type Config struct {
	Host              string
	Port              int
	User              string
	Password          string
	KeyPath           string
	KnownHostsPath    string
	IgnoreHostKey     bool
	SSHConfigPath     string
	Implementation    string // "sftp" or "rig"
}

// HostKeyError is returned when the host key verification fails.
type HostKeyError struct {
	Host           string
	KeyType        string
	KeyFingerprint string
	KnownHostsLine string
	Err            error
}

func (e *HostKeyError) Error() string {
	return e.Err.Error()
}

func (e *HostKeyError) Unwrap() error {
	return e.Err
}

// NewClient creates a new remote client based on the configuration.
// It returns the appropriate implementation based on Config.Implementation.
func NewClient(config *Config) (Client, error) {
	switch config.Implementation {
	case "rig":
		return NewRigClient(config)
	case "sftp", "":
		return NewSFTPClient(config)
	default:
		return NewSFTPClient(config)
	}
}
