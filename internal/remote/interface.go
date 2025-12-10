package remote

import (
	"os"
)

type Client interface {
	Connect() error
	Close() error
	WriteFile(remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error
	ReadFile(remotePath string) ([]byte, error)
	FileExists(remotePath string) (bool, error)
	DeleteFile(remotePath string) error
}

type Config struct {
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
