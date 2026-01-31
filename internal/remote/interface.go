package remote

import (
	"os"
)

type FileInfo struct {
	Mode os.FileMode
	Size int64
}

type Client interface {
	Connect() error
	Close() error
	WriteFile(remotePath string, content []byte, fileMode os.FileMode, dirMode os.FileMode) error
	ReadFile(remotePath string) ([]byte, error)
	FileExists(remotePath string) (bool, error)
	DeleteFile(remotePath string) error
	GetFileInfo(remotePath string) (*FileInfo, error)
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

	// ConnectionRetries specifies the number of connection attempts.
	// If 0, defaults to 3 for production use.
	// Tests can set this higher (e.g., 6) for more resilience.
	ConnectionRetries int

	// ConnectionRetryBaseDelay is the base delay for exponential backoff.
	// If 0, defaults to 500ms for production use.
	// Tests can set this higher (e.g., 2s) for longer waits.
	ConnectionRetryBaseDelay int // milliseconds
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
	return NewSFTPClient(config)
}
