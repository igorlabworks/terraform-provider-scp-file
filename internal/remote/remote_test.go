package remote

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testED25519Key is a throwaway ed25519 private key in OpenSSH format, used only in tests.
const testED25519Key = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDuwIAWxbLVNx9Vu3MhstytlISPBAxdb83tJ0TOMVCf/QAAAKB5s06MebNO
jAAAAAtzc2gtZWQyNTUxOQAAACDuwIAWxbLVNx9Vu3MhstytlISPBAxdb83tJ0TOMVCf/Q
AAAEAVyOukUl4rwa/YynNf2uxI94OvgmQzNe8NdKgWxo0Gc+7AgBbFstU3H1W7cyGy3K2U
hI8EDF1vze0nRM4xUJ/9AAAAHGlnb3JASWdvcnMtTWFjQm9vay1Qcm8ubG9jYWwB
-----END OPENSSH PRIVATE KEY-----
`

// testED25519Key2 is a second throwaway ed25519 private key, used to test host key changes.
const testED25519Key2 = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC+QDZOmYDcALECdbeE+t/V3INo2Cvfp1LNhSKO4vatzAAAAJg8WH1CPFh9
QgAAAAtzc2gtZWQyNTUxOQAAACC+QDZOmYDcALECdbeE+t/V3INo2Cvfp1LNhSKO4vatzA
AAAEC5rcMnRdXG6GApIaXhxU7UBTufc6B5+nu7hbH3c7CZkL5ANk6ZgNwAsQJ1t4T639Xc
g2jYK9+nUs2FIo7i9q3MAAAAEXRlc3QyQGV4YW1wbGUuY29tAQIDBA==
-----END OPENSSH PRIVATE KEY-----
`

func TestParseSSHConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")

	configContent := `
# Test SSH config
Host example
    Hostname example.com
    User testuser
    Port 2222
    IdentityFile ~/.ssh/example_key

Host *.example.org
    User wildcard_user
    Port 22

Host *
    User default_user
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := ParseSSHConfig(configPath)
	if err != nil {
		t.Fatalf("ParseSSHConfig failed: %v", err)
	}

	// Test exact match
	entry := config.GetEntry("example")
	if entry == nil {
		t.Fatal("Expected entry for 'example' but got nil")
	}
	if entry.Hostname != "example.com" {
		t.Errorf("Expected Hostname 'example.com', got '%s'", entry.Hostname)
	}
	if entry.User != "testuser" {
		t.Errorf("Expected User 'testuser', got '%s'", entry.User)
	}
	if entry.Port != "2222" {
		t.Errorf("Expected Port '2222', got '%s'", entry.Port)
	}

	// Test wildcard match
	entry = config.GetEntry("test.example.org")
	if entry == nil {
		t.Fatal("Expected entry for 'test.example.org' but got nil")
	}
	if entry.User != "wildcard_user" {
		t.Errorf("Expected User 'wildcard_user', got '%s'", entry.User)
	}

	// Test global wildcard match
	entry = config.GetEntry("unknown.host")
	if entry == nil {
		t.Fatal("Expected entry for 'unknown.host' but got nil")
	}
	if entry.User != "default_user" {
		t.Errorf("Expected User 'default_user', got '%s'", entry.User)
	}
}

func TestParseSSHConfigMissing(t *testing.T) {
	config, err := ParseSSHConfig("/nonexistent/path/to/config")
	if err != nil {
		t.Fatalf("ParseSSHConfig should return empty config for missing file, got error: %v", err)
	}
	if config == nil {
		t.Fatal("Expected non-nil config")
	}

	entry := config.GetEntry("anyhost")
	if entry != nil {
		t.Error("Expected nil entry for empty config")
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		match   bool
	}{
		{"*", "anything", true},
		{"*.example.com", "test.example.com", true},
		{"*.example.com", "example.com", false},
		{"test*", "testhost", true},
		{"test*", "host", false},
		{"192.168.1.*", "192.168.1.100", true},
		{"192.168.1.*", "192.168.2.100", false},
		{"host?.example.com", "host1.example.com", true},
		{"host?.example.com", "host12.example.com", false},
	}

	for _, tt := range tests {
		result := matchPattern(tt.pattern, tt.host)
		if result != tt.match {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.host, result, tt.match)
		}
	}
}

func TestApplyToConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")

	configContent := `
Host myserver
    Hostname actual.server.com
    User sshuser
    Port 2222
    IdentityFile ~/.ssh/mykey
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	sshConfig, err := ParseSSHConfig(configPath)
	if err != nil {
		t.Fatalf("ParseSSHConfig failed: %v", err)
	}

	config := &Config{
		Host: "myserver",
		Port: 0,
		User: "",
	}

	sshConfig.ApplyToConfig("myserver", config)

	if config.Host != "actual.server.com" {
		t.Errorf("Expected Host 'actual.server.com', got '%s'", config.Host)
	}

	if config.User != "sshuser" {
		t.Errorf("Expected User 'sshuser', got '%s'", config.User)
	}

	if config.Port != 2222 {
		t.Errorf("Expected Port 2222, got %d", config.Port)
	}

	config2 := &Config{
		Host: "myserver",
		Port: 22,       // Explicit port
		User: "myuser", // Explicit user
	}

	sshConfig.ApplyToConfig("myserver", config2)

	if config2.User != "myuser" {
		t.Errorf("Expected User 'myuser' (explicit), got '%s'", config2.User)
	}

	if config2.Port != 22 {
		t.Errorf("Expected Port 22 (explicit), got %d", config2.Port)
	}
}

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("Cannot get home directory")
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"~/test", filepath.Join(home, "test")},
		{"~/.ssh/id_rsa", filepath.Join(home, ".ssh", "id_rsa")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}

	for _, tt := range tests {
		result := expandPath(tt.input)
		if result != tt.expected {
			t.Errorf("expandPath(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestNewClient(t *testing.T) {
	// Test SFTP client creation
	config := &Config{
		Host:          "localhost",
		Port:          22,
		User:          "testuser",
		IgnoreHostKey: true,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	_, ok := client.(*SFTPClient)
	if !ok {
		t.Error("Expected *SFTPClient for default implementation")
	}

	client, err = NewClient(config)
	if err != nil {
		t.Fatalf("NewClient (sftp) failed: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	_, ok = client.(*SFTPClient)
	if !ok {
		t.Error("Expected *SFTPClient for 'sftp' implementation")
	}
}

func TestHostKeyError(t *testing.T) {
	err := &HostKeyError{
		Host:           "example.com",
		KeyType:        "ssh-ed25519",
		KeyFingerprint: "SHA256:...",
		KnownHostsLine: "example.com ssh-ed25519 AAAA...",
		Err:            os.ErrNotExist,
	}

	if err.Error() != os.ErrNotExist.Error() {
		t.Errorf("Expected error message '%s', got '%s'", os.ErrNotExist.Error(), err.Error())
	}

	if err.Unwrap() != os.ErrNotExist {
		t.Error("Unwrap should return the wrapped error")
	}
}

func TestParseSSHConfigWithGlobalDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")

	configContent := `AddKeysToAgent yes
UseKeychain yes
IdentityFile ~/.ssh/id_ed25519

Host hephaestus
  HostName 192.168.1.100
  User igor
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	sshConfig, err := ParseSSHConfig(configPath)
	if err != nil {
		t.Fatalf("ParseSSHConfig failed: %v", err)
	}

	if sshConfig.globalDefaults == nil {
		t.Fatal("Expected globalDefaults to be set")
	}

	home, _ := os.UserHomeDir()
	expectedKeyPath := filepath.Join(home, ".ssh", "id_ed25519")
	if sshConfig.globalDefaults.IdentityFile != expectedKeyPath {
		t.Errorf("Expected global IdentityFile '%s', got '%s'", expectedKeyPath, sshConfig.globalDefaults.IdentityFile)
	}

	entry := sshConfig.GetEntry("hephaestus")
	if entry == nil {
		t.Fatal("Expected entry for 'hephaestus' but got nil")
	}
	if entry.Hostname != "192.168.1.100" {
		t.Errorf("Expected Hostname '192.168.1.100', got '%s'", entry.Hostname)
	}
	if entry.User != "igor" {
		t.Errorf("Expected User 'igor', got '%s'", entry.User)
	}

	config := &Config{
		Host: "hephaestus",
	}

	sshConfig.ApplyToConfig("hephaestus", config)

	if config.Host != "192.168.1.100" {
		t.Errorf("Expected Host '192.168.1.100', got '%s'", config.Host)
	}

	if config.User != "igor" {
		t.Errorf("Expected User 'igor', got '%s'", config.User)
	}

	if config.KeyPath != expectedKeyPath {
		t.Errorf("Expected KeyPath '%s', got '%s'", expectedKeyPath, config.KeyPath)
	}
}

func TestApplyToConfigGlobalDefaultsAndHostOverride(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")

	configContent := `User globaluser
IdentityFile ~/.ssh/global_key

Host myserver
    Hostname actual.server.com
    User specificuser
    IdentityFile ~/.ssh/specific_key
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	sshConfig, err := ParseSSHConfig(configPath)
	if err != nil {
		t.Fatalf("ParseSSHConfig failed: %v", err)
	}

	config := &Config{
		Host: "myserver",
	}
	sshConfig.ApplyToConfig("myserver", config)

	home, _ := os.UserHomeDir()
	expectedKeyPath := filepath.Join(home, ".ssh", "specific_key")

	if config.User != "specificuser" {
		t.Errorf("Expected User 'specificuser' (host-specific), got '%s'", config.User)
	}
	if config.KeyPath != expectedKeyPath {
		t.Errorf("Expected KeyPath '%s' (host-specific), got '%s'", expectedKeyPath, config.KeyPath)
	}

	config2 := &Config{
		Host: "unknownhost",
	}
	sshConfig.ApplyToConfig("unknownhost", config2)

	expectedGlobalKeyPath := filepath.Join(home, ".ssh", "global_key")
	if config2.User != "globaluser" {
		t.Errorf("Expected User 'globaluser' (global default), got '%s'", config2.User)
	}
	if config2.KeyPath != expectedGlobalKeyPath {
		t.Errorf("Expected KeyPath '%s' (global default), got '%s'", expectedGlobalKeyPath, config2.KeyPath)
	}
}

func TestLoadSSHAgent(t *testing.T) {
	// Start a unix socket listener to simulate an SSH agent socket
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "agent.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create unix listener: %v", err)
	}
	defer listener.Close()

	t.Setenv("SSH_AUTH_SOCK", sockPath)

	client := &SFTPClient{config: &Config{}}
	auth := client.loadSSHAgent()

	if auth == nil {
		t.Fatal("Expected non-nil AuthMethod when SSH_AUTH_SOCK points to a valid socket")
	}
	if client.agentConn == nil {
		t.Fatal("Expected agentConn to be set after successful agent connection")
	}
	client.agentConn.Close()
}

func TestLoadSSHAgentMissing(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	client := &SFTPClient{config: &Config{}}
	auth := client.loadSSHAgent()

	if auth != nil {
		t.Error("Expected nil AuthMethod when SSH_AUTH_SOCK is unset")
	}
	if client.agentConn != nil {
		t.Error("Expected agentConn to remain nil when SSH_AUTH_SOCK is unset")
	}
}

func TestLoadSSHAgentUnreachable(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/path/agent.sock")

	client := &SFTPClient{config: &Config{}}
	auth := client.loadSSHAgent()

	if auth != nil {
		t.Error("Expected nil AuthMethod when SSH_AUTH_SOCK points to unreachable socket")
	}
	if client.agentConn != nil {
		t.Error("Expected agentConn to remain nil when dial fails")
	}
}

func TestLoadDefaultKeys(t *testing.T) {
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("Failed to create .ssh dir: %v", err)
	}

	// Write a valid ed25519 key as id_ed25519
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte(testED25519Key), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	t.Setenv("HOME", tmpHome)

	client := &SFTPClient{config: &Config{}}
	methods := client.loadDefaultKeys()

	if len(methods) == 0 {
		t.Fatal("Expected at least one AuthMethod from default keys when id_ed25519 exists")
	}
}

func TestLoadDefaultKeysEmpty(t *testing.T) {
	tmpHome := t.TempDir()
	// .ssh exists but contains no recognized key files
	if err := os.MkdirAll(filepath.Join(tmpHome, ".ssh"), 0700); err != nil {
		t.Fatalf("Failed to create .ssh dir: %v", err)
	}

	t.Setenv("HOME", tmpHome)

	client := &SFTPClient{config: &Config{}}
	methods := client.loadDefaultKeys()

	if len(methods) != 0 {
		t.Errorf("Expected zero AuthMethods when no default keys exist, got %d", len(methods))
	}
}

func TestKeyPathAuth(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "mykey")
	if err := os.WriteFile(keyPath, []byte(testED25519Key), 0600); err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	// Verify the key parses correctly (this is what Connect uses internally)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	_, err = ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatalf("Test key failed to parse: %v", err)
	}

	// Connect will fail at ssh.Dial, but we verify it gets past auth assembly
	// by checking the error is a connection error, not an auth-assembly error
	client := &SFTPClient{config: &Config{
		Host:          "localhost",
		Port:          1, // Deliberately invalid port to fail fast at dial
		User:          "testuser",
		KeyPath:       keyPath,
		IgnoreHostKey: true,

		ConnectionRetries:        1,
		ConnectionRetryBaseDelay: 1,
	}}

	err = client.Connect()
	if err == nil {
		t.Fatal("Expected connection error on invalid port")
	}
	// Should fail at dial, not at "no SSH authentication methods available"
	if err.Error() == "no SSH authentication methods available" {
		t.Error("KeyPath auth was not assembled; got 'no auth methods' error")
	}
}

func TestKeyPathAuthMissing(t *testing.T) {
	// KeyPath points to nonexistent file; Connect should fall through to other methods
	// With no other methods available, we expect "no SSH authentication methods available"
	tmpHome := t.TempDir()
	// Empty .ssh so loadDefaultKeys returns nothing
	if err := os.MkdirAll(filepath.Join(tmpHome, ".ssh"), 0700); err != nil {
		t.Fatalf("Failed to create .ssh dir: %v", err)
	}
	t.Setenv("HOME", tmpHome)
	t.Setenv("SSH_AUTH_SOCK", "")

	client := &SFTPClient{config: &Config{
		Host:    "localhost",
		User:    "testuser",
		KeyPath: "/nonexistent/path/to/key",
	}}

	err := client.Connect()
	if err == nil {
		t.Fatal("Expected error when no auth methods are available")
	}
	if err.Error() != "no SSH authentication methods available" {
		t.Errorf("Expected 'no SSH authentication methods available', got: %v", err)
	}
}

func TestAuthMethodPrecedence(t *testing.T) {
	// Verify: password is always added; agent added when socket exists;
	// keypath added when file is valid; default keys only loaded when nothing else is available.
	tmpDir := t.TempDir()
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("Failed to create .ssh dir: %v", err)
	}

	// Place a default key so loadDefaultKeys would find it
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte(testED25519Key), 0600); err != nil {
		t.Fatalf("Failed to write default key: %v", err)
	}

	// Place an explicit key at keyPath
	keyPath := filepath.Join(tmpDir, "explicit_key")
	if err := os.WriteFile(keyPath, []byte(testED25519Key), 0600); err != nil {
		t.Fatalf("Failed to write explicit key: %v", err)
	}

	// Set up a fake agent socket
	sockPath := filepath.Join(tmpDir, "agent.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create unix listener: %v", err)
	}
	defer listener.Close()

	t.Setenv("HOME", tmpHome)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	// With password + agent + keypath all available, Connect should attempt the connection
	// (fail at dial, but NOT fail at auth assembly). Default keys should NOT be consulted
	// because other methods are present.
	client := &SFTPClient{config: &Config{
		Host:          "localhost",
		Port:          1,
		User:          "testuser",
		Password:      "secret",
		KeyPath:       keyPath,
		IgnoreHostKey: true,

		ConnectionRetries:        1,
		ConnectionRetryBaseDelay: 1,
	}}

	err = client.Connect()
	if err == nil {
		t.Fatal("Expected connection error on invalid port")
	}
	if err.Error() == "no SSH authentication methods available" {
		t.Error("Auth assembly failed despite password, agent, and keypath being available")
	}

	// Now verify default keys ARE used when nothing else is available
	t.Setenv("SSH_AUTH_SOCK", "")
	client2 := &SFTPClient{config: &Config{
		Host:          "localhost",
		Port:          1,
		User:          "testuser",
		IgnoreHostKey: true,

		ConnectionRetries:        1,
		ConnectionRetryBaseDelay: 1,
	}}

	err = client2.Connect()
	if err == nil {
		t.Fatal("Expected connection error on invalid port")
	}
	if err.Error() == "no SSH authentication methods available" {
		t.Error("Default keys should have been loaded as fallback, but no auth methods were found")
	}
}

func TestHostKeyCallbackWithIgnoreHostKey(t *testing.T) {
	client := &SFTPClient{
		config: &Config{
			IgnoreHostKey: true,
		},
	}

	callback, err := client.createHostKeyCallback()
	if err != nil {
		t.Fatalf("createHostKeyCallback failed: %v", err)
	}

	// Parse a test key
	signer, err := ssh.ParsePrivateKey([]byte(testED25519Key))
	if err != nil {
		t.Fatalf("Failed to parse test key: %v", err)
	}

	// The callback should accept any host/key combination without error
	err = callback("example.com:22", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}, signer.PublicKey())
	if err != nil {
		t.Errorf("Expected no error with IgnoreHostKey=true, got: %v", err)
	}

	// Try another host/key combination
	signer2, err := ssh.ParsePrivateKey([]byte(testED25519Key2))
	if err != nil {
		t.Fatalf("Failed to parse second test key: %v", err)
	}

	err = callback("different.com:2222", &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 2222}, signer2.PublicKey())
	if err != nil {
		t.Errorf("Expected no error with IgnoreHostKey=true, got: %v", err)
	}
}

func TestCreateSSHDirectoryIfMissing(t *testing.T) {
	tmpHome := t.TempDir()
	knownHostsPath := filepath.Join(tmpHome, ".ssh", "known_hosts")

	client := &SFTPClient{
		config: &Config{
			KnownHostsPath: knownHostsPath,
			IgnoreHostKey:  false,
		},
	}

	// .ssh directory shouldn't exist yet
	sshDir := filepath.Join(tmpHome, ".ssh")
	if _, err := os.Stat(sshDir); !os.IsNotExist(err) {
		t.Fatal(".ssh directory should not exist yet")
	}

	_, err := client.createHostKeyCallback()
	if err != nil {
		t.Fatalf("createHostKeyCallback failed: %v", err)
	}

	// Verify .ssh directory was created with correct permissions
	info, err := os.Stat(sshDir)
	if err != nil {
		t.Fatalf("Failed to stat .ssh directory: %v", err)
	}
	if !info.IsDir() {
		t.Error(".ssh should be a directory")
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("Expected .ssh permissions 0700, got %04o", info.Mode().Perm())
	}

	// Verify known_hosts file was created with correct permissions
	info, err = os.Stat(knownHostsPath)
	if err != nil {
		t.Fatalf("Failed to stat known_hosts file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Expected known_hosts permissions 0600, got %04o", info.Mode().Perm())
	}
}

func TestHostKeyNotFoundError(t *testing.T) {
	tmpDir := t.TempDir()
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")

	// Create empty known_hosts file
	if err := os.WriteFile(knownHostsPath, []byte{}, 0600); err != nil {
		t.Fatalf("Failed to create empty known_hosts: %v", err)
	}

	client := &SFTPClient{
		config: &Config{
			KnownHostsPath: knownHostsPath,
			IgnoreHostKey:  false,
		},
	}

	callback, err := client.createHostKeyCallback()
	if err != nil {
		t.Fatalf("createHostKeyCallback failed: %v", err)
	}

	// Parse a test key
	signer, err := ssh.ParsePrivateKey([]byte(testED25519Key))
	if err != nil {
		t.Fatalf("Failed to parse test key: %v", err)
	}

	// Call the callback with a host not in known_hosts
	hostname := "unknown.example.com:22"
	err = callback(hostname, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}, signer.PublicKey())

	// Should return a HostKeyError
	if err == nil {
		t.Fatal("Expected error for unknown host key, got nil")
	}

	hostKeyErr, ok := err.(*HostKeyError)
	if !ok {
		t.Fatalf("Expected *HostKeyError, got %T", err)
	}

	// Verify error contents
	if hostKeyErr.Host != hostname {
		t.Errorf("Expected Host '%s', got '%s'", hostname, hostKeyErr.Host)
	}
	if hostKeyErr.KeyType != "ssh-ed25519" {
		t.Errorf("Expected KeyType 'ssh-ed25519', got '%s'", hostKeyErr.KeyType)
	}
	if hostKeyErr.KeyFingerprint == "" {
		t.Error("KeyFingerprint should not be empty")
	}
	if hostKeyErr.KnownHostsLine == "" {
		t.Error("KnownHostsLine should not be empty")
	}

	// Check error message content
	errMsg := hostKeyErr.Error()
	if !strings.Contains(errMsg, "host key not found") {
		t.Errorf("Error message should contain 'host key not found', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, hostKeyErr.KeyType) {
		t.Errorf("Error message should contain key type, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, hostKeyErr.KeyFingerprint) {
		t.Errorf("Error message should contain key fingerprint, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, knownHostsPath) {
		t.Errorf("Error message should contain known_hosts path, got: %s", errMsg)
	}
}

func TestHostKeyChangedError(t *testing.T) {
	tmpDir := t.TempDir()
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")

	// Parse first test key
	signer1, err := ssh.ParsePrivateKey([]byte(testED25519Key))
	if err != nil {
		t.Fatalf("Failed to parse first test key: %v", err)
	}

	// Create known_hosts with the first key
	hostname := "example.com"
	knownHostsLine := ssh.MarshalAuthorizedKey(signer1.PublicKey())
	knownHostsContent := fmt.Sprintf("%s %s", hostname, string(knownHostsLine))
	if err := os.WriteFile(knownHostsPath, []byte(knownHostsContent), 0600); err != nil {
		t.Fatalf("Failed to write known_hosts: %v", err)
	}

	client := &SFTPClient{
		config: &Config{
			KnownHostsPath: knownHostsPath,
			IgnoreHostKey:  false,
		},
	}

	callback, err := client.createHostKeyCallback()
	if err != nil {
		t.Fatalf("createHostKeyCallback failed: %v", err)
	}

	// Parse second test key (different from the one in known_hosts)
	signer2, err := ssh.ParsePrivateKey([]byte(testED25519Key2))
	if err != nil {
		t.Fatalf("Failed to parse second test key: %v", err)
	}

	// Call the callback with the same host but different key
	err = callback(hostname+":22", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}, signer2.PublicKey())

	// Should return a HostKeyError
	if err == nil {
		t.Fatal("Expected error for changed host key, got nil")
	}

	hostKeyErr, ok := err.(*HostKeyError)
	if !ok {
		t.Fatalf("Expected *HostKeyError, got %T", err)
	}

	// Verify error contents
	if !strings.Contains(hostKeyErr.Host, hostname) {
		t.Errorf("Expected Host to contain '%s', got '%s'", hostname, hostKeyErr.Host)
	}
	if hostKeyErr.KeyType != "ssh-ed25519" {
		t.Errorf("Expected KeyType 'ssh-ed25519', got '%s'", hostKeyErr.KeyType)
	}
	if hostKeyErr.KeyFingerprint == "" {
		t.Error("KeyFingerprint should not be empty")
	}
	if hostKeyErr.KnownHostsLine == "" {
		t.Error("KnownHostsLine should not be empty")
	}

	// Check error message content
	errMsg := hostKeyErr.Error()
	if !strings.Contains(errMsg, "host key has changed") {
		t.Errorf("Error message should contain 'host key has changed', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "man-in-the-middle") {
		t.Errorf("Error message should contain 'man-in-the-middle', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, hostKeyErr.KeyType) {
		t.Errorf("Error message should contain key type, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, hostKeyErr.KeyFingerprint) {
		t.Errorf("Error message should contain key fingerprint, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, knownHostsPath) {
		t.Errorf("Error message should contain known_hosts path, got: %s", errMsg)
	}
}

func TestPasswordAuthentication(t *testing.T) {
	tmpHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpHome, ".ssh"), 0700); err != nil {
		t.Fatalf("Failed to create .ssh dir: %v", err)
	}
	t.Setenv("HOME", tmpHome)
	t.Setenv("SSH_AUTH_SOCK", "")

	client := &SFTPClient{config: &Config{
		Host:          "127.0.0.1",
		Port:          1, // Closed port — will fail at dial, not at auth assembly
		User:          "testuser",
		Password:      "testpass",
		IgnoreHostKey: true,

		ConnectionRetries:        1,
		ConnectionRetryBaseDelay: 1,
	}}

	err := client.Connect()
	if err == nil {
		t.Fatal("Expected connection error on closed port")
	}
	if strings.Contains(err.Error(), "no SSH authentication methods") {
		t.Error("password authentication should have been configured")
	}
}

// TestDefaultSSHTimeoutValue verifies the SSH timeout constant is set correctly.
func TestDefaultSSHTimeoutValue(t *testing.T) {
	// Verify the constant is set correctly
	if defaultSSHTimeout != 30*time.Second {
		t.Errorf("Expected defaultSSHTimeout to be 30s, got %v", defaultSSHTimeout)
	}
}

// TestConnectionRetryCount verifies the correct number of connection attempts are made.
func TestConnectionRetryCount(t *testing.T) {
	tests := []struct {
		retries         int
		expectedInError string
	}{
		{1, "after 1 attempts"},
		{2, "after 2 attempts"},
		{3, "after 3 attempts"},
		{5, "after 5 attempts"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_retries", tt.retries), func(t *testing.T) {
			client := &SFTPClient{config: &Config{
				Host:                     "localhost",
				Port:                     1, // Closed port
				User:                     "testuser",
				Password:                 "testpass",
				IgnoreHostKey:            true,
				ConnectionRetries:        tt.retries,
				ConnectionRetryBaseDelay: 1, // Minimal delay
			}}

			err := client.Connect()
			if err == nil {
				t.Fatal("Expected connection error")
			}

			if !strings.Contains(err.Error(), tt.expectedInError) {
				t.Errorf("Expected error to contain %q, got: %v", tt.expectedInError, err)
			}
		})
	}
}

// TestConnectionFailureErrorMessage verifies connection failure error messages are informative.
func TestConnectionFailureErrorMessage(t *testing.T) {
	tests := []struct {
		name             string
		host             string
		port             int
		expectedContains []string
	}{
		{
			name: "connection_refused",
			host: "localhost",
			port: 1, // Closed port
			expectedContains: []string{
				"failed to connect to SSH server",
				"localhost:1",
				"after",
				"attempts",
			},
		},
		{
			name: "invalid_host",
			host: "this.host.does.not.exist.invalid",
			port: 22,
			expectedContains: []string{
				"failed to connect to SSH server",
				"this.host.does.not.exist.invalid:22",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &SFTPClient{config: &Config{
				Host:                     tt.host,
				Port:                     tt.port,
				User:                     "testuser",
				Password:                 "testpass",
				IgnoreHostKey:            true,
				ConnectionRetries:        1,
				ConnectionRetryBaseDelay: 1,
			}}

			err := client.Connect()
			if err == nil {
				t.Fatal("Expected connection error")
			}

			errMsg := err.Error()
			for _, expected := range tt.expectedContains {
				if !strings.Contains(errMsg, expected) {
					t.Errorf("Expected error to contain %q, got: %s", expected, errMsg)
				}
			}
		})
	}
}

// TestConnectionRetryWithBackoff verifies retry logic executes with exponential delays.
func TestConnectionRetryWithBackoff(t *testing.T) {
	tests := []struct {
		name          string
		retries       int
		baseDelayMs   int
		minExpectedMs int64 // Minimum time based on backoff formula
		maxExpectedMs int64 // Maximum reasonable time
	}{
		{
			name:          "single retry no delay",
			retries:       1,
			baseDelayMs:   100,
			minExpectedMs: 0,   // No retries = no delay
			maxExpectedMs: 500, // Just dial time
		},
		{
			name:        "two retries",
			retries:     2,
			baseDelayMs: 100,
			// First attempt fails, delay = 100ms * 2^0 = 100ms, second attempt fails
			minExpectedMs: 80, // ~100ms with tolerance
			maxExpectedMs: 500,
		},
		{
			name:        "three retries",
			retries:     3,
			baseDelayMs: 50,
			// delay1 = 50ms, delay2 = 100ms, total = 150ms
			minExpectedMs: 120,
			maxExpectedMs: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &SFTPClient{config: &Config{
				Host:                     "localhost",
				Port:                     1, // Invalid/closed port
				User:                     "testuser",
				Password:                 "testpass",
				IgnoreHostKey:            true,
				ConnectionRetries:        tt.retries,
				ConnectionRetryBaseDelay: tt.baseDelayMs,
			}}

			start := time.Now()
			err := client.Connect()
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("Expected connection error")
			}

			elapsedMs := elapsed.Milliseconds()
			if elapsedMs < tt.minExpectedMs {
				t.Errorf("Connection failed too fast (%dms), expected >= %dms; backoff may not be working",
					elapsedMs, tt.minExpectedMs)
			}
			if elapsedMs > tt.maxExpectedMs {
				t.Errorf("Connection took too long (%dms), expected <= %dms",
					elapsedMs, tt.maxExpectedMs)
			}
		})
	}
}

// TestDefaultRetryValues verifies default values are applied when config values are 0.
func TestDefaultRetryValues(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping default retry test in short mode")
	}

	// With defaults: 3 retries, 500ms base delay
	// Delays: 500ms, 1000ms = 1500ms total
	client := &SFTPClient{config: &Config{
		Host:          "localhost",
		Port:          1,
		User:          "testuser",
		Password:      "testpass",
		IgnoreHostKey: true,
		// ConnectionRetries: 0,        // Use default (3)
		// ConnectionRetryBaseDelay: 0, // Use default (500ms)
	}}

	start := time.Now()
	err := client.Connect()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected connection error")
	}

	// With 3 retries and 500ms base:
	// attempt 0 fails, sleep 500ms
	// attempt 1 fails, sleep 1000ms
	// attempt 2 fails, done
	// Total delay: ~1500ms

	if elapsed < 1400*time.Millisecond {
		t.Errorf("Default retry backoff seems too fast (%v); expected ~1500ms+", elapsed)
	}

	// Verify error message says 3 attempts
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Errorf("Expected default of 3 attempts, error: %v", err)
	}
}
