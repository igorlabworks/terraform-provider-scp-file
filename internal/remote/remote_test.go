package remote

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSSHConfig(t *testing.T) {
	// Create a temporary SSH config file
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
	// Test with non-existent config file
	config, err := ParseSSHConfig("/nonexistent/path/to/config")
	if err != nil {
		t.Fatalf("ParseSSHConfig should return empty config for missing file, got error: %v", err)
	}
	if config == nil {
		t.Fatal("Expected non-nil config")
	}

	// Should return nil for any host
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
	// Create a temporary SSH config file
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

	// Test that SSH config settings are applied to remote.Config
	config := &Config{
		Host: "myserver",
		Port: 0,
		User: "",
	}

	sshConfig.ApplyToConfig("myserver", config)

	// Host should be updated to Hostname
	if config.Host != "actual.server.com" {
		t.Errorf("Expected Host 'actual.server.com', got '%s'", config.Host)
	}

	// User should be set from SSH config
	if config.User != "sshuser" {
		t.Errorf("Expected User 'sshuser', got '%s'", config.User)
	}

	// Port should be set from SSH config
	if config.Port != 2222 {
		t.Errorf("Expected Port 2222, got %d", config.Port)
	}

	// Test that explicit settings take precedence
	config2 := &Config{
		Host: "myserver",
		Port: 22,       // Explicit port
		User: "myuser", // Explicit user
	}

	sshConfig.ApplyToConfig("myserver", config2)

	// User should NOT be overridden (explicit takes precedence)
	if config2.User != "myuser" {
		t.Errorf("Expected User 'myuser' (explicit), got '%s'", config2.User)
	}

	// Port should NOT be overridden (explicit takes precedence)
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

	// Check it's an SFTP client
	_, ok := client.(*SFTPClient)
	if !ok {
		t.Error("Expected *SFTPClient for default implementation")
	}

	// Test rig client creation
	config.Implementation = "rig"
	client, err = NewClient(config)
	if err != nil {
		t.Fatalf("NewClient (rig) failed: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Check it's a Rig client
	_, ok = client.(*RigClient)
	if !ok {
		t.Error("Expected *RigClient for 'rig' implementation")
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
	// Create a temporary SSH config file with global defaults
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")

	// This matches the user's actual SSH config structure
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

	// Verify global defaults are parsed
	if sshConfig.globalDefaults == nil {
		t.Fatal("Expected globalDefaults to be set")
	}

	home, _ := os.UserHomeDir()
	expectedKeyPath := filepath.Join(home, ".ssh", "id_ed25519")
	if sshConfig.globalDefaults.IdentityFile != expectedKeyPath {
		t.Errorf("Expected global IdentityFile '%s', got '%s'", expectedKeyPath, sshConfig.globalDefaults.IdentityFile)
	}

	// Test that host-specific entry is parsed
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

	// Test ApplyToConfig with global defaults
	config := &Config{
		Host: "hephaestus",
	}

	sshConfig.ApplyToConfig("hephaestus", config)

	// Host should be updated to Hostname
	if config.Host != "192.168.1.100" {
		t.Errorf("Expected Host '192.168.1.100', got '%s'", config.Host)
	}

	// User should be set from host-specific entry
	if config.User != "igor" {
		t.Errorf("Expected User 'igor', got '%s'", config.User)
	}

	// KeyPath should be set from global default
	if config.KeyPath != expectedKeyPath {
		t.Errorf("Expected KeyPath '%s', got '%s'", expectedKeyPath, config.KeyPath)
	}
}

func TestApplyToConfigGlobalDefaultsAndHostOverride(t *testing.T) {
	// Create a temporary SSH config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")

	// Config with global defaults and host-specific overrides
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

	// Test with host-specific settings (should override global)
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

	// Test with unknown host (should use global defaults)
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
