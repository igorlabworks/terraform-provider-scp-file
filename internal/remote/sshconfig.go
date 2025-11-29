package remote

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SSHConfigEntry represents a parsed SSH config entry for a host.
type SSHConfigEntry struct {
	Host         string
	Hostname     string
	User         string
	Port         string
	IdentityFile string
}

// SSHConfig represents a parsed SSH config file.
type SSHConfig struct {
	entries map[string]*SSHConfigEntry
}

// ParseSSHConfig parses the SSH config file at the given path.
// If path is empty, it uses the default ~/.ssh/config.
func ParseSSHConfig(configPath string) (*SSHConfig, error) {
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		configPath = filepath.Join(home, ".ssh", "config")
	}

	// Expand ~ in path
	if strings.HasPrefix(configPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		configPath = filepath.Join(home, configPath[2:])
	}

	file, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty config if file doesn't exist
			return &SSHConfig{entries: make(map[string]*SSHConfigEntry)}, nil
		}
		return nil, err
	}
	defer file.Close()

	config := &SSHConfig{entries: make(map[string]*SSHConfigEntry)}
	var currentEntry *SSHConfigEntry
	var currentPatterns []string

	scanner := bufio.NewScanner(file)
	// Regular expression for parsing SSH config lines
	// Matches: keyword value or keyword=value
	lineRe := regexp.MustCompile(`^\s*(\w+)\s*[=\s]\s*(.+?)\s*$`)
	commentRe := regexp.MustCompile(`^\s*(#.*)?$`)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if commentRe.MatchString(line) {
			continue
		}

		matches := lineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		keyword := strings.ToLower(matches[1])
		value := matches[2]

		// Remove surrounding quotes if present
		value = strings.Trim(value, "\"'")

		switch keyword {
		case "host":
			// Save the current entry before starting a new one
			if currentEntry != nil {
				for _, pattern := range currentPatterns {
					config.entries[pattern] = currentEntry
				}
			}
			// Start a new entry
			currentPatterns = strings.Fields(value)
			currentEntry = &SSHConfigEntry{Host: value}

		case "hostname":
			if currentEntry != nil {
				currentEntry.Hostname = value
			}

		case "user":
			if currentEntry != nil {
				currentEntry.User = value
			}

		case "port":
			if currentEntry != nil {
				currentEntry.Port = value
			}

		case "identityfile":
			if currentEntry != nil {
				// Expand ~ in identity file path
				if strings.HasPrefix(value, "~/") {
					home, err := os.UserHomeDir()
					if err == nil {
						value = filepath.Join(home, value[2:])
					}
				}
				currentEntry.IdentityFile = value
			}
		}
	}

	// Save the last entry
	if currentEntry != nil {
		for _, pattern := range currentPatterns {
			config.entries[pattern] = currentEntry
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}

// GetEntry returns the SSH config entry for the given host.
// It supports wildcard matching following OpenSSH precedence (first match wins).
func (c *SSHConfig) GetEntry(host string) *SSHConfigEntry {
	// First, try exact match
	if entry, ok := c.entries[host]; ok {
		return entry
	}

	// Then try pattern matching (OpenSSH uses first match)
	for pattern, entry := range c.entries {
		if matchPattern(pattern, host) {
			return entry
		}
	}

	return nil
}

// matchPattern checks if the host matches the SSH config pattern.
// Supports * and ? wildcards as per OpenSSH spec.
func matchPattern(pattern, host string) bool {
	if pattern == "*" {
		return true
	}

	// Convert SSH pattern to regexp
	regexPattern := "^"
	for _, char := range pattern {
		switch char {
		case '*':
			regexPattern += ".*"
		case '?':
			regexPattern += "."
		case '.', '^', '$', '+', '|', '(', ')', '[', ']', '{', '}', '\\':
			regexPattern += "\\" + string(char)
		default:
			regexPattern += string(char)
		}
	}
	regexPattern += "$"

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}

	return re.MatchString(host)
}

// ApplyToConfig applies SSH config settings to a remote.Config.
// It follows OpenSSH precedence: explicit settings override config file settings.
func (c *SSHConfig) ApplyToConfig(host string, config *Config) {
	entry := c.GetEntry(host)
	if entry == nil {
		return
	}

	// Only apply if not already set (explicit settings take precedence)
	if config.Host == host && entry.Hostname != "" {
		config.Host = entry.Hostname
	}

	if config.User == "" && entry.User != "" {
		config.User = entry.User
	}

	if config.Port == 0 && entry.Port != "" {
		if port, err := parsePort(entry.Port); err == nil && port > 0 {
			config.Port = port
		}
	}

	if config.KeyPath == "" && entry.IdentityFile != "" {
		config.KeyPath = entry.IdentityFile
	}
}

func parsePort(s string) (int, error) {
	var port int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port: %s", s)
		}
		port = port*10 + int(c-'0')
	}
	return port, nil
}
