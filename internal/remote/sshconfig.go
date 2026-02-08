package remote

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SSHConfigEntry struct {
	Host         string
	Hostname     string
	User         string
	Port         string
	IdentityFile string
}

type SSHConfig struct {
	entries         map[string]*SSHConfigEntry
	orderedPatterns []string
	globalDefaults  *SSHConfigEntry
}

func LoadSSHConfig(configPath string) (*SSHConfig, error) {
	configPath, err := resolveConfigPath(configPath)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(configPath)
	if err != nil {
		return &SSHConfig{entries: make(map[string]*SSHConfigEntry)}, nil
	}
	defer file.Close()
	return parseSSHConfig(file)
}

func resolveConfigPath(configPath string) (string, error) {
	if configPath == "" {
		configPath = "~/.ssh/config"
	}

	if strings.HasPrefix(configPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configPath = filepath.Join(home, configPath[2:])
	}
	return configPath, nil
}

func parseSSHConfig(file *os.File) (*SSHConfig, error) {
	config := &SSHConfig{
		entries:        make(map[string]*SSHConfigEntry),
		globalDefaults: &SSHConfigEntry{},
	}
	var currentEntry *SSHConfigEntry
	var currentPatterns []string
	inHostBlock := false

	scanner := bufio.NewScanner(file)
	lineRe := regexp.MustCompile(`^\s*(\w+)\s*[=\s]\s*(.+?)\s*$`)
	commentRe := regexp.MustCompile(`^\s*(#.*)?$`)

	for scanner.Scan() {
		line := scanner.Text()

		if commentRe.MatchString(line) {
			continue
		}

		matches := lineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		keyword := strings.ToLower(matches[1])
		value := matches[2]

		value = strings.Trim(value, "\"'")

		switch keyword {
		case "host":
			if currentEntry != nil {
				for _, pattern := range currentPatterns {
					config.entries[pattern] = currentEntry
					config.orderedPatterns = append(config.orderedPatterns, pattern)
				}
			}
			currentPatterns = strings.Fields(value)
			currentEntry = &SSHConfigEntry{Host: value}
			inHostBlock = true

		case "hostname":
			if inHostBlock && currentEntry != nil {
				currentEntry.Hostname = value
			}

		case "user":
			if inHostBlock && currentEntry != nil {
				currentEntry.User = value
			} else if !inHostBlock {
				config.globalDefaults.User = value
			}

		case "port":
			if inHostBlock && currentEntry != nil {
				currentEntry.Port = value
			} else if !inHostBlock {
				config.globalDefaults.Port = value
			}

		case "identityfile":
			value = expandPath(value)
			if inHostBlock && currentEntry != nil {
				currentEntry.IdentityFile = value
			} else if !inHostBlock {
				config.globalDefaults.IdentityFile = value
			}
		}
	}

	if currentEntry != nil {
		for _, pattern := range currentPatterns {
			config.entries[pattern] = currentEntry
			config.orderedPatterns = append(config.orderedPatterns, pattern)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *SSHConfig) GetEntry(host string) *SSHConfigEntry {
	if entry, ok := c.entries[host]; ok {
		return entry
	}

	for _, pattern := range c.orderedPatterns {
		if pattern != host && matchPattern(pattern, host) {
			return c.entries[pattern]
		}
	}

	return nil
}

func matchPattern(pattern, host string) bool {
	if pattern == "*" {
		return true
	}

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

func (c *SSHConfig) ApplyToConfig(host string, config *Config) {
	originalConfig := &Config{
		Host:    config.Host,
		User:    config.User,
		Port:    config.Port,
		KeyPath: config.KeyPath,
	}

	c.applyGlobalDefaults(config)

	c.applyEntryDefaults(host, config, originalConfig)
}

func (c *SSHConfig) applyGlobalDefaults(config *Config) {
	originalUser := config.User
	originalPort := config.Port
	originalKeyPath := config.KeyPath

	if c.globalDefaults != nil {
		if originalUser == "" && c.globalDefaults.User != "" {
			config.User = c.globalDefaults.User
		}
		if originalPort == 0 && c.globalDefaults.Port != "" {
			if port, err := parsePort(c.globalDefaults.Port); err == nil && port > 0 {
				config.Port = port
			}
		}
		if originalKeyPath == "" && c.globalDefaults.IdentityFile != "" {
			config.KeyPath = c.globalDefaults.IdentityFile
		}
	}
}
func (c *SSHConfig) applyEntryDefaults(host string, config *Config, originalConfig *Config) {
	entry := c.GetEntry(host)

	if entry != nil {
		if originalConfig.Host == host && entry.Hostname != "" {
			config.Host = entry.Hostname
		}

		if originalConfig.User == "" && entry.User != "" {
			config.User = entry.User
		}

		if originalConfig.Port == 0 && entry.Port != "" {
			if port, err := parsePort(entry.Port); err == nil && port > 0 {
				config.Port = port
			}
		}

		if originalConfig.KeyPath == "" && entry.IdentityFile != "" {
			config.KeyPath = entry.IdentityFile
		}
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
