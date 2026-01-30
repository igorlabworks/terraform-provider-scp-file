# Terraform Provider for SCP File Transfer

This Terraform provider enables managing files on remote hosts via SCP/SFTP. It aims to provide the same interface as the [hashicorp/local](https://registry.terraform.io/providers/hashicorp/local/latest) provider for `local_file` and `local_sensitive_file` resources, but transfers files to a remote destination instead of the local filesystem.

## Features

- **Similar interface to local provider**: Uses the same schema as `local_file` and `local_sensitive_file`
- **Remote file management**: Creates, updates, and deletes files on remote hosts via SFTP
- **Drift detection**: Automatically detects when remote files have been modified externally (content or permissions) and reconciles state
- **Multiple content sources**: Supports content, content_base64, and source file
- **File and directory permissions**: Configure file and directory permissions with proper enforcement
- **Checksum attributes**: Provides MD5, SHA1, SHA256, and SHA512 checksums
- **SSH config support**: Reads `~/.ssh/config` for `User`, `Hostname`, `Port`, and `IdentityFile` directives
- **SSH agent support**: Automatically uses SSH agent when available
- **Host key verification**: Uses `known_hosts` file for host key verification with helpful error messages

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.24 (for building from source)

## Installation

### Building from Source

```bash
git clone https://github.com/igorlabworks/terraform-provider-scp.git
cd terraform-provider-scp
go build -o terraform-provider-scp
```

## Usage

### Provider Configuration

```hcl
provider "scp" {
  host             = "example.com"        # Required: hostname, IP, or SSH config alias
  port             = 22                   # Optional, defaults to 22
  user             = "username"           # Optional, can be set via ~/.ssh/config
  password         = "password"           # Optional, for password auth
  key_path         = "~/.ssh/id_rsa"      # Optional, for key-based auth
  ssh_config_path  = "~/.ssh/config"      # Optional, path to SSH config file
  known_hosts_path = "~/.ssh/known_hosts" # Optional, path to known_hosts file
  ignore_host_key  = false                # Optional, skip host key verification (insecure)
}
```

### Authentication Methods

The provider supports multiple authentication methods (tried in order):

1. **Password authentication**: Use the `password` attribute
2. **SSH agent**: Automatically uses `SSH_AUTH_SOCK` if available
3. **SSH key file**: Use the `key_path` attribute or `IdentityFile` from SSH config
4. **Default SSH keys**: If nothing is specified, tries keys from `~/.ssh/` in order:
   - `id_ed25519`
   - `id_ecdsa`
   - `id_rsa`
   - `id_dsa`

### SSH Config Support

The provider reads `~/.ssh/config` and supports the following directives:

- `Host` - Pattern matching for host aliases
- `Hostname` - The actual hostname to connect to
- `User` - Username for authentication
- `Port` - SSH port
- `IdentityFile` - Path to SSH private key

Example `~/.ssh/config`:

```
Host myserver
    Hostname actual.server.com
    User deploy
    Port 2222
    IdentityFile ~/.ssh/deploy_key
```

Then in Terraform:

```hcl
provider "scp" {
  host = "myserver"  # Uses settings from SSH config
}
```

### Host Key Verification

By default, the provider verifies host keys using the `~/.ssh/known_hosts` file. If the host key is not found or has changed, the provider will output a helpful error message with the line to add to your known_hosts file:

```
host key not found for example.com. To add this host, append this line to /home/user/.ssh/known_hosts:
example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

To disable host key verification (not recommended for production):

```hcl
provider "scp" {
  host            = "example.com"
  ignore_host_key = true
}
```

### Resources

#### `scp_file`

Creates a file on a remote host with the given content.

```hcl
resource "scp_file" "example" {
  content  = "Hello, World!"
  filename = "/home/user/hello.txt"
}
```

With base64 content:

```hcl
resource "scp_file" "binary_file" {
  content_base64 = base64encode(file("local_file.bin"))
  filename       = "/home/user/file.bin"
}
```

From a local source file:

```hcl
resource "scp_file" "from_source" {
  source   = "./local_config.txt"
  filename = "/etc/app/config.txt"
}
```

With custom permissions:

```hcl
resource "scp_file" "script" {
  content              = "#!/bin/bash\necho 'Hello'"
  filename             = "/home/user/script.sh"
  file_permission      = "0755"
  directory_permission = "0755"
}
```

#### `scp_sensitive_file`

Creates a file on a remote host with sensitive content. The content will not be displayed in Terraform plan output.

```hcl
resource "scp_sensitive_file" "credentials" {
  content  = var.secret_data
  filename = "/home/user/.credentials"
  file_permission = "0600"
}
```

### Attributes Reference

Both `scp_file` and `scp_sensitive_file` resources support the following:

#### Arguments

- `filename` - (Required) The path to the file on the remote host. Missing parent directories will be created.
- `content` - (Optional) Content to store in the file, expected to be a UTF-8 encoded string. Conflicts with `content_base64`, `sensitive_content`, and `source`.
- `content_base64` - (Optional) Content to store in the file, expected to be binary encoded as base64 string. Conflicts with `content`, `sensitive_content`, and `source`.
- `source` - (Optional) Path to a local file to use as source. Conflicts with `content`, `content_base64`, and `sensitive_content`.
- `sensitive_content` - (Optional, `scp_file` only, deprecated) Use `scp_sensitive_file` instead.
- `file_permission` - (Optional) Permissions for the file in octal notation. Default is `"0777"` for `scp_file` and `"0700"` for `scp_sensitive_file`.
- `directory_permission` - (Optional) Permissions for created directories in octal notation. Default is `"0777"` for `scp_file` and `"0700"` for `scp_sensitive_file`.

#### Read-Only Attributes

- `id` - The hexadecimal encoding of the SHA1 checksum of the file content.
- `content_md5` - MD5 checksum of file content.
- `content_sha1` - SHA1 checksum of file content.
- `content_sha256` - SHA256 checksum of file content.
- `content_base64sha256` - Base64 encoded SHA256 checksum of file content.
- `content_sha512` - SHA512 checksum of file content.
- `content_base64sha512` - Base64 encoded SHA512 checksum of file content.

## Drift Detection

The provider automatically detects changes to remote files made outside of Terraform:

- **Content drift**: Detected via SHA1 checksum comparison
- **Permission drift**: Detected by comparing actual file mode with configured `file_permission`

When drift is detected, the provider will:

1. Remove the resource from state during refresh
2. Recreate the file with the expected content and permissions during the next apply

This ensures that the remote file always matches the desired state in your Terraform configuration.

## Development

### Building

```bash
just build
```

### Testing

Run unit tests:

```bash
just test
```

Run acceptance tests (requires SSH server):

```bash
TF_ACC=1 TEST_SSH_HOST=localhost TEST_SSH_PORT=22 TEST_SSH_USER=testuser TEST_SSH_PASSWORD=testpass go test -v ./internal/provider/...
```

### Architecture

The provider uses a clean separation between Terraform plugin code and SSH/SFTP logic:

- `internal/provider/` - Terraform provider implementation (resources, schema, CRUD operations)
- `internal/remote/interface.go` - Defines the `Client` interface and `FileInfo` struct
- `internal/remote/sftp.go` - SFTP implementation using pkg/sftp
- `internal/remote/sshconfig.go` - SSH config file parser with first-match semantics

## License

This project is licensed under the MIT License.
