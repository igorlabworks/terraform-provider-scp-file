# Terraform Provider for SCP File Transfer

This Terraform provider enables managing files on remote hosts via SCP/SFTP. It provides the same interface as the [hashicorp/local](https://registry.terraform.io/providers/hashicorp/local/latest) provider for `local_file` and `local_sensitive_file` resources, but transfers files to a remote destination instead of the local filesystem.

## Features

- **Similar interface to local provider**: Uses the same schema as `local_file` and `local_sensitive_file`
- **Remote file management**: Creates, updates, and deletes files on remote hosts via SFTP
- **Drift detection**: Automatically detects when remote files have been modified externally and reconciles state
- **Multiple content sources**: Supports content, content_base64, sensitive_content, and source file
- **File permissions**: Configure file and directory permissions
- **Checksum attributes**: Provides MD5, SHA1, SHA256, and SHA512 checksums

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.23 (for building from source)

## Installation

### Building from Source

```bash
git clone https://github.com/igorlabworks/terraform-provider-scp-file.git
cd terraform-provider-scp-file
go build -o terraform-provider-scp-file
```

## Usage

### Provider Configuration

```hcl
provider "scp" {
  host     = "example.com"
  port     = 22          # Optional, defaults to 22
  user     = "username"
  password = "password"  # Optional, conflicts with key_path
  key_path = "~/.ssh/id_rsa"  # Optional, for key-based auth
}
```

The provider supports multiple authentication methods:
1. **Password authentication**: Use the `password` attribute
2. **SSH key authentication**: Use the `key_path` attribute
3. **Default SSH keys**: If neither is specified, the provider will try default SSH keys from `~/.ssh/`

### Resources

#### scp_file

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

#### scp_sensitive_file

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

The provider automatically detects changes to remote files made outside of Terraform. When a file's content changes (detected via SHA1 checksum comparison), the provider will:

1. Remove the resource from state during refresh
2. Recreate the file with the expected content during the next apply

This ensures that the remote file always matches the desired state in your Terraform configuration.

## Development

### Building

```bash
go build -o terraform-provider-scp-file
```

### Testing

Run unit tests:
```bash
go test -v ./...
```

Run acceptance tests (requires SSH server):
```bash
TF_ACC=1 TEST_SSH_HOST=localhost TEST_SSH_PORT=22 TEST_SSH_USER=testuser TEST_SSH_PASSWORD=testpass go test -v ./internal/provider/...
```

## License

This project is licensed under the MIT License.
