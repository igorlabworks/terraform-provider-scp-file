# Multi-Container Setup for Terraform Provider Testing

## Overview

This repository uses Docker CLI within the GitHub Actions setup steps to run an SSH server container alongside the GitHub Copilot coding agent. This enables testing of SSH/SCP operations required by the Terraform provider.

## Architecture

The `copilot-setup-steps.yml` starts an SSH server container using Docker CLI:

1. **Main Environment**: Where the Copilot agent runs, builds the provider, and executes tests
2. **SSH Server Container**: A Docker container running OpenSSH server for testing file transfer operations

## Why Not GitHub Actions Services?

Initially attempted to use GitHub Actions `services`, but research revealed that **Copilot agent only executes the `steps` from the workflow**, not the full workflow including services. The `services` section would be ignored.

**Source**: [Customizing the development environment for GitHub Copilot coding agent](https://docs.github.com/en/copilot/customizing-copilot/customizing-the-development-environment-for-copilot-coding-agent)

> In your copilot-setup-steps.yml file, you can only customize the following settings of the copilot-setup-steps job. If you try to customize other settings, your changes will be ignored.

While `services` is listed as customizable, the agent extracts and runs only the steps in its own environment, not as a full GitHub Actions workflow run.

## SSH Server Configuration

The SSH server uses the `linuxserver/openssh-server` Docker image with:

- **Port**: 2222 (mapped to host)
- **Username**: `testuser`
- **Password**: `testpass`
- **Home Directory**: `/config`

### Connection Details

From within the agent's environment:

```bash
# Using password authentication
sshpass -p testpass ssh -p 2222 testuser@localhost

# Using SCP for file transfer
sshpass -p testpass scp -P 2222 local_file testuser@localhost:/config/destination
```

## How It Works

### Docker CLI Approach

The setup steps use `docker run` to start the SSH server container:

```yaml
steps:
  - name: Start SSH server container
    run: |
      docker run -d --name ssh-server \
        -p 2222:2222 \
        -e PASSWORD_ACCESS=true \
        -e USER_PASSWORD=testpass \
        -e USER_NAME=testuser \
        linuxserver/openssh-server:latest
```

This approach works because:
- The Copilot agent executes the setup steps
- Docker is available in the GitHub Actions runner environment
- The container persists for the duration of the agent's work

### Network Connectivity

- The SSH server container is started with `-p 2222:2222` to expose port 2222
- The agent can connect to the SSH server at `localhost:2222`
- Health checks ensure the SSH server is ready before tests run

### Firewall Considerations

From the GitHub documentation on firewall limitations:

> The firewall only applies to processes started by the agent via its Bash tool. It does not apply to Model Context Protocol (MCP) servers or processes started in configured Copilot setup steps.

This means:
- Containers started in setup steps bypass firewall restrictions
- The agent can freely connect to localhost:2222 for testing

## Testing the Provider

### Manual Testing

To test SSH connectivity manually in a similar environment:

```yaml
steps:
  - name: Test SSH connection
    run: |
      sshpass -p testpass ssh -p 2222 testuser@localhost "echo 'Connection successful'"
  
  - name: Test SCP upload
    run: |
      echo "test data" > test.txt
      sshpass -p testpass scp -P 2222 test.txt testuser@localhost:/config/test.txt
  
  - name: Test SCP download
    run: |
      sshpass -p testpass scp -P 2222 testuser@localhost:/config/test.txt downloaded.txt
      cat downloaded.txt
```

### Provider Tests

The Terraform provider can use these connection details in acceptance tests:

```go
resource.Test(t, resource.TestCase{
    // ...
    Steps: []resource.TestStep{
        {
            Config: testAccSCPFileConfig("localhost", 2222, "testuser", "testpass"),
            // ...
        },
    },
})
```

## Limitations

1. **Single Repository**: The agent can only work within the repository where it's assigned
2. **Ephemeral Environment**: Everything resets between agent runs
3. **Ubuntu Only**: Only Ubuntu x64 Linux runners are supported
4. **No Self-Hosted Runners**: GitHub-hosted or ARC-managed runners only

## Advantages

1. **Isolated Testing**: Each run gets a fresh SSH server
2. **No External Dependencies**: Everything runs within GitHub Actions
3. **Fast Setup**: Services start in parallel with checkout
4. **Reproducible**: Same environment every time

## Alternative Approaches

If the Docker CLI approach doesn't work, alternatives include:

1. **Install OpenSSH directly**: Install and configure OpenSSH server in the runner itself
2. **Docker Compose**: Use docker-compose if multi-container orchestration is needed
3. **External Test Server**: Allowlist an external SSH server (requires firewall config)
4. **Mock Server**: Use a minimal SSH server implementation for testing

## Resources

- [GitHub Actions Services](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idservices)
- [Customizing Copilot Agent Environment](https://docs.github.com/en/copilot/customizing-copilot/customizing-the-development-environment-for-copilot-coding-agent)
- [OpenSSH Server Docker Image](https://hub.docker.com/r/linuxserver/openssh-server)
