# litellm-investigation

Audit script to detect indicators of compromise from the [litellm supply chain attack](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) (versions 1.82.7 / 1.82.8, March 2026).

## Supported platforms

- **macOS** (Apple Silicon and Intel)
- **Linux**

The script auto-detects the platform and adjusts checks accordingly (e.g. LaunchAgents on macOS, systemd on Linux).

## Usage

```bash
chmod +x litellm-audit.sh
./litellm-audit.sh
```

Run specific phases:

```bash
./litellm-audit.sh -s 1 -s 2      # Discovery + version check only
./litellm-audit.sh --skip-docker   # Skip Docker container/image scanning
```

## Phases

1. **Discovery** — Find Python interpreters, site-packages, and scan Docker images/containers
2. **Version check** — Detect litellm installations and flag malicious versions
3. **IOC artifacts** — Check for backdoor files, .pth payloads, and exfiltration artifacts
4. **Persistence** — Scan systemd, LaunchAgents, crontab, and running processes
5. **Network** — Check connections to C2/exfil domains
6. **History** — Search shell history, pip/uv cache, and install logs

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no IOCs found |
| 1 | Warning — litellm present but safe version |
| 2 | Compromised — malicious version or IOC artifacts detected |

## License

MIT
