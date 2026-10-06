# Security Policy

## Security model

KeyRelay keeps credentials out of the Bot API and limits browser navigation to
explicitly approved public hosts. Credentials are encrypted at rest, and
administration uses a separate token from login execution.

KeyRelay does **not** protect secrets from an attacker or Bot with unrestricted
access to the host operating system, process memory, data directory, or
encryption key. For untrusted agents, run KeyRelay and its browser in a
separately administered environment and expose only a narrowly scoped private
API.

Do not expose KeyRelay directly to the public internet. Keep it bound to
`127.0.0.1` and use a trusted tunnel when remote access is required.

## Reporting a vulnerability

Do not include passwords, tokens, cookies, database files, or other secrets in
a public issue. Open a GitHub issue containing only non-sensitive reproduction
details and request a private reporting channel when confidential material is
required.
