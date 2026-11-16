# Security

This is an unqualified spike. Do not deploy it with production data or credentials.
Report vulnerabilities privately through the repository's GitHub security advisory
reporting, when available, or contact the repository owner privately. Do not post
secrets or exploit details in public issues.

Use a fresh CA and independent credentials per run. Never commit or upload tokens,
private keys, environment files or raw database dumps. Runtime artifacts must be
sanitized and allowlisted. The adapter API is trusted infrastructure, isolated from
clients; HTTPS server verification and a per-run service credential are mandatory.

Known boundaries: in-memory state is lost on restart; no management API parity,
no persistent audit, no token introspection or immediate IdP-membership revocation,
no policy bundle signatures, no production hardening or storage isolation claim.
