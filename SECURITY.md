# Security Policy

Stage 2CS SIEM is an educational and lab project.

- Set separate `SIEM_INGEST_API_KEY`, `SIEM_ANALYST_API_KEY`, and `SIEM_ADMIN_API_KEY` values before sharing a deployment. `SIEM_API_KEY` is a convenient all-access key for small labs.
- Set `SIEM_PROTECT_READS=true` when read endpoints should require an analyst or administrator key.
- Put the service behind TLS and an authenticated reverse proxy for any shared environment.
- Do not ingest secrets unless you intend to store them in the configured database.
- The included UDP syslog collector is intentionally minimal and is not hardened for hostile networks.
- Use only telemetry and systems you are authorized to monitor.

Please report security issues privately to the repository maintainer rather than opening a public issue with exploit details.
