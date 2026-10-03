# Architecture

## Request path

The browser talks to a FastAPI application with Jinja templates and vanilla JavaScript. The UI polls for state and telemetry; no frontend build tool is required. Static assets are served locally.

The application enforces authentication for library data, logs, results and export. An Argon2 owner password establishes a signed session backed by a database row. Mutations require CSRF; requests are checked against allowed hosts and browser origins. Responses use no-store, noindex, CSP and anti-framing headers.

## Storage

SQLite records the library, dictionary order, jobs, attempts, sessions and password rotations. Uploaded files get generated names under a private runtime directory. Dictionaries are deduplicated by SHA-256; WPA records are validated and exactly deduplicated.

Recovered passwords are omitted from general state responses. Reveal and CSV export use authenticated endpoints. Operators must treat the database, potfile and exported CSV as private data.

## Worker

The worker is a separate systemd service with a process lock. A job stores immutable hash IDs and an ordered dictionary snapshot. Hashcat runs with WPA mode 22000 and dictionary mode 0. It receives an argument array, not a shell command.

Each dictionary produces a separate attempt with status, progress and a private log. The worker reads results, updates history, and stops early when all selected records have been recovered. Process groups and bounded shutdown keep child processes from surviving worker failures.

Pause/resume uses Hashcat's restore checkpoint. If no checkpoint exists, the current pass restarts. Unexpected worker restarts mark the job interrupted and require an operator decision.

## Deployment

The systemd web unit listens on loopback. Both services run as a locked user with no sudo, restrictive permissions, filesystem protection, memory limits and no Linux capability set. GPU access comes through the host's NVIDIA driver.

TLS, tunnels, firewalls and remote access are operator-managed. The source repository contains no account-specific infrastructure configuration.
