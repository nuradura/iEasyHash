# Installing iEasyHash

## Supported setup

The application has been exercised on Debian 13, Python 3.13, NVIDIA GTX 1070 (8 GiB), NVIDIA driver 550.163.01, Hashcat 6.2.6 and hcxtools 6.3.5. Other NVIDIA GPUs may work but are not part of this validation. This is the server web edition, not a native macOS app.

Use a host you administer. You need sudo for system installation and a working NVIDIA OpenCL runtime. Install the appropriate driver using your distribution's documented procedure before installing the application; the iEasyHash installer does not change the driver, bootloader, network, firewall or DNS.

## 1. Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv hashcat hcxtools clinfo
nvidia-smi
hashcat -I
hcxpcapngtool --version
```

Confirm that Hashcat lists your NVIDIA GPU as an OpenCL device. A working `nvidia-smi` alone does not confirm OpenCL support. The worker selects a GPU device; a CPU-only OpenCL setup is not the intended production configuration.

## 2. Install

```bash
git clone https://github.com/nuradura/iEasyHash.git
cd iEasyHash
sudo python3 ops/install.py
```

The default is `http://localhost:8787`, suitable for a local browser or SSH tunnel. For your own TLS endpoint:

```bash
sudo python3 ops/install.py --public-url https://audit.example.com
```

Choose the URL before the initial install. The installer refuses to overwrite an existing environment file. It creates:

| Resource | Location |
| --- | --- |
| Read-only application and virtual environment | /opt/wifi-audit |
| Private data, SQLite, captures, wordlists and runs | /var/lib/wifi-audit |
| Secret environment file, root-only | /etc/wifi-audit.env |
| Generated initial password, mode 0600 | FIRST_LOGIN.md in the checkout |
| Locked service account | wifi-audit |
| System units | wifi-audit-web.service, wifi-audit-worker.service |

The internal `wifi-audit` paths and `WIFI_*` variables are retained for compatibility. The product name is iEasyHash.

Read `FIRST_LOGIN.md` privately on your machine. Sign in as `admin` and change the initial password using the account button. Do not share or commit this file. Changing the password invalidates existing sessions.

## 3. Access

Both services run under an account without sudo. The web listener is loopback-only.

From another computer:

```bash
ssh -N -L 8787:127.0.0.1:8787 your-user@your-server
```

Then visit http://localhost:8787. Keep the SSH session running.

For an HTTPS endpoint, point your own reverse proxy at `127.0.0.1:8787`, preserve the Host header, and configure upload limits and timeouts. The supplied service trusts forwarded headers only from loopback. The environment's public URL, allowed hosts and secure-cookie flag must match your deployment. HTTPS requires `WIFI_COOKIE_SECURE=1`; the local HTTP setup requires `0`.

No domain, cloud account or tunnel credentials are required for the local setup.

## 4. Verify and use

```bash
sudo systemctl is-active wifi-audit-web wifi-audit-worker
curl -fsS http://127.0.0.1:8787/healthz
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/api/state
```

Expect healthy services and HTTP 401 for the unauthenticated data API.

1. Import an existing capture from a network you are authorized to audit.
2. Upload dictionaries or use the GitHub catalog.
3. Choose and order the dictionaries.
4. Select your networks and start a job.
5. Follow progress, pause/resume if needed, and view results in a network's detail dialog.

No dictionaries are bundled. Do not run real network checks as installation smoke tests.

## 5. Configuration

| Variable | Purpose |
| --- | --- |
| WIFI_DATA_DIR | Private runtime directory |
| WIFI_SESSION_SECRET | Random session-signing secret |
| WIFI_ADMIN_USER | Owner username |
| WIFI_ADMIN_PASSWORD_HASH | Initial Argon2 password hash; later rotations are stored in SQLite |
| WIFI_PUBLIC_URL | Browser origin, without a trailing slash |
| WIFI_COOKIE_SECURE | 1 for HTTPS, 0 for local HTTP |
| WIFI_ALLOWED_HOSTS | Comma-separated allowed hostnames |
| WIFI_HASHCAT | Hashcat executable, default /usr/bin/hashcat |
| WIFI_CONVERTER | hcxtools converter, default /usr/bin/hcxpcapngtool |

Edit `/etc/wifi-audit.env` privately and restart the web service after an origin change. Do not print the file in logs or support reports.

## 6. Upgrade

Wait for a job to finish or pause it and account for its checkpoint before stopping the worker. Back up the private runtime data and environment first.

```bash
git pull --ff-only
sudo systemctl stop wifi-audit-worker wifi-audit-web
sudo cp -a webapp/. /opt/wifi-audit/webapp/
sudo /opt/wifi-audit/.venv/bin/python -m pip install -r requirements.lock
sudo systemctl start wifi-audit-web wifi-audit-worker
```

Do not rerun the initial installer for an upgrade. Do not replace the data directory or environment file. After a restart, interrupted jobs require an explicit resume or stop.

## 7. Backups and troubleshooting

For a consistent backup, stop both services before copying `/var/lib/wifi-audit` and `/etc/wifi-audit.env` into private encrypted storage, then start the services again. The data directory includes recovered passwords. Do not attach it to a public issue.

- **GPU missing:** inspect `nvidia-smi` and `hashcat -I`, driver compatibility, and the service account's video/render permissions.
- **Login does not persist:** check that the URL matches the allowed host and that the cookie flag matches HTTP or HTTPS.
- **Conversion fails:** verify the converter is installed and the capture contains a usable WPA handshake or PMKID.
- **Resume repeats a pass:** the checkpoint had not yet been written; completed passes remain completed.
- **Upload rejected:** check the application's size limit and any smaller proxy limit.

Service logs are available through `journalctl -u wifi-audit-web -u wifi-audit-worker`. Redact private paths, network identities and credentials before sharing diagnostics.
