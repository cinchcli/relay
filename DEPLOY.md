# Cinch Relay — Deployment Runbook

## Recommended: OCI Always Free (ARM Ampere)

Oracle Cloud Always Free never expires. The recommended shape for the relay:

| Setting | Value |
|---------|-------|
| Shape | VM.Standard.A1.Flex (ARM) |
| OCPU | 2 |
| RAM | 12 GB |
| OS | Ubuntu 22.04 ARM64 |
| Storage | 50 GB block volume (mounted at `/data`) |

The relay image (`ghcr.io/cinchcli/relay:latest`) is multi-arch and runs natively on ARM.

---

## TLS: Cloudflare proxy (recommended)

The relay speaks plain HTTP on `:8080`. Put Cloudflare in front:

1. In Cloudflare DNS, add an **A record** for `api.cinchcli.com` → OCI public IP, **orange cloud ON** (proxied).
2. SSL/TLS mode: set to **Full** (not Full Strict) if you don't have an origin cert, or **Full (Strict)** if you install a Cloudflare Origin Certificate on the VM.
3. Done — Cloudflare terminates HTTPS, forwards plain HTTP to the relay.
4. Optional: add a Cloudflare firewall rule to block requests that don't carry the `CF-Connecting-IP` header, so the origin can't be hit directly.

---

## OAuth App Registration

You must register OAuth apps **before** deploying with OAuth env vars.

### GitHub OAuth App

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
2. Application name: `Cinch`
3. Homepage URL: `https://cinchcli.com`
4. Authorization callback URL: `https://api.cinchcli.com/auth/oauth/github/callback`
5. Copy **Client ID** and **Client Secret** → add to `/etc/cinch/relay.env`

### Google OAuth Client

1. Go to **Google Cloud Console → APIs & Services → Credentials → Create Credentials → OAuth client ID**
2. Application type: **Web application**
3. Authorized redirect URI: `https://api.cinchcli.com/auth/oauth/google/callback`
4. Copy **Client ID** and **Client Secret** → add to `/etc/cinch/relay.env`

---

## Environment File

Create `/etc/cinch/relay.env` on the VM (mode `0600`, owned by root):

```bash
sudo mkdir -p /etc/cinch
sudo tee /etc/cinch/relay.env > /dev/null <<'EOF'
# Required — public HTTPS root of the relay (no trailing slash)
BASE_URL=https://api.cinchcli.com

# GitHub OAuth (leave empty to disable GitHub sign-in)
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Google OAuth (leave empty to disable Google sign-in)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Optional — comma-separated extra allowed CORS origins
# CORS_ORIGINS=https://your-frontend.example.com
EOF
sudo chmod 600 /etc/cinch/relay.env
```

Fill in the values from the OAuth app registration above.

---

## Docker Install & Run

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # log out and back in

# Create data directory
sudo mkdir -p /data
sudo chown $USER:$USER /data

# Pull and start
docker pull ghcr.io/cinchcli/relay:latest
docker run -d \
  --name cinch-relay \
  --restart always \
  -p 8080:8080 \
  -v /data:/data \
  --env-file /etc/cinch/relay.env \
  -e PORT=8080 \
  -e DB_PATH=/data/cinch.db \
  ghcr.io/cinchcli/relay:latest

# Verify
curl http://localhost:8080/health
```

### Systemd unit (alternative to `--restart always`)

```ini
# /etc/systemd/system/cinch-relay.service
[Unit]
Description=Cinch Relay
After=docker.service
Requires=docker.service

[Service]
Restart=always
ExecStartPre=-/usr/bin/docker stop cinch-relay
ExecStartPre=-/usr/bin/docker rm cinch-relay
ExecStart=/usr/bin/docker run \
  --name cinch-relay \
  -p 8080:8080 \
  -v /data:/data \
  --env-file /etc/cinch/relay.env \
  -e PORT=8080 \
  -e DB_PATH=/data/cinch.db \
  ghcr.io/cinchcli/relay:latest
ExecStop=/usr/bin/docker stop cinch-relay

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cinch-relay
```

---

## Local OAuth Smoke Test

To test OAuth end-to-end before deploying:

1. Register **localhost OAuth apps** on GitHub and Google with callback URL `http://localhost:8080/auth/oauth/github/callback` (and Google equivalent).
2. Create a local env file:
   ```bash
   cat > /tmp/relay-test.env <<EOF
   BASE_URL=http://localhost:8080
   GITHUB_CLIENT_ID=<your test app client id>
   GITHUB_CLIENT_SECRET=<your test app client secret>
   EOF
   ```
3. Run the relay locally:
   ```bash
   cd relay && env $(cat /tmp/relay-test.env | xargs) go run ./cmd/relay
   ```
4. From another terminal, start `cinch auth login` — it will print a URL like `http://localhost:8080/auth/browser?device_code=XXXX-XXXX`.
5. Open that URL in a browser — you should see the GitHub/Google sign-in page.
6. Click **Sign in with GitHub**, complete the OAuth flow.
7. The terminal should print `✓ Signed in.` within a few seconds.
8. Test push/pull: `echo hello | cinch push` then `cinch pull` from another terminal.

**Self-host fallback test:** run without `GITHUB_CLIENT_ID` set — the browser page should show the legacy "Device Name" form instead of OAuth buttons, confirming self-hosters aren't broken.

---

## Updates

```bash
docker pull ghcr.io/cinchcli/relay:latest
docker restart cinch-relay
```

SQLite migrations are applied automatically on startup — no manual schema work needed.
