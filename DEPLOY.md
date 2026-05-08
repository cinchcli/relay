# Cinch Relay — Deployment Runbook

## Architecture overview

AWS EC2 is the **primary** relay. OCI VM #2 is the **standby** — it stays in replica mode until EC2 fails, then takes over automatically. See `INFRA.md` for the full architecture diagram.

---

## Phase 1 — AWS setup

### 1-1. Account and billing

1. Create an AWS account (credit card required for free tier).
2. Set up CloudWatch billing alarms:
   - Metric: `EstimatedCharges`, threshold `$5` → SNS → `jingmuio@gmail.com`
   - Same for `$10`

### 1-2. EC2 instance

| Setting | Value |
|---------|-------|
| Region | us-east-1 |
| AMI | Rocky Linux 9 (ARM or x86 — pick x86 for t3.micro) |
| Instance type | t3.micro (2 vCPU, 1 GB RAM) |
| Storage | EBS gp3 20 GB, mounted at `/data/db` |
| Key pair | Create and download `.pem` |

```bash
# Mount EBS after instance start
sudo mkfs.ext4 /dev/xvdb
sudo mkdir -p /data/db
sudo mount /dev/xvdb /data/db
echo "/dev/xvdb /data/db ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab
sudo chown $USER:$USER /data/db
```

### 1-3. Elastic IP

Allocate an Elastic IP and associate it with the EC2 instance. The Cloudflare A record points here permanently.

### 1-4. Security group

| Direction | Port | Source |
|-----------|------|--------|
| Inbound | 8080 (TCP) | [Cloudflare IP ranges](https://www.cloudflare.com/ips/) |
| Inbound | 22 (TCP) | Your IP |
| Inbound | 9090 (TCP) | localhost only (Failback Listener — bind to 127.0.0.1) |
| Outbound | all | 0.0.0.0/0 |

### 1-5. IAM

**Instance Role** (attach to EC2 at launch):
```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::cinch-data", "arn:aws:s3:::cinch-data/*"]
}
```

**IAM User `cinch-data-rw`** (for OCI to access S3):
- Same policy as above
- Generate access key; you will store it in OCI later

### 1-6. S3 bucket

```bash
aws s3api create-bucket \
  --bucket cinch-data \
  --region us-east-1

# No versioning needed — S3's 11-nines durability is sufficient
```

Bucket structure (Litestream and relay create these automatically):
```
s3://cinch-data/
  litestream/    WAL segments (real-time)
  snapshots/     daily SQLite snapshots
  media/         binary clips (images, files)
```

### 1-7. SSM Parameter Store

Store secrets so the EC2 instance never has plaintext credentials on disk:
```bash
aws ssm put-parameter --name /cinch/CF_API_TOKEN   --type SecureString --value "<cloudflare api token>"
aws ssm put-parameter --name /cinch/GITHUB_SECRET  --type SecureString --value "<github oauth secret>"
aws ssm put-parameter --name /cinch/GOOGLE_SECRET  --type SecureString --value "<google oauth secret>"
```

### 1-8. CloudWatch Auto Recovery

Create an alarm that automatically recovers the EC2 instance on hardware failure:
- Metric: `StatusCheckFailed_System`
- Threshold: ≥ 1 for 2 consecutive minutes
- Action: EC2 recover

---

## Phase 2 — Cloudflare setup

1. Add an **A record**: `api.cinchcli.com` → EC2 Elastic IP, **orange cloud ON** (proxied).
2. SSL/TLS mode: **Full** (relay speaks plain HTTP on :8080; Cloudflare terminates TLS).
3. Firewall rule: block requests missing the `CF-Connecting-IP` header (hides origin IP).
4. Create an **API token** with `Zone:DNS:Edit` permission for `cinchcli.com` — store in SSM.

---

## Phase 3 — EC2 relay deployment

### 3-1. OAuth app registration

**GitHub:**
1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App
2. Callback URL: `https://api.cinchcli.com/auth/oauth/github/callback`
3. Copy Client ID + Secret → `/etc/cinch/relay.env`

**Google:**
1. Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web application)
2. Redirect URI: `https://api.cinchcli.com/auth/oauth/google/callback`
3. Copy Client ID + Secret → `/etc/cinch/relay.env`

### 3-2. Environment file

```bash
sudo mkdir -p /etc/cinch
sudo tee /etc/cinch/relay.env > /dev/null <<'EOF'
BASE_URL=https://api.cinchcli.com

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Media storage — use S3 for binary clips
MEDIA_BACKEND=s3
MEDIA_BUCKET=cinch-data
MEDIA_ENDPOINT=s3.amazonaws.com
MEDIA_REGION=us-east-1
# No access key needed — IAM instance role provides credentials

# Cloudflare API (for failover/failback DNS switch)
CF_API_TOKEN=
CF_ZONE_ID=
OCI_PUBLIC_IP=   # VM #2 public IP

# Telemetry heartbeat key
TELEMETRY_KEY=
EOF
sudo chmod 600 /etc/cinch/relay.env
```

### 3-3. Install Docker and Litestream

```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # log out and back in

# Litestream
wget https://github.com/benbjohnson/litestream/releases/latest/download/litestream-linux-amd64.tar.gz
tar xzf litestream-linux-amd64.tar.gz
sudo mv litestream /usr/local/bin/
```

### 3-4. Litestream config

```bash
sudo tee /etc/litestream.yml > /dev/null <<'EOF'
dbs:
  - path: /data/db/cinch.db
    replicas:
      - type: s3
        bucket: cinch-data
        path: litestream
        region: us-east-1
EOF
```

### 3-5. Systemd unit (relay + Litestream)

Litestream restores the latest state from S3 before starting the relay — so EC2 always boots with the most recent data, including any writes made while OCI was primary.

```bash
sudo tee /etc/systemd/system/cinch-relay.service > /dev/null <<'EOF'
[Unit]
Description=Cinch Relay (via Litestream)
After=docker.service network-online.target
Requires=docker.service

[Service]
EnvironmentFile=/etc/cinch/relay.env
Restart=always
ExecStartPre=/usr/local/bin/litestream restore -config /etc/litestream.yml -if-replica-exists /data/db/cinch.db
ExecStart=/usr/local/bin/litestream replicate -config /etc/litestream.yml \
  -exec "docker run --rm \
    --name cinch-relay-proc \
    -p 8080:8080 \
    -v /data/db:/data \
    --env-file /etc/cinch/relay.env \
    -e PORT=8080 \
    -e DB_PATH=/data/cinch.db \
    ghcr.io/cinchcli/relay:latest"
ExecStop=/usr/bin/docker stop cinch-relay-proc

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cinch-relay
```

### 3-6. Failback Listener

The Failback Listener runs on EC2, port 9090 (bound to 127.0.0.1). OCI Telemetry calls `POST /promote` when EC2 recovers — it restores the latest data from S3 and starts the relay.

```bash
sudo tee /etc/cinch/failback.sh > /dev/null <<'EOF'
#!/bin/bash
set -e
source /etc/cinch/relay.env

# 1. Restore latest SQLite state from S3 (includes OCI's writes)
litestream restore -config /etc/litestream.yml -if-replica-exists /data/db/cinch.db

# 2. Start relay
systemctl start cinch-relay

# 3. Switch Cloudflare origin back to EC2
curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$(curl -s "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?name=api.cinchcli.com" -H "Authorization: Bearer $CF_API_TOKEN" | jq -r '.result[0].id')" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"A\",\"name\":\"api.cinchcli.com\",\"content\":\"$(curl -s ifconfig.me)\",\"proxied\":true}"
EOF
sudo chmod 755 /etc/cinch/failback.sh
```

Build and install the Failback Listener binary (Go, provider-agnostic — executes `$FAILBACK_SCRIPT`):
```bash
# See relay/cmd/failover-listener for source
go build -o /usr/local/bin/cinch-failback ./cmd/failover-listener
```

```ini
# /etc/systemd/system/cinch-failback.service
[Unit]
Description=Cinch Failback Listener
After=network.target

[Service]
EnvironmentFile=/etc/cinch/relay.env
Environment=LISTEN_ADDR=127.0.0.1:9090
Environment=FAILBACK_SCRIPT=/etc/cinch/failback.sh
ExecStart=/usr/local/bin/cinch-failback
Restart=always

[Install]
WantedBy=multi-user.target
```

### 3-7. Health ping (systemd timer)

Relay sends `health.ping` to Telemetry every 60 seconds. If silent for 2 minutes, Telemetry triggers failover.

```bash
sudo tee /etc/systemd/system/cinch-health-ping.service > /dev/null <<'EOF'
[Unit]
Description=Cinch relay health ping

[Service]
EnvironmentFile=/etc/cinch/relay.env
ExecStart=/usr/bin/curl -s -X POST https://telemetry.jinmu.me/v1/events \
  -H "X-API-Key: $TELEMETRY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"app":"cinch","event":"health.ping","context":{"instance":"aws-primary"}}'
EOF

sudo tee /etc/systemd/system/cinch-health-ping.timer > /dev/null <<'EOF'
[Unit]
Description=Cinch relay health ping (60s)

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cinch-health-ping.timer
```

---

## Phase 4 — OCI standby setup

### 4-1. VM #2 provisioning

| Setting | Value |
|---------|-------|
| Shape | VM.Standard.A1.Flex |
| OCPU | 2 |
| RAM | 12 GB |
| OS | Oracle Linux (Oracle Cloud Image) |
| Storage | 50 GB block volume at `/data/db` |
| Cost | Always Free, never expires |

> OCI VM #1 + VM #2 total: 4 OCPU / 24 GB RAM — exactly the Always Free limit.

Place both VMs in the **same VCN and subnet**. Security List for VM #2:
- TCP 8080 inbound: Cloudflare IP ranges only
- TCP 9090 inbound: VM #1 private IP only (VCN-internal, no internet)

### 4-2. Install Litestream (receive mode)

```bash
# Linux ARM64 binary
wget https://github.com/benbjohnson/litestream/releases/latest/download/litestream-linux-arm64.tar.gz
tar xzf litestream-linux-arm64.tar.gz
sudo mv litestream /usr/local/bin/
```

```yaml
# /etc/litestream.yml (receive/replica mode — normal state)
dbs:
  - path: /data/db/cinch.db
    replicas:
      - type: s3
        bucket: cinch-data
        path: litestream
        region: us-east-1
        access-key-id: <cinch-data-rw key>
        secret-access-key: <cinch-data-rw secret>
```

Store the `cinch-data-rw` IAM credentials in OCI Vault (or `/etc/cinch/s3.env` mode 0600).

### 4-3. Failover scripts

```bash
sudo tee /etc/cinch/failover.sh > /dev/null <<'EOF'
#!/bin/bash
set -e
source /etc/cinch/relay.env

# 1. Switch Litestream to write mode (stop receive, start replicate)
systemctl stop cinch-litestream-receive
systemctl start cinch-relay   # relay starts Litestream in replicate mode

# 2. Switch Cloudflare origin to OCI public IP
curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$(curl -s "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?name=api.cinchcli.com" -H "Authorization: Bearer $CF_API_TOKEN" | jq -r '.result[0].id')" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"A\",\"name\":\"api.cinchcli.com\",\"content\":\"$OCI_PUBLIC_IP\",\"proxied\":true}"
EOF

sudo tee /etc/cinch/flush.sh > /dev/null <<'EOF'
#!/bin/bash
# Flush remaining WAL to S3 before failback
litestream replicate -config /etc/litestream.yml -flush
EOF

sudo chmod 755 /etc/cinch/failover.sh /etc/cinch/flush.sh
```

### 4-4. Failover Listener

```bash
# Build for ARM64 — see relay/cmd/failover-listener
GOARCH=arm64 GOOS=linux go build -o /usr/local/bin/cinch-failover ./cmd/failover-listener
```

```ini
# /etc/systemd/system/cinch-failover-listener.service
[Unit]
Description=Cinch Failover Listener
After=network.target

[Service]
EnvironmentFile=/etc/cinch/relay.env
Environment=LISTEN_ADDR=0.0.0.0:9090
Environment=FAILOVER_SCRIPT=/etc/cinch/failover.sh
Environment=FLUSH_SCRIPT=/etc/cinch/flush.sh
ExecStart=/usr/local/bin/cinch-failover
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cinch-failover-listener
```

### 4-5. Pre-pull Docker image

```bash
docker pull ghcr.io/cinchcli/relay:latest
```

The relay image is multi-arch — runs natively on ARM64.

---

## Phase 5 — Telemetry configuration

Add two columns and configure the silence rule. This is done on OCI VM #1 (`telemetry.jinmu.me`).

### 5-1. DB migration

```sql
ALTER TABLE alert_rules ADD COLUMN webhook_url TEXT;
ALTER TABLE alert_rules ADD COLUMN resolve_webhook_url TEXT;
```

### 5-2. Config change

Relax `silence_minutes` minimum from 5 → 1, and add per-rule webhook support (falls back to global `ALERT_WEBHOOK_URL` when `webhook_url` is NULL).

### 5-3. Register cinch-relay silence rule

```json
{
  "name": "cinch-relay-heartbeat",
  "rule_type": "silence",
  "config": {
    "app": "cinch",
    "event_pattern": "health.ping",
    "silence_minutes": 2
  },
  "webhook_url": "http://<VM2-VCN-private-IP>:9090/failover",
  "resolve_webhook_url": "http://<EC2-IP>:9090/promote"
}
```

> Both webhook calls travel over the OCI VCN (failover) or the internet (failback to EC2). The failover path never touches the public internet.

---

## Phase 6 — Integration test

```bash
# 1. Verify EC2 relay
curl https://api.cinchcli.com/health

# 2. Round-trip
echo "hello" | cinch push
cinch pull

# 3. Simulate failover — stop EC2 relay
sudo systemctl stop cinch-relay
# Wait ~65s, then verify traffic is served by OCI:
curl https://api.cinchcli.com/health

# 4. Push a clip via OCI
echo "from oci" | cinch push

# 5. Restore EC2 relay — wait for failback (3 consecutive health successes)
sudo systemctl start cinch-relay
# After ~90s, verify EC2 is primary again and OCI clip is present:
cinch pull
```

---

## Updates

```bash
# EC2 — pull new image and restart
docker pull ghcr.io/cinchcli/relay:latest
sudo systemctl restart cinch-relay

# OCI — pre-pull so failover starts faster
docker pull ghcr.io/cinchcli/relay:latest
```

SQLite migrations run automatically on relay startup — no manual schema work needed.

---

## Media storage

Binary clip media (images, files) is stored via a pluggable backend.

| Variable | Default | Description |
|---|---|---|
| `MEDIA_BACKEND` | `local` | `local` or `s3` |
| `MEDIA_BUCKET` | — | Bucket name (S3 backend) |
| `MEDIA_ENDPOINT` | `s3.amazonaws.com` | S3-compatible endpoint |
| `MEDIA_REGION` | `us-east-1` | Bucket region |
| `MEDIA_ACCESS_KEY_ID` | — | Omit to use IAM role |
| `MEDIA_SECRET_ACCESS_KEY` | — | Omit to use IAM role |

Both EC2 and OCI read/write the same `s3://cinch-data/media/` prefix — no sync needed on failover.

**Cloudflare R2 example:**
```env
MEDIA_BACKEND=s3
MEDIA_ENDPOINT=<account-id>.r2.cloudflarestorage.com
MEDIA_BUCKET=cinch-media
MEDIA_ACCESS_KEY_ID=<r2-token-id>
MEDIA_SECRET_ACCESS_KEY=<r2-token-secret>
MEDIA_USE_SSL=true
```

---

## Local OAuth smoke test

1. Register localhost OAuth apps with callback `http://localhost:8080/auth/oauth/github/callback`.
2. Run:
   ```bash
   cat > /tmp/relay-test.env <<EOF
   BASE_URL=http://localhost:8080
   GITHUB_CLIENT_ID=<test id>
   GITHUB_CLIENT_SECRET=<test secret>
   EOF
   cd relay && env $(cat /tmp/relay-test.env | xargs) go run ./cmd/relay
   ```
3. In another terminal: `cinch auth login` → open the printed URL → complete OAuth.
4. `echo hello | cinch push` then `cinch pull`.

**Self-host fallback:** omit `GITHUB_CLIENT_ID` — the browser page shows the legacy "Device Name" form.
