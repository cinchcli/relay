# Cinch Relay — AWS Infrastructure

```mermaid
graph TD
    subgraph Clients["Clients"]
        CLI["cinch CLI\n(macOS / Linux / Windows)"]
        Desktop["cinch Desktop\n(macOS)"]
    end

    subgraph Edge["Edge · Cloudflare"]
        CF["api.cinchcli.com\nDNS proxied (orange cloud)\nSSL mode: Full Strict\nEdge cert: Let's Encrypt (to clients)\nOrigin cert: CF Origin Cert (to EC2)"]
    end

    subgraph AWS["AWS (us-east-1)"]
        EIP["Elastic IP\n100.55.222.248"]

        subgraph EC2Box["EC2 t3.micro · Amazon Linux 2023 — PRIMARY"]
            SG["Security Group cinch-relay-sg\nTCP 443 — Cloudflare IPv4/IPv6 ranges\nTCP 443 — home IP 115.31.118.143/32\nTCP 22  — home IP 115.31.118.143/32"]
            Nginx["nginx 1.28.3\nlisten 443 ssl\nssl_certificate /etc/nginx/ssl/cinchcli.crt\nproxy_pass http://127.0.0.1:8080\nWebSocket Upgrade/Connection headers\nproxy_read_timeout 3600s"]
            Relay["Docker: ghcr.io/cinchcli/relay:latest\n-p 127.0.0.1:8080:8080\nenv: relay.env + DATABASE_URL\nsystemd: cinch-relay.service"]
        end

        RDS["RDS db.t4g.micro\nPostgreSQL 16\n20 GiB gp2\nSingle AZ\nNo public access\nSG: port 5432 from cinch-relay-sg only"]

        S3["S3 Bucket cinch-data\nmedia/  binary clips\nVersioning OFF"]

        IAM_ROLE["IAM Instance Role cinch-relay-ec2-role\ns3:* → cinch-data/*"]
        CW["CloudWatch\nBilling Alarm $5 / $10\nSNS → jingmuio@gmail.com"]
    end

    subgraph OCI["OCI Always Free (planned)"]
        VM1["OCI VM #1 · A1.Flex\ntelemetry.jinmu.me\nhealth.ping monitor"]
        VM2["OCI VM #2 · A1.Flex\nStandby Relay (not yet provisioned)"]
    end

    subgraph External["External"]
        GHCR["GitHub Container Registry\nghcr.io/cinchcli/relay:latest"]
    end

    CLI     -->|"HTTPS POST /clips\nWSS GET /v1/stream"| CF
    Desktop -->|"WSS /v1/stream\nHTTPS POST /clips"| CF
    CF      -->|"HTTPS :443"| EIP
    EIP     --> SG
    SG      --> Nginx
    Nginx   -->|"HTTP :8080"| Relay
    Relay   -->|"DATABASE_URL (SSL)"| RDS
    Relay   -->|"media read/write"| S3
    IAM_ROLE -.->|"attached"| EC2Box
    GHCR    -->|"docker pull"| Relay
    CW      -.->|"auto recovery (planned)"| EC2Box
    VM1     -.->|"failover trigger (planned)"| VM2
```

## Components

| Component | Status | Detail |
|---|---|---|
| EC2 t3.micro | ✅ Running | `i-01031829df0e1be6a`, Amazon Linux 2023, EIP `100.55.222.248` |
| nginx 1.28.3 | ✅ Running | TLS terminator. Cloudflare Origin Cert at `/etc/nginx/ssl/cinchcli.crt`. Proxies to relay on `127.0.0.1:8080`. |
| Cloudflare | ✅ Active | `api.cinchcli.com` DNS proxied. SSL mode Full Strict. SG allows CF IPv4/IPv6 ranges only (no `0.0.0.0/0`). |
| cinch-relay Docker | ✅ Running | `cinch-relay-proc`. Systemd service `cinch-relay.service`. Bound to `127.0.0.1:8080` (nginx-only access). |
| RDS db.t4g.micro | ✅ Created | PostgreSQL 16, 20 GiB gp2, Single AZ, no public access. Endpoint: `cinch-db.c2rcmg0giknp.us-east-1.rds.amazonaws.com`. User: `cinchdb`, DB: `postgres`. |
| S3 cinch-data | ✅ Active | `media/` prefix for binary clips. IAM instance role for EC2 access. |
| IAM Instance Role | ✅ Active | `cinch-relay-ec2-role`. Attached to EC2. No static access keys on instance. |
| CloudWatch Billing | ✅ Active | Alarms at $5 and $10 → SNS → `jingmuio@gmail.com`. |
| CloudWatch Auto Recovery | ⏳ Planned | `StatusCheckFailed_System` → EC2 recover action. |
| OCI VM #2 Standby | ⏳ Planned | Standby relay. Not yet provisioned. |

## TLS Architecture

```
Client → [Let's Encrypt cert] → Cloudflare Edge → [Origin Cert] → nginx (EC2 :443) → relay (:8080)
```

- Clients see a valid Let's Encrypt certificate issued by Cloudflare.
- Cloudflare validates the EC2 origin using a Cloudflare Origin Certificate (`Full Strict` mode).
- nginx holds the origin cert at `/etc/nginx/ssl/cinchcli.crt`.
- Relay never handles TLS directly; it only sees plain HTTP from nginx on localhost.

## EC2 Service Layout

```
/etc/nginx/conf.d/cinch-relay.conf   — nginx reverse proxy config
/etc/nginx/ssl/cinchcli.crt          — Cloudflare Origin Certificate
/etc/nginx/ssl/cinchcli.key          — Origin Certificate private key
/etc/cinch/relay.env                 — relay env vars (DATABASE_URL, OAuth keys, etc.)
/etc/cinch/start-relay.sh            — Docker run script (invoked by systemd)
/etc/systemd/system/cinch-relay.service
```

## relay.env required vars

```bash
DATABASE_URL=postgres://cinchdb:PASSWORD@cinch-db.c2rcmg0giknp.us-east-1.rds.amazonaws.com:5432/postgres?sslmode=require
BASE_URL=https://api.cinchcli.com
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
MEDIA_BACKEND=s3
MEDIA_BUCKET=cinch-data
MEDIA_ENDPOINT=s3.amazonaws.com
MEDIA_REGION=us-east-1
TELEMETRY_URL=https://telemetry.jinmu.me
TELEMETRY_API_KEY=...
INTERNAL_SERVICE_SECRET=...
```

## Monthly cost estimate (us-east-1)

| Resource | 12 months (free tier) | After / month | Notes |
|---|---|---|---|
| EC2 t3.micro | $0 | $7.59 | 12-month free tier |
| RDS db.t4g.micro | $0 | ~$12.41 | 12-month free tier, 20 GB gp2 |
| S3 cinch-data (media) | $0 | ~$0.023/GB | Scales with usage |
| CloudWatch + SNS | $0 | $0 | Always free |
| OCI A1.Flex (×2) | $0 | $0 | Always Free, never expires |
| Cloudflare | $0 | $0 | Always free |
| **Total (base)** | **$0** | **~$20 + media** | Both EC2 and RDS free tiers expire at the same time |

## Pending tasks

- [ ] Add `DATABASE_URL` to `/etc/cinch/relay.env` on EC2
- [ ] Update `/etc/cinch/start-relay.sh` — remove Litestream wrapper, direct `docker run`
- [ ] `systemctl restart cinch-relay` after env update
- [ ] Run `cinch auth login` + round-trip test (`cinch push` / `cinch pull`)
- [ ] CloudWatch Auto Recovery alarm (`StatusCheckFailed_System` → EC2 recover)
- [ ] OCI VM #2 standby relay provisioning
