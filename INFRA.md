# Cinch Relay — AWS Infrastructure

```mermaid
graph TD
    subgraph Clients["Clients"]
        CLI["cinch CLI\n(macOS / Linux / Windows)"]
        Desktop["cinch Desktop\n(macOS)"]
    end

    subgraph Edge["Edge"]
        CF["Cloudflare\napi.cinchcli.com\nTLS termination · proxied"]
    end

    subgraph AWS["AWS (us-east-1)"]
        EIP["Elastic IP\n(static public IP)"]

        subgraph EC2Box["EC2 t3.micro · Ubuntu 22.04"]
            SG["Security Group\nTCP 8080 — Cloudflare IPs only\nTCP 22   — SSH (your IP)"]
            Relay["Docker: ghcr.io/cinchcli/relay:latest\nPORT=8080  DB_PATH=/data/cinch.db\n--restart always"]
            Cron["cron (daily 03:00 UTC)\naws s3 cp /data/cinch.db\ns3://cinch-backups/YYYY-MM-DD.db"]
        end

        EBS["EBS gp3 — 20 GB\nmounted at /data\n(cinch.db + media/)"]
        IAM["IAM Instance Role\ns3:PutObject → cinch-backups/*"]

        S3["S3 Bucket\ncinch-backups\nVersioning ON · lifecycle 30d"]

        CW["CloudWatch\nBilling Alarm\n> $10 / month"]
        SNS["SNS Topic\n→ jingmuio@gmail.com"]
    end

    subgraph External["External"]
        GHCR["GitHub Container Registry\nghcr.io/cinchcli/relay:latest"]
        Uptime["telemetry.jinmu.me\nGET /health every 60s"]
    end

    CLI     -->|"HTTPS  POST /clips\nHTTPS  GET  /v1/stream"| CF
    Desktop -->|"WSS    /v1/stream\nHTTPS  POST /clips"| CF
    CF      -->|"HTTP :8080 (plain)"| EIP
    EIP     --> SG
    SG      --> Relay
    Relay  <-->|"read / write"| EBS
    Cron    -->|"aws s3 cp"| S3
    Relay   -.->|"same instance"| Cron
    IAM     -.->|"attached to EC2"| EC2Box
    GHCR    -->|"docker pull on update"| Relay
    CW      -->|"threshold exceeded"| SNS
    Uptime  -->|"health ping"| CF
```

## Component notes

| Component | Detail |
|---|---|
| EC2 t3.micro | 2 vCPU / 1 GB RAM. Sufficient for personal + small-team load. |
| EBS gp3 20 GB | Mounted at `/data`. Holds `cinch.db` (SQLite) and `media/` (binary clips). Resize with `resize2fs` if needed, no downtime. |
| Elastic IP | Static IP attached to the instance so the Cloudflare A-record doesn't break on stop/start. |
| Cloudflare | DNS-proxied A record → Elastic IP. SSL mode **Full** (Cloudflare ↔ origin is plain HTTP on :8080). Firewall rule: block requests missing `CF-Connecting-IP` to hide origin IP. |
| Security Group | Inbound: TCP 8080 from [Cloudflare IP ranges](https://www.cloudflare.com/ips/), TCP 22 from your IP. Outbound: all (for docker pull, S3 backup, OAuth calls). |
| IAM Instance Role | Attached at launch. Policy: `s3:PutObject` on `arn:aws:s3:::cinch-backups/*`. No access keys needed on the instance. |
| S3 cinch-backups | Versioning ON for accidental-delete protection. Lifecycle rule: expire non-current versions after 30 days. |
| CloudWatch Billing Alarm | Metric: `EstimatedCharges`, threshold `$10`, period 1 day. SNS → email. |
| cron daily backup | `/etc/cron.d/cinch-backup`: `0 3 * * * root aws s3 cp /data/cinch.db s3://cinch-backups/$(date +\%F).db` |

## Monthly cost estimate (us-east-1, on-demand)

| Resource | Cost |
|---|---|
| EC2 t3.micro | ~$8.47 |
| EBS gp3 20 GB | ~$1.60 |
| Elastic IP (attached) | $0.00 |
| S3 (< 1 GB backups) | < $0.03 |
| Data transfer out (< 1 GB) | < $0.10 |
| **Total** | **~$10.20 / month** |
